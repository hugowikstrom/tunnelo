"""
Tunnelo — webbportal (hub-and-spoke VPN).

Logga in på en websida → skapa en enhet → scanna QR-kod med officiella
WireGuard-appen → uppkopplad mot servern.

Kör (kräver root för port 80 + wg):
    sudo TUNNELO_ENDPOINT=<serverns-publika-ip> ./venv/bin/python webapp.py

Inloggning: email-baserad tvåstegsverifiering. Tillåtna adresser listas i
server/allowed_emails.txt (en per rad). Vid inloggning matas en mailadress in;
finns den i listan mailas en engångskod som anges i steg 2.

Miljövariabler:
    TUNNELO_ENDPOINT   serverns publika ip:port som enheter kopplar mot
                     (default: maskinens IP + :51820)
    TUNNELO_WEBPORT    port för webbsidan (default 80)
    TUNNELO_ALLOWED    AllowedIPs i klient-config (default 10.44.0.0/24 =
                     bara VPN-nätet. Sätt 0.0.0.0/0 för = full tunnel.)
    TUNNELO_SMTP_HOST  SMTP-server för att maila koder. Utan denna skrivs
                     koden i serverloggen (utvecklingsläge).
    TUNNELO_SMTP_PORT/USER/PASS/FROM  SMTP-inställningar.
"""
import base64
import hashlib
import io
import json
import os
import secrets
import smtplib
import socket
import threading
import time
import urllib.request
from datetime import timedelta
from email.message import EmailMessage

# Ladda hemligheter/inställningar från server/.env (KEY=VALUE per rad) om filen
# finns — MÅSTE ske före "import hub" som läser TUNNELO_HUB_PORT vid import.
# Riktiga miljövariabler vinner (setdefault skriver bara om de saknas).
_envfil = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_envfil):
    with open(_envfil) as _f:
        for _rad in _f:
            _rad = _rad.strip()
            if _rad and not _rad.startswith("#") and "=" in _rad:
                _k, _v = _rad.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

import qrcode
import qrcode.image.svg
from flask import (Flask, Response, g, redirect, render_template, request,
                   session, url_for)
from flask_sock import Sock

import hub
import sprak

app = Flask(__name__)

# Stabil hemlig nyckel (sparas till fil) så inloggningar överlever omstart —
# annars loggas alla ut varje gång servern startar om.
_HAR = os.path.dirname(os.path.abspath(__file__))
_nyckelfil = os.path.join(_HAR, "secret.key")
if os.path.exists(_nyckelfil):
    with open(_nyckelfil) as _f:
        app.secret_key = _f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_nyckelfil, "w") as _f:
        _f.write(app.secret_key)
    os.chmod(_nyckelfil, 0o600)

# "Betrodd enhet": sessionen (cookien) gäller i 30 dagar, så en igenkänd
# webbläsare loggas in direkt utan ny kod.
app.permanent_session_lifetime = timedelta(days=30)
# Ladda om mallar från disk vid ändring (slipper starta om servern).
app.config["TEMPLATES_AUTO_RELOAD"] = True

sock = Sock(app)  # websockets för web-terminalen

# --- Inställningar ------------------------------------------------------------
WEBPORT = int(os.environ.get("TUNNELO_WEBPORT", "80"))
ALLOWED_IPS = os.environ.get("TUNNELO_ALLOWED", hub.NET_CIDR)

HAR = os.path.dirname(os.path.abspath(__file__))
DEVICES_FIL = os.path.join(HAR, "devices.json")
# Användare (mailadress + roll). Bara dessa får logga in. Första användaren
# skapas via setup-flödet och blir admin.
USERS_FIL = os.path.join(HAR, "users.json")
# Betrodda enheter: en långlivad enhetsnyckel (cookie) → adress. Känd enhet
# loggas in direkt utan mail. Vi lagrar bara hashen av nyckeln.
TRUSTED_FIL = os.path.join(HAR, "trusted.json")
# Sparade SSH/VNC-anslutningar per e-post → delas mellan alla som loggar in med
# samma adress. Innehåller ev. sparade lösenord/nycklar → gitignoreras.
ANSLUTNINGAR_FIL = os.path.join(HAR, "anslutningar.json")
# Host-konfiguration: API-nycklar + installationslösenord. Känsligt → gitignoreras.
KONFIG_FIL = os.path.join(HAR, "konfig.json")

# Utskick av inloggningskoder. Prioritet: Resend (enklast) → SMTP → serverlogg.
# Resend: skaffa en API-nyckel på resend.com, sätt TUNNELO_RESEND_KEY.
RESEND_KEY = os.environ.get("TUNNELO_RESEND_KEY")
SMTP_HOST = os.environ.get("TUNNELO_SMTP_HOST")
SMTP_PORT = int(os.environ.get("TUNNELO_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("TUNNELO_SMTP_USER")
SMTP_PASS = os.environ.get("TUNNELO_SMTP_PASS")
SMTP_FROM = os.environ.get("TUNNELO_SMTP_FROM", SMTP_USER or "")
# Avsändaradress. För Resend måste domänen vara verifierad; onboarding@resend.dev
# funkar för test (går bara till ditt eget konto).
MAIL_FROM = (os.environ.get("TUNNELO_MAIL_FROM") or SMTP_FROM
             or "Tunnelo <onboarding@resend.dev>")

KOD_GILTIGHET = 600  # sekunder en inloggningskod gäller (10 min)
BETRODD_GILTIGHET = 30 * 24 * 3600  # betrodd enhet: 30 dagars inaktivitet → ny mail-inloggning
# Väntande koder i minnet: email -> {"kod": "123456", "utgang": <tid>}
PENDING = {}


def las_anvandare():
    """Läs användarna som en dict: epost -> {"epost", "admin"}."""
    if not os.path.exists(USERS_FIL):
        return {}
    with open(USERS_FIL) as f:
        return {u["epost"]: u for u in json.load(f)}


def spara_anvandare(users):
    """Spara användar-dicten till disk."""
    with open(USERS_FIL, "w") as f:
        json.dump(list(users.values()), f, indent=2)


def finns_admin():
    """True om minst en admin är registrerad (annars behövs setup)."""
    return any(u.get("admin") for u in las_anvandare().values())


def las_anslutningar_alla():
    """Alla sparade anslutningar: dict epost -> lista."""
    if not os.path.exists(ANSLUTNINGAR_FIL):
        return {}
    with open(ANSLUTNINGAR_FIL) as f:
        return json.load(f)


def spara_anslutningar_alla(d):
    with open(ANSLUTNINGAR_FIL, "w") as f:
        json.dump(d, f, indent=2)


# --- Host-konfiguration (nycklar + installationslösenord) --------------------
def las_konfig():
    if not os.path.exists(KONFIG_FIL):
        return {}
    with open(KONFIG_FIL) as f:
        return json.load(f)


def spara_konfig(d):
    with open(KONFIG_FIL, "w") as f:
        json.dump(d, f, indent=2)


def aktiv_resend_key():
    """Resend-nyckel: konfig.json först, annars miljövariabeln."""
    return las_konfig().get("resend_key") or RESEND_KEY


def aktiv_smtp():
    """SMTP-inställningar: konfig.json först, annars miljövariabler."""
    k = las_konfig()
    return {
        "host": k.get("smtp_host") or SMTP_HOST,
        "port": int(k.get("smtp_port") or SMTP_PORT),
        "user": k.get("smtp_user") or SMTP_USER,
        "pass": k.get("smtp_pass") or SMTP_PASS,
    }


def aktiv_mail_from():
    """Avsändaradress: konfig först, annars miljö/standard."""
    return las_konfig().get("mail_from") or MAIL_FROM


def epost_konfigurerad():
    """Kan systemet skicka mejl (så e-postverifiering fungerar)?"""
    return bool(aktiv_resend_key() or aktiv_smtp()["host"])


def satt_install_losen(losen):
    k = las_konfig()
    if losen:
        k["install_losen_hash"] = hashlib.sha256(losen.encode()).hexdigest()
    else:
        k.pop("install_losen_hash", None)
    spara_konfig(k)


def install_losen_satt():
    return bool(las_konfig().get("install_losen_hash"))


def kolla_install_losen(losen):
    h = las_konfig().get("install_losen_hash")
    return bool(h) and bool(losen) and hashlib.sha256(losen.encode()).hexdigest() == h


def maska(v):
    """Visa en nyckel delvis maskad: bara sista 4 tecknen synliga."""
    if not v:
        return ""
    return ("•" * max(4, len(v) - 4)) + v[-4:] if len(v) > 4 else "••••"


# --- Betrodda enheter --------------------------------------------------------
def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def las_trusted():
    if not os.path.exists(TRUSTED_FIL):
        return {}
    with open(TRUSTED_FIL) as f:
        return json.load(f)


def spara_trusted(d):
    with open(TRUSTED_FIL, "w") as f:
        json.dump(d, f, indent=2)


def betro_enhet(epost):
    """Skapa en enhetsnyckel, spara dess hash → adress, returnera nyckeln."""
    token = secrets.token_urlsafe(32)
    d = las_trusted()
    d[_hash(token)] = {"epost": epost, "senast": time.time()}
    spara_trusted(d)
    return token


def trusted_epost(token):
    """Adressen en betrodd enhetsnyckel hör till (eller None).
    Glidande 30-dagarsfönster: har enheten inte använts på 30 dagar tas den
    bort och None returneras (då krävs ny mail-inloggning). Annars förnyas
    tidsstämpeln så fönstret nollställs vid varje besök."""
    if not token:
        return None
    d = las_trusted()
    post = d.get(_hash(token))
    if not post:
        return None
    nu = time.time()
    if nu - post.get("senast", 0) > BETRODD_GILTIGHET:
        d.pop(_hash(token), None)
        spara_trusted(d)
        return None
    post["senast"] = nu  # förnya fönstret
    spara_trusted(d)
    return post.get("epost")


def glom_enhet(token):
    """Ta bort en enhets betrodd-status (vid utloggning)."""
    if not token:
        return
    d = las_trusted()
    if d.pop(_hash(token), None) is not None:
        spara_trusted(d)


def generera_kod():
    """Sexsiffrig engångskod."""
    return f"{secrets.randbelow(1000000):06d}"


def maila(till, amne, text):
    """Skicka mejl. Prioritet: Resend → SMTP → serverlogg (utvecklingsläge)."""
    if aktiv_resend_key():
        skicka_resend(till, amne, text)
    elif aktiv_smtp()["host"]:
        skicka_smtp(till, amne, text)
    else:
        print(f"[DEV] Mail till {till}: {amne} :: {text[:80]}")


def skicka_lank_mail(epost, lank):
    """Maila enbart en inloggningslänk (ingen kod). Ett klick loggar in."""
    maila(epost, "Din Tunnelo-inloggning",
          f"Klicka för att logga in:\n{lank}\n\n"
          f"Öppna länken i samma webbläsare där du angav din mejladress.\n"
          f"Gäller i 10 minuter och kan bara användas en gång.")


def skicka_resend(till, amne, text):
    """Skicka mejl via Resends API (https://resend.com) — bara en API-nyckel."""
    data = json.dumps({
        "from": aktiv_mail_from(), "to": [till], "subject": amne, "text": text,
    }).encode()
    req = urllib.request.Request("https://api.resend.com/emails",
                                 data=data, method="POST")
    req.add_header("Authorization", f"Bearer {aktiv_resend_key()}")
    req.add_header("Content-Type", "application/json")
    # Resend ligger bakom Cloudflare som blockerar Python-urllibs standard-UA
    # (fel 1010) — sätt en egen User-Agent.
    req.add_header("User-Agent", "Tunnelo/1.0")
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()  # 200 = skickat


def skicka_smtp(till, amne, text):
    """Skicka mejl via en vanlig SMTP-server."""
    smtp = aktiv_smtp()
    msg = EmailMessage()
    msg["Subject"] = amne
    msg["From"] = aktiv_mail_from()
    msg["To"] = till
    msg.set_content(text)
    with smtplib.SMTP(smtp["host"], smtp["port"]) as s:
        if smtp["port"] in (587, 25):
            s.starttls()
        if smtp["user"]:
            s.login(smtp["user"], smtp["pass"])
        s.send_message(msg)


def endpoint():
    """Serverns publika ip:port. Från env, annars maskinens IP + hub-porten."""
    ep = os.environ.get("TUNNELO_ENDPOINT")
    if ep:
        return ep if ":" in ep else f"{ep}:{hub.HUB_PORT}"
    # Gissa maskinens utåtriktade IP (ingen trafik skickas, bara för att välja IP).
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return f"{ip}:{hub.HUB_PORT}"


# --- Lagring (enheter) --------------------------------------------------------
def load_devices():
    if not os.path.exists(DEVICES_FIL):
        return []
    with open(DEVICES_FIL) as f:
        return json.load(f)


def save_devices(devices):
    with open(DEVICES_FIL, "w") as f:
        json.dump(devices, f, indent=2)


def next_ip(devices):
    """Nästa lediga VPN-IP (.2 och uppåt; .1 är navet)."""
    upptagna = {d["vpn_ip"] for d in devices}
    for i in range(2, 255):
        ip = f"10.44.0.{i}"
        if ip not in upptagna:
            return ip
    raise RuntimeError("Slut på adresser")


# --- WireGuard-config för en enhet -------------------------------------------
def anvandar_allowed_ips(epost):
    """Vilka nät/IP en användare når. Fallback: globala ALLOWED_IPS."""
    u = las_anvandare().get(epost or "", {})
    return u.get("allowed_ips") or ALLOWED_IPS


def bygg_klientconfig(device):
    """Bygg den .conf som enheten (WireGuard-appen) ska använda.
    AllowedIPs styrs av ägarens tilldelade nät (olika användare → olika nät)."""
    allowed = anvandar_allowed_ips(device.get("agare"))
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {device['priv']}",
        f"Address = {device['vpn_ip']}/32",
        "DNS = 1.1.1.1",
        "",
        "[Peer]",
        f"PublicKey = {hub.server_pubkey()}",
        f"Endpoint = {endpoint()}",
        f"AllowedIPs = {allowed}",
        "PersistentKeepalive = 25",
        "",
    ])


def qr_svg(text):
    """Gör en QR-kod som inbäddningsbar SVG-sträng (kräver ej Pillow)."""
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(text, image_factory=factory)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


# --- Språk (i18n) ------------------------------------------------------------
def tr(nyckel):
    """Översätt en nyckel i backend-kod (mallar använder t())."""
    return sprak.t(nyckel, session.get("lang", "sv"))


@app.context_processor
def injicera_sprak():
    """Gör t('nyckel'), lang och språklistan tillgängliga i alla mallar."""
    lang = session.get("lang", "sv")
    return {
        "t": lambda nyckel: sprak.t(nyckel, lang),
        "lang": lang,
        "sprak_lista": sprak.SPRAK,
    }


@app.route("/sprak/<lang>")
def byt_sprak(lang):
    """Byt språk och gå tillbaka dit man var."""
    if lang in sprak.SPRAK:
        session["lang"] = lang
        session.permanent = True
    # #sprakbyte-fragment: talar om för sidan att inte köra autostart igen
    mal = (request.referrer or url_for("home")).split("#")[0]
    return redirect(mal + "#sprakbyte")


# --- Auth ---------------------------------------------------------------------
def inloggad():
    return session.get("inloggad") is True


def ar_admin():
    return session.get("admin") is True


def skicka_ny_lank(epost):
    """Skapa och maila en inloggningslänk. Binder token till DEN HÄR webbläsaren
    via sessionen (pending_epost) så bara den kan slutföra inloggningen."""
    token = secrets.token_urlsafe(32)
    PENDING[epost] = {"token": token, "utgang": time.time() + KOD_GILTIGHET}
    lank = f"{request.host_url.rstrip('/')}/magic/{token}"
    skicka_lank_mail(epost, lank)
    session["pending_epost"] = epost


def hitta_magic(token):
    """Hitta vilken adress en magic-token hör till (om giltig)."""
    for epost, post in PENDING.items():
        if post.get("token") == token and time.time() < post["utgang"]:
            return epost
    return None


def logga_in(epost, admin):
    """Sätt en inloggad session för användaren."""
    session.permanent = True
    session["inloggad"] = True
    session["epost"] = epost
    session["admin"] = admin


def svara_inloggad(epost, admin):
    """Logga in, gör enheten betrodd (30-dagars glidande cookie) och gå till startsidan."""
    logga_in(epost, admin)
    token = betro_enhet(epost)
    resp = redirect(url_for("home"))
    resp.set_cookie("tunnelo_device", token, max_age=BETRODD_GILTIGHET,
                    httponly=True, secure=True, samesite="Lax")
    return resp


@app.before_request
def krav_login():
    """Bootstrap till setup om ingen admin finns; annars kräv inloggning.
    En betrodd enhet (giltig enhets-cookie) loggas in direkt utan mail."""
    if request.endpoint in ("static", "byt_sprak", "login_status"):
        return
    # Första gången: ingen admin finns → tvinga setup-flödet (magic tillåts
    # så första admin kan logga in via länken i mailet).
    if not finns_admin():
        if request.endpoint not in ("setup", "setup_verify", "magic"):
            return redirect(url_for("setup"))
        return
    # Normalt läge: inloggning/verifiering + magic + curl-installlänk är öppna.
    if request.endpoint in ("login", "verify", "setup", "setup_verify",
                            "magic", "install_via_token"):
        return
    if not inloggad():
        # Känd enhet? Logga in direkt utan mail.
        device = request.cookies.get("tunnelo_device")
        ep = trusted_epost(device)
        if ep and ep in las_anvandare():
            logga_in(ep, las_anvandare()[ep].get("admin", False))
            g.fornya_device = device  # förnya cookiens 30-dagarsfönster
            return
        return redirect(url_for("login"))


@app.after_request
def fornya_device_cookie(resp):
    """Skjut fram enhets-cookiens utgång vid varje besök (glidande 30 dagar)."""
    token = getattr(g, "fornya_device", None)
    if token:
        resp.set_cookie("tunnelo_device", token, max_age=BETRODD_GILTIGHET,
                        httponly=True, secure=True, samesite="Lax")
    return resp


# --- Setup (första gången: skapa admin) --------------------------------------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Första start: ange admin-mailadress → kod mailas."""
    if finns_admin():
        return redirect(url_for("login"))
    fel = None
    if request.method == "POST":
        epost = request.form.get("epost", "").strip().lower()
        install_losen = request.form.get("install_losen", "")
        if "@" not in epost:
            fel = "Ange en giltig mailadress."
        elif install_losen:
            # Bootstrap: skapa admin direkt med installationslösenord (ingen mejl behövs)
            users = las_anvandare()
            users[epost] = {"epost": epost, "admin": True, "allowed_ips": hub.NET_CIDR}
            spara_anvandare(users)
            satt_install_losen(install_losen)
            return svara_inloggad(epost, True)
        else:
            skicka_ny_lank(epost)
            return redirect(url_for("setup_verify"))
    return render_template("setup.html", fel=fel)


@app.route("/setup/verify")
def setup_verify():
    """Väntesida under första start: väntar på att admin klickar länken."""
    if finns_admin():
        return redirect(url_for("login"))
    epost = session.get("pending_epost")
    if not epost:
        return redirect(url_for("setup"))
    return render_template("verify.html", epost=epost, setup=True)


# --- Inloggning --------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """Steg 1: mata in mailadress. Finns den som användare mailas en länk."""
    fel = None
    if request.method == "POST":
        install_losen = request.form.get("install_losen", "")
        if install_losen:
            # Installationslösenord = första verifiering i stället för e-post
            if kolla_install_losen(install_losen):
                admins = [u for u in las_anvandare().values() if u.get("admin")]
                if admins:
                    return svara_inloggad(admins[0]["epost"], True)
            fel = "Fel installationslösenord."
        else:
            epost = request.form.get("epost", "").strip().lower()
            if epost in las_anvandare():
                skicka_ny_lank(epost)
                return redirect(url_for("verify"))
            fel = "Adressen är inte registrerad i tvåstegsverifieringen."
    return render_template("login.html", fel=fel,
                           install_losen_finns=install_losen_satt())


@app.route("/verify")
def verify():
    """Steg 2: väntesida. Länken i mailet loggar in DENNA webbläsare; sidan
    pollar och går vidare när det skett."""
    epost = session.get("pending_epost")
    if not epost:
        return redirect(url_for("login"))
    return render_template("verify.html", epost=epost)


@app.route("/login-status")
def login_status():
    """Pollas av väntesidan. Säger om denna webbläsare nu är inloggad."""
    return {"inloggad": bool(inloggad())}


@app.route("/magic/<token>")
def magic(token):
    """
    Länk från mailet. Loggar BARA in den webbläsare som begärde inloggningen
    (samma session har pending_epost == adressen). Öppnas länken i en annan
    dator/webbläsare nekas den — då saknas bindningen i sessionen.
    """
    epost = hitta_magic(token)
    if not epost:
        return render_template("magic.html", fel=tr("lank_ogiltig"))
    # Samma-webbläsare-koll: sessionen som klickar måste vara den som begärde.
    if session.get("pending_epost") != epost:
        return render_template("magic.html", fel=tr("lank_fel_annan"))
    PENDING.pop(epost, None)
    session.pop("pending_epost", None)
    if not finns_admin():
        users = las_anvandare()
        users[epost] = {"epost": epost, "admin": True, "allowed_ips": hub.NET_CIDR}
        spara_anvandare(users)
        return svara_inloggad(epost, True)
    if epost in las_anvandare():
        return svara_inloggad(epost, las_anvandare()[epost].get("admin", False))
    return render_template("magic.html", fel="Adressen är inte registrerad.")


@app.route("/logout")
def logout():
    # Glöm den här enheten (så den inte loggas in automatiskt igen) + rensa allt.
    glom_enhet(request.cookies.get("tunnelo_device"))
    session.clear()
    resp = redirect(url_for("login"))
    resp.delete_cookie("tunnelo_device")
    return resp


# --- Host-konfiguration (endast admin) ---------------------------------------
@app.route("/config", methods=["GET", "POST"])
def config_sida():
    """Ange/visa nycklar (delvis maskade) + installationslösenord."""
    if not ar_admin():
        return redirect(url_for("home"))
    k = las_konfig()
    meddelande = None
    if request.method == "POST":
        handling = request.form.get("handling")
        if handling == "resend":
            ny = request.form.get("resend_key", "").strip()
            if ny:
                k["resend_key"] = ny
                spara_konfig(k)
                meddelande = "Resend-nyckel sparad."
        elif handling == "install_satt":
            satt_install_losen(request.form.get("install_losen", ""))
            meddelande = "Installationslösenord uppdaterat."
        elif handling == "install_ta_bort":
            satt_install_losen(None)
            meddelande = "Installationslösenord borttaget."
        elif handling == "smtp":
            for falt in ("smtp_host", "smtp_port", "smtp_user", "smtp_from", "mail_from"):
                v = request.form.get(falt, "").strip()
                if v:
                    k[falt] = v
            pw = request.form.get("smtp_pass", "")
            if pw:
                k["smtp_pass"] = pw
            spara_konfig(k)
            meddelande = "SMTP-inställningar sparade."
        k = las_konfig()
    smtp = aktiv_smtp()
    return render_template(
        "config.html", meddelande=meddelande,
        resend_maskad=maska(k.get("resend_key") or RESEND_KEY or ""),
        resend_finns=bool(k.get("resend_key") or RESEND_KEY),
        smtp_host=smtp["host"] or "", smtp_port=smtp["port"],
        smtp_user=smtp["user"] or "", smtp_pass_maskad=maska(smtp["pass"] or ""),
        mail_from=aktiv_mail_from(),
        install_satt=install_losen_satt(),
        epost_ok=epost_konfigurerad())


# --- Användarhantering (endast admin) ----------------------------------------
@app.route("/users")
def users_sida():
    if not ar_admin():
        return redirect(url_for("home"))
    return render_template("users.html", users=list(las_anvandare().values()),
                           jag=session.get("epost"), default_ips=hub.NET_CIDR)


@app.route("/users", methods=["POST"])
def skapa_user():
    if not ar_admin():
        return redirect(url_for("home"))
    epost = request.form.get("epost", "").strip().lower()
    # Vilka nät/IP användaren ska nå via VPN (kommaseparerat, CIDR).
    allowed = request.form.get("allowed_ips", "").strip() or hub.NET_CIDR
    if "@" in epost:
        users = las_anvandare()
        if epost not in users:
            users[epost] = {"epost": epost, "admin": False,
                            "allowed_ips": allowed}
            spara_anvandare(users)
    return redirect(url_for("users_sida"))


@app.route("/users/allowed", methods=["POST"])
def uppdatera_allowed():
    """Admin ändrar vilka nät/IP en användare når."""
    if not ar_admin():
        return redirect(url_for("home"))
    epost = request.form.get("epost", "").strip().lower()
    allowed = request.form.get("allowed_ips", "").strip() or hub.NET_CIDR
    users = las_anvandare()
    if epost in users:
        users[epost]["allowed_ips"] = allowed
        spara_anvandare(users)
    return redirect(url_for("users_sida"))


@app.route("/users/delete", methods=["POST"])
def ta_bort_user():
    if not ar_admin():
        return redirect(url_for("home"))
    epost = request.form.get("epost", "").strip().lower()
    users = las_anvandare()
    # Skydda admins och en själv från borttagning.
    if epost in users and not users[epost].get("admin"):
        users.pop(epost)
        spara_anvandare(users)
    return redirect(url_for("users_sida"))


@app.route("/")
def home():
    """Startsida: SSH-sessioner. VPN-enheter nås via meny (/enheter)."""
    return render_template("home.html", is_admin=ar_admin())


@app.route("/enheter")
def enheter_sida():
    """VPN-enheter: skapa och lista (QR/installation). Flyttad från startsidan."""
    return render_template("enheter.html", devices=load_devices(),
                           endpoint=endpoint(), allowed=ALLOWED_IPS)


@app.route("/om")
def om_sida():
    """Om-sida: beskriver hur säkerheten fungerar."""
    return render_template("om.html")


@app.route("/hjalp")
def hjalp_sida():
    """Hjälp: terminallägen (SSH/tmux/screen) + viktigaste kommandon."""
    return render_template("hjalp.html")


@app.route("/devices", methods=["POST"])
def skapa_device():
    """Skapa ny enhet: nyckelpar, IP, lägg till i navet, spara."""
    hub.ensure_hub()
    namn = request.form.get("namn", "").strip() or "enhet"
    priv, pub = hub.gen_klientnycklar()

    devices = load_devices()
    vpn_ip = next_ip(devices)
    device = {
        "id": secrets.token_hex(4),
        "namn": namn,
        "priv": priv,
        "pub": pub,
        "vpn_ip": vpn_ip,
        "agare": session.get("epost"),  # vem enheten tillhör
        "install_token": secrets.token_urlsafe(48),  # lång hemlig token för curl
    }
    hub.add_peer(pub, vpn_ip)
    devices.append(device)
    save_devices(devices)
    return redirect(url_for("visa_device", device_id=device["id"]))


@app.route("/devices/<device_id>")
def visa_device(device_id):
    devices = load_devices()
    device = next((d for d in devices if d["id"] == device_id), None)
    if not device:
        return "Enhet saknas", 404
    # Färsk install-token (15 min) varje gång sidan visas → curl-raden är alltid giltig.
    fornya_install_token(device, devices)
    conf = bygg_klientconfig(device)
    curl_url = f"{request.host_url.rstrip('/')}/i/{device['install_token']}"
    return render_template("device.html", device=device, conf=conf,
                           qr=qr_svg(conf), curl_url=curl_url)


@app.route("/devices/<device_id>/config")
def ladda_config(device_id):
    device = next((d for d in load_devices() if d["id"] == device_id), None)
    if not device:
        return "Enhet saknas", 404
    conf = bygg_klientconfig(device)
    return Response(conf, mimetype="text/plain", headers={
        "Content-Disposition": f'attachment; filename="tunnelo-{device["namn"]}.conf"'
    })


def bygg_install_skript(device):
    """Bash-skript som installerar WireGuard, skriver configen och startar tunneln."""
    conf = bygg_klientconfig(device)
    return f"""#!/usr/bin/env bash
# Tunnelo — installerar WireGuard och kopplar upp enheten "{device['namn']}".
set -e
IFACE=tunnelo
CONF=$(cat <<'TUNNELO_EOF'
{conf}
TUNNELO_EOF
)

echo "Installerar WireGuard..."
if command -v apt >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y wireguard
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y wireguard-tools
elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm wireguard-tools
elif command -v brew >/dev/null 2>&1; then
    brew install wireguard-tools
else
    echo "Hittade ingen pakethanterare — installera WireGuard manuellt."; exit 1
fi

echo "Skriver config och startar tunneln..."
echo "$CONF" | sudo tee /etc/wireguard/$IFACE.conf >/dev/null
sudo chmod 600 /etc/wireguard/$IFACE.conf
sudo wg-quick down $IFACE 2>/dev/null || true
sudo wg-quick up $IFACE

echo ""
echo "Klart! Du är uppkopplad mot Tunnelo som {device['vpn_ip']}."
echo "Koppla ner:  sudo wg-quick down $IFACE"
echo "Koppla upp:  sudo wg-quick up $IFACE"
"""


@app.route("/devices/<device_id>/install.sh")
def install_skript(device_id):
    """Nedladdningsbart installationsskript (kräver inloggning)."""
    device = next((d for d in load_devices() if d["id"] == device_id), None)
    if not device:
        return "Enhet saknas", 404
    return Response(bygg_install_skript(device), mimetype="text/x-shellscript",
                    headers={"Content-Disposition":
                             f'attachment; filename="tunnelo-{device["namn"]}.sh"'})


@app.route("/devices/<device_id>/maila-lank", methods=["POST"])
def maila_lank(device_id):
    """Maila curl-installationslänken till den inloggade användaren."""
    devices = load_devices()
    device = next((d for d in devices if d["id"] == device_id), None)
    if not device:
        return "Enhet saknas", 404
    fornya_install_token(device, devices)  # färsk token, 15 min
    curl_url = f"{request.host_url.rstrip('/')}/i/{device['install_token']}"
    till = session.get("epost")
    maila(till, "Tunnelo: din installationslänk",
          f'Installera enheten "{device["namn"]}" med ett kommando:\n\n'
          f"curl -sSL {curl_url} | sudo bash\n\n"
          f"Länken är personlig och hemlig — dela den inte.")
    return redirect(url_for("visa_device", device_id=device_id, mailad="1"))


def fornya_install_token(device, devices):
    """Ge enheten en färsk install-token som gäller i 15 minuter, och spara."""
    device["install_token"] = secrets.token_urlsafe(48)
    device["token_utgang"] = time.time() + 900  # 15 min
    save_devices(devices)


@app.route("/i/<token>")
def install_via_token(token):
    """
    Curl-endpoint: kör t.ex.  curl -sSL <url>/i/<token> | sudo bash
    Token är enhetens hemliga install_token — giltig i 15 minuter efter att den
    utfärdades (när du tittade på enheten eller mailade länken). Notifierar ägaren.
    """
    device = next((d for d in load_devices()
                   if d.get("install_token") == token), None)
    if not device:
        return "# Ogiltig eller återkallad länk\n", 404
    if time.time() > device.get("token_utgang", 0):
        return "# Länken har gått ut — hämta en ny i portalen\n", 410
    # Meddela ägaren att configen hämtades (säkerhet: upptäck obehörig användning).
    agare = device.get("agare")
    if agare and agare in las_anvandare():
        try:
            _notifiera_installation(agare, device)
        except Exception:
            pass
    return Response(bygg_install_skript(device), mimetype="text/x-shellscript")


def _notifiera_installation(epost, device):
    """Maila ägaren att enhetens config hämtades via curl-länken."""
    maila(epost, "Tunnelo: en enhet installerades",
          f'Enheten "{device["namn"]}" ({device["vpn_ip"]}) kopplades just upp '
          f"via installationslänken.\n\nVar det inte du? Ta bort enheten i "
          f"Tunnelo-portalen så återkallas nyckeln.")


@app.route("/devices/<device_id>/delete", methods=["POST"])
def ta_bort_device(device_id):
    devices = load_devices()
    device = next((d for d in devices if d["id"] == device_id), None)
    if device:
        hub.remove_peer(device["pub"])
        devices = [d for d in devices if d["id"] != device_id]
        save_devices(devices)
    return redirect(url_for("enheter_sida"))


# --- Web-terminal (SSH i webbläsaren) ----------------------------------------
@app.route("/terminal")
def terminal():
    """Hub: sparade SSH-anslutningar (favoriter) + ny anslutning. Sessioner
    öppnas i eget fönster via /terminal/session."""
    return render_template("terminal.html")


@app.route("/terminal/session")
def terminal_session():
    """Själva terminalen — öppnas i ett nytt fönster. host/user/port kommer
    som URL-parametrar (aldrig lösenord, det anges i fönstret)."""
    return render_template("terminal_session.html",
                           host=request.args.get("host", ""),
                           user=request.args.get("user", ""),
                           port=request.args.get("port", "22"))


def oppna_ssh(host, user, port=22, password=None, private_key=None, timeout=10):
    """Öppna en SSH-anslutning med lösenord ELLER privat nyckel. Återanvänds av
    terminalen, nyckelinstallationen och filöverföringen."""
    import io as _io

    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    if private_key:
        pkey = paramiko.RSAKey.from_private_key(_io.StringIO(private_key))
    c.connect(host, port=int(port), username=user,
              password=None if pkey else password, pkey=pkey,
              timeout=timeout, look_for_keys=False, allow_agent=False)
    # Skicka "jag-lever"-paket var 30:e sek så NAT/brandvägg inte slänger tunneln
    tr = c.get_transport()
    if tr:
        tr.set_keepalive(30)
    return c


# --- Whisper tal-till-text (push-to-talk i terminalen) -------------------
_whisper_modell = None


def _hamta_whisper():
    """Ladda Whisper en gång (lat laddning). KB-Whisper (KBLab) är finetunad på
    svenska → bäst svensk igenkänning. Fallback till 'base' om den inte kan laddas."""
    global _whisper_modell
    if _whisper_modell is None:
        from faster_whisper import WhisperModel
        tradar = max(4, (os.cpu_count() or 8) - 2)   # nästan alla kärnor
        for namn in ("KBLab/kb-whisper-small", "base"):
            try:
                # local_files_only först (snabb laddning från cache), annars ladda ner
                try:
                    _whisper_modell = WhisperModel(namn, device="cpu", compute_type="int8",
                                                   cpu_threads=tradar, local_files_only=True)
                except Exception:
                    _whisper_modell = WhisperModel(namn, device="cpu", compute_type="int8",
                                                   cpu_threads=tradar)
                break
            except Exception as e:
                print(f"[whisper] kunde inte ladda {namn}: {e}")
    return _whisper_modell


def _forladda_whisper():
    """Ladda OCH värm upp modellen (CTranslate2 optimerar på första inferensen,
    annars tar första riktiga anropet ~13 s). Körs i bakgrundstråd vid start."""
    m = _hamta_whisper()
    if m:
        try:
            import numpy as np
            list(m.transcribe(np.zeros(16000, dtype=np.float32),
                              language="sv", beam_size=5)[0])
            print("[whisper] uppvärmd och redo")
        except Exception as e:
            print(f"[whisper] uppvärmning misslyckades: {e}")
    return _whisper_modell


@app.route("/stt", methods=["POST"])
def stt():
    """Ta emot en ljudinspelning och returnera transkriberad text (Whisper)."""
    import tempfile
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    fil = request.files.get("ljud")
    if not fil:
        return {"fel": "ingen ljudfil"}, 400
    with tempfile.NamedTemporaryFile(suffix=".webm", delete=True) as tmp:
        fil.save(tmp.name)
        try:
            modell = _hamta_whisper()
            if modell is None:
                return {"fel": "tal-till-text-modell kunde inte laddas"}, 500
            # Svenska + beam_size=5 (noggrannare, klippen är korta), VAD klipper tystnad
            segment, _ = modell.transcribe(tmp.name, language="sv",
                                           beam_size=5, vad_filter=True)
            text = " ".join(s.text.strip() for s in segment).strip()
        except Exception as e:
            return {"fel": str(e)}, 500
    return {"text": text}


@sock.route("/terminal/ws")
def terminal_ws(ws):
    """
    Websocket som kopplar webbterminalen till en riktig SSH-session via paramiko.
    Init-JSON: {host, port, user, password ELLER private_key, cols, rows}.
    Kräver inloggning (samma sessions-cookie som resten av portalen).
    """
    import json
    import select
    import threading

    if not inloggad():
        return  # neka om ej inloggad

    init = json.loads(ws.receive())
    try:
        klient = oppna_ssh(init["host"], init["user"], init.get("port", 22),
                           password=init.get("password"),
                           private_key=init.get("private_key"))
    except Exception as e:
        ws.send(f"\r\n\x1b[31mAnslutning misslyckades: {e}\x1b[0m\r\n")
        return

    chan = klient.invoke_shell(term="xterm-256color",
                               width=int(init.get("cols", 80)),
                               height=int(init.get("rows", 24)))

    def las_fran_ssh():
        """Bakgrundstråd: SSH-utdata → webbläsaren."""
        while True:
            r, _, _ = select.select([chan], [], [], 1)
            if chan in r:
                try:
                    data = chan.recv(4096)
                except Exception:
                    break
                if not data:
                    break
                try:
                    ws.send(data.decode(errors="replace"))
                except Exception:
                    break
            if chan.closed:
                break

    t = threading.Thread(target=las_fran_ssh, daemon=True)
    t.start()
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            if not msg:
                continue
            op, payload = msg[0], msg[1:]   # 1-teckens opcode-prefix
            if op == "1":                    # resize: {cols, rows}
                d = json.loads(payload)
                chan.resize_pty(width=int(d["cols"]), height=int(d["rows"]))
            elif op == "2":                  # ping (håll ws vaken) — ignorera
                continue
            else:                            # "0" = tangenttryck
                chan.send(payload)
    except Exception:
        pass
    finally:
        chan.close()
        klient.close()


# --- Grafisk session (noVNC tunnlad genom SSH) ---------------------------
# Uppgifter POSTas till /grafik/prepare → engångstoken; noVNC ansluter sedan
# till /grafik/ws?token=… så inga lösenord hamnar i URL:en.
_grafik_pending = {}   # token -> {"auth": {...}, "tid": ...}


@app.route("/grafik/prepare", methods=["POST"])
def grafik_prepare():
    """Ta emot anslutningsuppgifter, returnera en kortlivad engångstoken."""
    import secrets
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    d = request.get_json(force=True)
    if not (d.get("host") and d.get("user")):
        return {"fel": "host och user krävs"}, 400
    token = secrets.token_urlsafe(24)
    _grafik_pending[token] = {"auth": d, "tid": time.time()}
    # Städa gamla tokens (äldre än 60 s)
    for t in [k for k, v in _grafik_pending.items() if time.time() - v["tid"] > 60]:
        _grafik_pending.pop(t, None)
    return {"token": token}


@app.route("/grafik/session")
def grafik_session():
    """Sidan som visar det grafiska skrivbordet (noVNC)."""
    if not inloggad():
        return redirect(url_for("login"))
    return render_template("grafik_session.html",
                           host=request.args.get("host", "localhost"),
                           user=request.args.get("user", ""),
                           port=request.args.get("port", "22"))


# VNC-miniatyrer sparas som filer på hosten (inte i webbläsaren)
TUMNAGEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tumnaglar")


def _tumnagel_fil(ident):
    """Säkert filnamn av user@host:port via hash."""
    import hashlib
    h = hashlib.sha1((ident or "").encode()).hexdigest()
    return os.path.join(TUMNAGEL_DIR, h + ".jpg")


@app.route("/grafik/tumnagel", methods=["POST"])
def spara_tumnagel():
    """Ta emot en skärmdump (dataURL) och spara som fil."""
    import base64
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    d = request.get_json(force=True)
    ident, data = d.get("id"), d.get("data", "")
    if not ident or "," not in data:
        return {"fel": "ogiltig"}, 400
    os.makedirs(TUMNAGEL_DIR, exist_ok=True)
    with open(_tumnagel_fil(ident), "wb") as f:
        f.write(base64.b64decode(data.split(",", 1)[1]))
    return {"ok": True}


@app.route("/grafik/tumnagel", methods=["GET"])
def hamta_tumnagel():
    """Servera en sparad miniatyr (404 om ingen finns)."""
    if not inloggad():
        return "", 403
    fil = _tumnagel_fil(request.args.get("id", ""))
    if not os.path.exists(fil):
        return "", 404
    with open(fil, "rb") as f:
        return Response(f.read(), mimetype="image/jpeg")


@app.route("/anslutningar", methods=["GET"])
def hamta_anslutningar():
    """Anslutningarna för den inloggade e-posten (delas mellan enheter)."""
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    epost = session.get("epost", "")
    return {"anslutningar": las_anslutningar_alla().get(epost, [])}


@app.route("/anslutningar", methods=["POST"])
def spara_anslutningar():
    """Ersätt anslutningslistan för den inloggade e-posten."""
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    epost = session.get("epost", "")
    lista = request.get_json(force=True).get("anslutningar")
    if not isinstance(lista, list):
        return {"fel": "ogiltig"}, 400
    alla = las_anslutningar_alla()
    alla[epost] = lista
    spara_anslutningar_alla(alla)
    # Returnera den sparade listan → klienten speglar alltid servern (sanningen)
    return {"anslutningar": lista}


def _idfor(c):
    return f"{c.get('user')}@{c.get('host')}:{c.get('port')}"


@app.route("/anslutningar/spara", methods=["POST"])
def anslutning_spara_en():
    """Infoga/uppdatera EN anslutning (per id). Rör inte övriga → inget kläms bort.
    Server-sidan är atomär: läs → ersätt/lägg till → skriv."""
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    epost = session.get("epost", "")
    c = request.get_json(force=True).get("anslutning")
    if not isinstance(c, dict) or not (c.get("user") and c.get("host")):
        return {"fel": "ogiltig"}, 400
    alla = las_anslutningar_alla()
    lista = [x for x in alla.get(epost, []) if _idfor(x) != _idfor(c)]
    lista.append(c)
    alla[epost] = lista
    spara_anslutningar_alla(alla)
    return {"anslutningar": lista}


@app.route("/anslutningar/ta-bort", methods=["POST"])
def anslutning_ta_bort():
    """Ta bort EN anslutning per id. Övriga orörda."""
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    epost = session.get("epost", "")
    mid = request.get_json(force=True).get("id")
    alla = las_anslutningar_alla()
    lista = [x for x in alla.get(epost, []) if _idfor(x) != mid]
    alla[epost] = lista
    spara_anslutningar_alla(alla)
    return {"anslutningar": lista}


@sock.route("/grafik/ws")
def grafik_ws(ws):
    """Brygga: noVNC (binärt RFB) ↔ VNC-server.
    localhost → direkt TCP till 127.0.0.1:port. Annan värd → tunnlad via SSH."""
    import select
    import socket as _socket
    import threading
    if not inloggad():
        return
    token = request.args.get("token", "")
    post = _grafik_pending.pop(token, None)
    if not post or time.time() - post["tid"] > 60:
        return
    init = post["auth"]
    vnc_port = int(init.get("vnc_port", 5901))
    host = (init.get("host") or "").lower()

    klient = None
    try:
        if host in ("localhost", "127.0.0.1", "::1", ""):
            # Portalen kör på samma maskin → anslut direkt, ingen SSH behövs
            chan = _socket.create_connection(("127.0.0.1", vnc_port), timeout=10)
        else:
            # Fjärrvärd: tunnla VNC genom SSH (direct-tcpip till dess localhost)
            klient = oppna_ssh(init["host"], init["user"], init.get("port", 22),
                               password=init.get("password"),
                               private_key=init.get("private_key"))
            chan = klient.get_transport().open_channel(
                "direct-tcpip", ("localhost", vnc_port), ("127.0.0.1", 0))
    except Exception as e:
        try:
            ws.send(("VNC-fel: " + str(e)).encode())
        except Exception:
            pass
        if klient:
            klient.close()
        return

    def las_fran_vnc():
        while True:
            r, _, _ = select.select([chan], [], [], 1)
            if chan in r:
                try:
                    data = chan.recv(32768)
                except Exception:
                    break
                if not data:
                    break
                try:
                    ws.send(data)          # binärt till noVNC
                except Exception:
                    break

    t = threading.Thread(target=las_fran_vnc, daemon=True)
    t.start()
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            if isinstance(msg, str):
                msg = msg.encode()
            chan.send(msg)
    except Exception:
        pass
    finally:
        try:
            chan.close()
        except Exception:
            pass
        if klient:
            klient.close()


@app.route("/ssh/setup-key", methods=["POST"])
def ssh_setup_key():
    """
    Skapa ett SSH-nyckelpar och installera den publika nyckeln på servern (via en
    engångs-lösenordsinloggning). Returnerar den privata nyckeln så webbläsaren
    kan spara den → framtida inloggningar sker utan lösenord.
    """
    import io as _io

    import paramiko
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    d = request.get_json(force=True)
    host, user = d.get("host"), d.get("user")
    port, pw = int(d.get("port", 22)), d.get("password")
    if not (host and user and pw):
        return {"fel": "host, user och lösenord krävs"}, 400

    # Generera nyckelpar
    key = paramiko.RSAKey.generate(3072)
    buf = _io.StringIO()
    key.write_private_key(buf)
    priv = buf.getvalue()
    pub = f"ssh-rsa {key.get_base64()} tunnelo"

    # Logga in med lösenord och lägg publika nyckeln i authorized_keys
    try:
        c = oppna_ssh(host, user, port, password=pw)
        cmd = ("mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
               f'touch ~/.ssh/authorized_keys && grep -qxF "{pub}" ~/.ssh/authorized_keys '
               f'|| echo "{pub}" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys')
        _in, _out, _err = c.exec_command(cmd)
        _out.read()
        fel = _err.read().decode().strip()
        c.close()
    except Exception as e:
        return {"fel": str(e)}, 400
    if fel:
        return {"fel": fel}, 400
    return {"ok": True, "private_key": priv}


# --- SFTP-filöverföring ------------------------------------------------------
def _sftp(d):
    """Öppna SSH+SFTP från en request-dict (lösenord eller private_key)."""
    c = oppna_ssh(d.get("host"), d.get("user"), d.get("port", 22),
                  password=d.get("password") or None,
                  private_key=d.get("private_key") or None)
    return c, c.open_sftp()


@app.route("/sftp/list", methods=["POST"])
def sftp_list():
    """Lista en katalog på fjärrservern. path='.' → hemkatalogen."""
    import stat as _stat
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    d = request.get_json(force=True)
    try:
        c, sftp = _sftp(d)
        path = d.get("path") or "."
        path = sftp.normalize(path)  # gör absolut (t.ex. hemkatalogen)
        poster = [{"namn": a.filename, "dir": _stat.S_ISDIR(a.st_mode),
                   "storlek": a.st_size} for a in sftp.listdir_attr(path)]
        c.close()
        poster.sort(key=lambda x: (not x["dir"], x["namn"].lower()))
        return {"path": path, "poster": poster}
    except Exception as e:
        return {"fel": str(e)}, 400


@app.route("/sftp/download", methods=["POST"])
def sftp_download():
    """Ladda ner en fil från fjärrservern."""
    import io as _io
    if not inloggad():
        return "", 403
    d = request.get_json(force=True)
    try:
        c, sftp = _sftp(d)
        buf = _io.BytesIO()
        sftp.getfo(d["path"], buf)
        c.close()
        buf.seek(0)
        namn = d["path"].rstrip("/").rsplit("/", 1)[-1]
        return Response(buf.read(), mimetype="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{namn}"'})
    except Exception as e:
        return str(e), 400


@app.route("/sftp/upload", methods=["POST"])
def sftp_upload():
    """Ladda upp en fil till en katalog på fjärrservern (drag-and-drop)."""
    if not inloggad():
        return {"fel": "ej inloggad"}, 403
    d = request.form
    f = request.files.get("fil")
    if not f:
        return {"fel": "ingen fil"}, 400
    try:
        c, sftp = _sftp(d)
        path = sftp.normalize(d.get("path") or ".")
        mal = path.rstrip("/") + "/" + f.filename
        sftp.putfo(f.stream, mal)
        c.close()
        return {"ok": True, "namn": f.filename}
    except Exception as e:
        return {"fel": str(e)}, 400


if __name__ == "__main__":
    hub.ensure_hub()  # se till att navet finns vid start
    # Förladda Whisper i bakgrunden så första mik-tryckningen inte hänger
    threading.Thread(target=_forladda_whisper, daemon=True).start()
    print(f"Tunnelo-portal på http://0.0.0.0:{WEBPORT}  (endpoint {endpoint()})")
    app.run(host="0.0.0.0", port=WEBPORT, threaded=True)
