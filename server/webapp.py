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
from flask import (Flask, Response, redirect, render_template, request,
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
    d[_hash(token)] = {"epost": epost}
    spara_trusted(d)
    return token


def trusted_epost(token):
    """Adressen en betrodd enhetsnyckel hör till (eller None)."""
    if not token:
        return None
    return las_trusted().get(_hash(token), {}).get("epost")


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
    if RESEND_KEY:
        skicka_resend(till, amne, text)
    elif SMTP_HOST:
        skicka_smtp(till, amne, text)
    else:
        print(f"[DEV] Mail till {till}: {amne} :: {text[:80]}")


def skicka_kod(epost, kod, lank):
    """Maila inloggningskoden + en klickbar magic-länk (ett-klicks inloggning)."""
    maila(epost, "Din Tunnelo-inloggning",
          f"Din inloggningskod: {kod}\n\n"
          f"Eller klicka för att logga in direkt:\n{lank}\n\n"
          f"Gäller i 10 minuter och kan bara användas en gång.")


def skicka_resend(till, amne, text):
    """Skicka mejl via Resends API (https://resend.com) — bara en API-nyckel."""
    data = json.dumps({
        "from": MAIL_FROM, "to": [till], "subject": amne, "text": text,
    }).encode()
    req = urllib.request.Request("https://api.resend.com/emails",
                                 data=data, method="POST")
    req.add_header("Authorization", f"Bearer {RESEND_KEY}")
    req.add_header("Content-Type", "application/json")
    # Resend ligger bakom Cloudflare som blockerar Python-urllibs standard-UA
    # (fel 1010) — sätt en egen User-Agent.
    req.add_header("User-Agent", "Tunnelo/1.0")
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()  # 200 = skickat


def skicka_smtp(till, amne, text):
    """Skicka mejl via en vanlig SMTP-server."""
    msg = EmailMessage()
    msg["Subject"] = amne
    msg["From"] = MAIL_FROM
    msg["To"] = till
    msg.set_content(text)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        if SMTP_PORT in (587, 25):
            s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
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
    return redirect(request.referrer or url_for("home"))


# --- Auth ---------------------------------------------------------------------
def inloggad():
    return session.get("inloggad") is True


def ar_admin():
    return session.get("admin") is True


MAX_FORSOK = 5  # antal felaktiga kodförsök innan koden dör (mot brute-force)


def skicka_ny_kod(epost):
    """Skapa och maila en engångskod + magic-länk. Kom ihåg vem som väntar."""
    kod = generera_kod()
    token = secrets.token_urlsafe(32)
    PENDING[epost] = {"kod": kod, "token": token, "forsok": 0,
                      "utgang": time.time() + KOD_GILTIGHET}
    lank = f"{request.host_url.rstrip('/')}/magic/{token}"
    skicka_kod(epost, kod, lank)
    session["pending_epost"] = epost


def kolla_kod(epost, angiven):
    """True om koden stämmer och inte gått ut. Räknar försök; för många → dör."""
    post = PENDING.get(epost)
    if not post or time.time() >= post["utgang"]:
        return False
    post["forsok"] = post.get("forsok", 0) + 1
    if post["forsok"] > MAX_FORSOK:
        PENDING.pop(epost, None)  # för många gissningar → koden ogiltig
        return False
    if angiven == post["kod"]:
        PENDING.pop(epost, None)
        session.pop("pending_epost", None)
        return True
    return False


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
    """Logga in, gör enheten betrodd (1-års cookie) och gå till startsidan."""
    logga_in(epost, admin)
    token = betro_enhet(epost)
    resp = redirect(url_for("home"))
    resp.set_cookie("tunnelo_device", token, max_age=31536000,
                    httponly=True, secure=True, samesite="Lax")
    return resp


@app.before_request
def krav_login():
    """Bootstrap till setup om ingen admin finns; annars kräv inloggning.
    En betrodd enhet (giltig enhets-cookie) loggas in direkt utan mail."""
    if request.endpoint in ("static", "byt_sprak"):
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
        ep = trusted_epost(request.cookies.get("tunnelo_device"))
        if ep and ep in las_anvandare():
            logga_in(ep, las_anvandare()[ep].get("admin", False))
            return
        return redirect(url_for("login"))


# --- Setup (första gången: skapa admin) --------------------------------------
@app.route("/setup", methods=["GET", "POST"])
def setup():
    """Första start: ange admin-mailadress → kod mailas."""
    if finns_admin():
        return redirect(url_for("login"))
    fel = None
    if request.method == "POST":
        epost = request.form.get("epost", "").strip().lower()
        if "@" in epost:
            skicka_ny_kod(epost)
            return redirect(url_for("setup_verify"))
        fel = "Ange en giltig mailadress."
    return render_template("setup.html", fel=fel)


@app.route("/setup/verify", methods=["GET", "POST"])
def setup_verify():
    """Verifiera admin-adressen och spara den som första användaren (admin)."""
    if finns_admin():
        return redirect(url_for("login"))
    epost = session.get("pending_epost")
    if not epost:
        return redirect(url_for("setup"))
    fel = None
    if request.method == "POST":
        if kolla_kod(epost, request.form.get("kod", "").strip()):
            users = las_anvandare()
            users[epost] = {"epost": epost, "admin": True,
                            "allowed_ips": hub.NET_CIDR}
            spara_anvandare(users)
            return svara_inloggad(epost, True)
        fel = "Fel eller utgången kod."
    return render_template("verify.html", epost=epost, fel=fel, setup=True)


# --- Inloggning --------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """Steg 1: mata in mailadress. Finns den som användare mailas en kod."""
    fel = None
    if request.method == "POST":
        epost = request.form.get("epost", "").strip().lower()
        if epost in las_anvandare():
            skicka_ny_kod(epost)
            return redirect(url_for("verify"))
        fel = "Adressen är inte registrerad i tvåstegsverifieringen."
    return render_template("login.html", fel=fel)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    """Steg 2: mata in koden som mailades."""
    epost = session.get("pending_epost")
    if not epost:
        return redirect(url_for("login"))
    fel = None
    if request.method == "POST":
        if kolla_kod(epost, request.form.get("kod", "").strip()):
            admin = las_anvandare().get(epost, {}).get("admin", False)
            return svara_inloggad(epost, admin)
        fel = "Fel eller utgången kod."
    return render_template("verify.html", epost=epost, fel=fel)


@app.route("/magic/<token>")
def magic(token):
    """
    Magic-länk från mailet: klick → inloggad direkt (ingen mellansida).
    Skapar admin om det är första gången (setup). Vid ogiltig/utgången länk
    visas ett felmeddelande.
    """
    epost = hitta_magic(token)
    if not epost:
        return render_template("magic.html",
                               fel="Länken är ogiltig eller har gått ut.")
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


@sock.route("/terminal/ws")
def terminal_ws(ws):
    """
    Websocket som kopplar webbterminalen till en riktig SSH-session via paramiko.
    Första meddelandet från klienten är JSON: {host, port, user, password, cols, rows}.
    Sedan skickas tangenttryck som text; SSH-utdata skickas tillbaka.
    Kräver inloggning (samma sessions-cookie som resten av portalen).
    """
    import json
    import select
    import threading

    import paramiko

    if not inloggad():
        return  # neka om ej inloggad

    init = json.loads(ws.receive())
    klient = paramiko.SSHClient()
    klient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        klient.connect(init["host"], port=int(init.get("port", 22)),
                       username=init["user"], password=init.get("password"),
                       timeout=10, look_for_keys=False, allow_agent=False)
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
            chan.send(msg)
    except Exception:
        pass
    finally:
        chan.close()
        klient.close()


if __name__ == "__main__":
    hub.ensure_hub()  # se till att navet finns vid start
    print(f"Tunnelo-portal på http://0.0.0.0:{WEBPORT}  (endpoint {endpoint()})")
    app.run(host="0.0.0.0", port=WEBPORT)
