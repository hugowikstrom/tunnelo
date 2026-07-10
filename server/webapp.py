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
import io
import json
import os
import secrets
import smtplib
import socket
import time
from email.message import EmailMessage

import qrcode
import qrcode.image.svg
from flask import (Flask, Response, redirect, render_template, request,
                   session, url_for)
from flask_sock import Sock

import hub

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # för sessions-cookien
sock = Sock(app)  # websockets för web-terminalen

# --- Inställningar ------------------------------------------------------------
WEBPORT = int(os.environ.get("TUNNELO_WEBPORT", "80"))
ALLOWED_IPS = os.environ.get("TUNNELO_ALLOWED", hub.NET_CIDR)

HAR = os.path.dirname(os.path.abspath(__file__))
DEVICES_FIL = os.path.join(HAR, "devices.json")
# Användare (mailadress + roll). Bara dessa får logga in. Första användaren
# skapas via setup-flödet och blir admin.
USERS_FIL = os.path.join(HAR, "users.json")

# SMTP för att skicka inloggningskoder. Sätts ingen SMTP_HOST skrivs koden i
# serverloggen istället (praktiskt vid test/utveckling).
SMTP_HOST = os.environ.get("TUNNELO_SMTP_HOST")
SMTP_PORT = int(os.environ.get("TUNNELO_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("TUNNELO_SMTP_USER")
SMTP_PASS = os.environ.get("TUNNELO_SMTP_PASS")
SMTP_FROM = os.environ.get("TUNNELO_SMTP_FROM", SMTP_USER or "tunnelo@localhost")

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


def generera_kod():
    """Sexsiffrig engångskod."""
    return f"{secrets.randbelow(1000000):06d}"


def skicka_kod(epost, kod):
    """Maila koden. Utan SMTP_HOST loggas den istället (utvecklingsläge)."""
    if not SMTP_HOST:
        print(f"[DEV] Inloggningskod för {epost}: {kod}")
        return
    msg = EmailMessage()
    msg["Subject"] = "Din Tunnelo-inloggningskod"
    msg["From"] = SMTP_FROM
    msg["To"] = epost
    msg.set_content(f"Din inloggningskod: {kod}\n\nGäller i 10 minuter.")
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
def bygg_klientconfig(device):
    """Bygg den .conf som enheten (WireGuard-appen) ska använda."""
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {device['priv']}",
        f"Address = {device['vpn_ip']}/32",
        "DNS = 1.1.1.1",
        "",
        "[Peer]",
        f"PublicKey = {hub.server_pubkey()}",
        f"Endpoint = {endpoint()}",
        f"AllowedIPs = {ALLOWED_IPS}",
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


# --- Auth ---------------------------------------------------------------------
def inloggad():
    return session.get("inloggad") is True


def ar_admin():
    return session.get("admin") is True


def skicka_ny_kod(epost):
    """Skapa och maila en engångskod, kom ihåg vilken adress som väntar."""
    kod = generera_kod()
    PENDING[epost] = {"kod": kod, "utgang": time.time() + KOD_GILTIGHET}
    skicka_kod(epost, kod)
    session["pending_epost"] = epost


def kolla_kod(epost, angiven):
    """True om koden stämmer och inte gått ut. Förbrukar koden."""
    post = PENDING.get(epost)
    if post and time.time() < post["utgang"] and angiven == post["kod"]:
        PENDING.pop(epost, None)
        session.pop("pending_epost", None)
        return True
    return False


@app.before_request
def krav_login():
    """Bootstrap till setup om ingen admin finns; annars kräv inloggning."""
    if request.endpoint == "static":
        return
    # Första gången: ingen admin finns → tvinga setup-flödet.
    if not finns_admin():
        if request.endpoint not in ("setup", "setup_verify"):
            return redirect(url_for("setup"))
        return
    # Normalt läge: inloggning/verifiering är öppna, resten kräver inloggning.
    if request.endpoint in ("login", "verify", "setup", "setup_verify"):
        return
    if not inloggad():
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
            users[epost] = {"epost": epost, "admin": True}
            spara_anvandare(users)
            session["inloggad"] = True
            session["epost"] = epost
            session["admin"] = True
            return redirect(url_for("home"))
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
            session["inloggad"] = True
            session["epost"] = epost
            session["admin"] = las_anvandare().get(epost, {}).get("admin", False)
            return redirect(url_for("home"))
        fel = "Fel eller utgången kod."
    return render_template("verify.html", epost=epost, fel=fel)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Användarhantering (endast admin) ----------------------------------------
@app.route("/users")
def users_sida():
    if not ar_admin():
        return redirect(url_for("home"))
    return render_template("users.html", users=list(las_anvandare().values()),
                           jag=session.get("epost"))


@app.route("/users", methods=["POST"])
def skapa_user():
    if not ar_admin():
        return redirect(url_for("home"))
    epost = request.form.get("epost", "").strip().lower()
    if "@" in epost:
        users = las_anvandare()
        if epost not in users:
            users[epost] = {"epost": epost, "admin": False}
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
    return render_template("home.html", devices=load_devices(),
                           endpoint=endpoint(), allowed=ALLOWED_IPS,
                           is_admin=ar_admin())


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
    }
    hub.add_peer(pub, vpn_ip)
    devices.append(device)
    save_devices(devices)
    return redirect(url_for("visa_device", device_id=device["id"]))


@app.route("/devices/<device_id>")
def visa_device(device_id):
    device = next((d for d in load_devices() if d["id"] == device_id), None)
    if not device:
        return "Enhet saknas", 404
    conf = bygg_klientconfig(device)
    return render_template("device.html", device=device, conf=conf,
                           qr=qr_svg(conf))


@app.route("/devices/<device_id>/config")
def ladda_config(device_id):
    device = next((d for d in load_devices() if d["id"] == device_id), None)
    if not device:
        return "Enhet saknas", 404
    conf = bygg_klientconfig(device)
    return Response(conf, mimetype="text/plain", headers={
        "Content-Disposition": f'attachment; filename="tunnelo-{device["namn"]}.conf"'
    })


@app.route("/devices/<device_id>/delete", methods=["POST"])
def ta_bort_device(device_id):
    devices = load_devices()
    device = next((d for d in devices if d["id"] == device_id), None)
    if device:
        hub.remove_peer(device["pub"])
        devices = [d for d in devices if d["id"] != device_id]
        save_devices(devices)
    return redirect(url_for("home"))


# --- Web-terminal (SSH i webbläsaren) ----------------------------------------
@app.route("/terminal")
def terminal():
    """Sida med en terminal (xterm.js) man kan öppna en SSH-session i."""
    return render_template("terminal.html")


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
