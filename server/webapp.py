"""
Tunnelo — webbportal (hub-and-spoke VPN).

Logga in på en websida → skapa en enhet → scanna QR-kod med officiella
WireGuard-appen → uppkopplad mot servern.

Kör (kräver root för port 80 + wg):
    sudo TUNNELO_ENDPOINT=<serverns-publika-ip> ./venv/bin/python webapp.py

Miljövariabler:
    TUNNELO_LOSEN      inloggningslösen (default "hugo")
    TUNNELO_ENDPOINT   serverns publika ip:port som enheter kopplar mot
                     (default: maskinens IP + :51820)
    TUNNELO_WEBPORT    port för webbsidan (default 80)
    TUNNELO_ALLOWED    AllowedIPs i klient-config (default 10.44.0.0/24 =
                     bara VPN-nätet. Sätt 0.0.0.0/0 för att skicka ALL
                     trafik genom VPN:et = full tunnel.)
"""
import base64
import io
import json
import os
import secrets
import socket

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
LOSEN = os.environ.get("TUNNELO_LOSEN", "hugo")
WEBPORT = int(os.environ.get("TUNNELO_WEBPORT", "80"))
ALLOWED_IPS = os.environ.get("TUNNELO_ALLOWED", hub.NET_CIDR)

HAR = os.path.dirname(os.path.abspath(__file__))
DEVICES_FIL = os.path.join(HAR, "devices.json")


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


@app.before_request
def krav_login():
    """Kräv inloggning för allt utom login-sidan och statiska filer."""
    if request.endpoint in ("login", "static"):
        return
    if not inloggad():
        return redirect(url_for("login"))


# --- Vyer ---------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    fel = None
    if request.method == "POST":
        if request.form.get("losen") == LOSEN:
            session["inloggad"] = True
            return redirect(url_for("home"))
        fel = "Fel lösenord"
    return render_template("login.html", fel=fel)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    return render_template("home.html", devices=load_devices(),
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
