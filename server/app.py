"""
Tunnelo — koordinationsserver ("telefonkatalogen").

Vet vilka noder som finns, deras publika WireGuard-nycklar, endpoints och
tilldelade VPN-IP. Skickar INTE själva trafiken — den går direkt mellan noder.

Kör:
    python app.py            # lyssnar på :8080
"""
import ipaddress
import json
import os
import threading

from flask import Flask, jsonify, request

app = Flask(__name__)

# --- Inställningar -----------------------------------------------------------
STATE_FILE = os.path.join(os.path.dirname(__file__), "state.json")
# Delad token som klienterna måste skicka med. Byt gärna till nåt hemligt.
TOKEN = os.environ.get("TUNNELO_TOKEN", "hemlig-token-byt-mig")
# VPN-nätet noder tilldelas IP ur. .1 reserveras, noder får .2 och uppåt.
NET = ipaddress.ip_network("10.44.0.0/24")

# En lås så att flera samtidiga anrop inte skriver sönder state-filen.
_lock = threading.Lock()


# --- Lagring (enkel JSON-fil) ------------------------------------------------
def load_state():
    """Läs noderna från disk. Tom dict om filen inte finns än."""
    if not os.path.exists(STATE_FILE):
        return {"nodes": {}}
    with open(STATE_FILE) as f:
        return json.load(f)


def save_state(state):
    """Skriv noderna till disk."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def next_free_ip(state):
    """Hitta nästa lediga VPN-IP (.2 och uppåt)."""
    upptagna = {n["vpn_ip"] for n in state["nodes"].values()}
    for host in NET.hosts():
        ip = str(host)
        if ip.endswith(".1"):  # reserverad för servern/gateway
            continue
        if ip not in upptagna:
            return ip
    raise RuntimeError("Slut på VPN-adresser")


# --- Auth --------------------------------------------------------------------
def check_token():
    """Returnerar True om anropet har rätt token i Authorization-headern."""
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {TOKEN}"


# --- API ---------------------------------------------------------------------
@app.get("/health")
def health():
    """Enkel statuskoll — kräver ingen token."""
    return jsonify(status="ok")


@app.post("/register")
def register():
    """
    Nod registrerar sig. Body: {namn, publik_nyckel, endpoint}.
    Svarar med tilldelat vpn_ip. Registrerar man samma publika nyckel igen
    får man behålla sitt IP (idempotent).
    """
    if not check_token():
        return jsonify(fel="ogiltig token"), 401

    data = request.get_json(force=True)
    for falt in ("namn", "publik_nyckel", "endpoint"):
        if not data.get(falt):
            return jsonify(fel=f"saknar fält: {falt}"), 400

    with _lock:
        state = load_state()
        nyckel = data["publik_nyckel"]

        if nyckel in state["nodes"]:
            # Känd nod — uppdatera endpoint/namn, behåll IP.
            nod = state["nodes"][nyckel]
            nod["namn"] = data["namn"]
            nod["endpoint"] = data["endpoint"]
        else:
            # Ny nod — tilldela IP.
            nod = {
                "namn": data["namn"],
                "publik_nyckel": nyckel,
                "endpoint": data["endpoint"],
                "vpn_ip": next_free_ip(state),
            }
            state["nodes"][nyckel] = nod

        save_state(state)

    return jsonify(vpn_ip=nod["vpn_ip"])


@app.get("/peers")
def peers():
    """
    Returnerar alla noder UTOM den som frågar (identifieras via ?nyckel=...).
    Detta är listan klienten bygger sin WireGuard-tunnel av.
    """
    if not check_token():
        return jsonify(fel="ogiltig token"), 401

    egen_nyckel = request.args.get("nyckel", "")
    state = load_state()
    lista = [
        n for k, n in state["nodes"].items() if k != egen_nyckel
    ]
    return jsonify(peers=lista)


if __name__ == "__main__":
    # 0.0.0.0 så andra maskiner kan nå servern. Port via TUNNELO_PORT (default 8080).
    app.run(host="0.0.0.0", port=int(os.environ.get("TUNNELO_PORT", "8080")))
