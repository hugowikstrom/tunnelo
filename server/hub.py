"""
Tunnelo Hub — hanterar serverns WireGuard-nav-interface.

Navet (`tunnelo-hub`) är interfacet som alla enheter kopplar in mot. Den här
modulen skapar navet och lägger till/tar bort peers live med `wg set`
(utan att ta ner tunneln).

Kräver root (webbappen körs som root för port 80 + wg-kommandon).
"""
import os
import subprocess

# --- Inställningar ------------------------------------------------------------
HUB_IFACE = "tunnelo-hub"
HUB_IP = "10.44.0.1"          # navets egen VPN-adress
# UDP-port som WireGuard lyssnar på. Byt via TUNNELO_HUB_PORT om 51820 är upptagen
# (t.ex. om du redan kör ett annat wg-interface).
HUB_PORT = int(os.environ.get("TUNNELO_HUB_PORT", "51820"))
NET_CIDR = "10.44.0.0/24"     # hela VPN-nätet

HAR = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(HAR, "hub_keys")
PRIV_FIL = os.path.join(KEY_DIR, "private.key")
PUB_FIL = os.path.join(KEY_DIR, "public.key")


# --- Hjälpare -----------------------------------------------------------------
def kor(*args, indata=None, tillat_fel=False):
    """Kör ett kommando, returnera stdout. Avbryt vid fel om ej tillat_fel."""
    r = subprocess.run(args, input=indata, capture_output=True, text=True)
    if r.returncode != 0 and not tillat_fel:
        raise RuntimeError(f"{' '.join(args)} misslyckades:\n{r.stderr}")
    return r.stdout.strip()


def _nycklar():
    """Skapa (första gången) och läs navets nyckelpar."""
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(PRIV_FIL):
        priv = kor("wg", "genkey")
        pub = kor("wg", "pubkey", indata=priv)
        with open(PRIV_FIL, "w") as f:
            f.write(priv)
        os.chmod(PRIV_FIL, 0o600)
        with open(PUB_FIL, "w") as f:
            f.write(pub)
    with open(PRIV_FIL) as f:
        priv = f.read().strip()
    with open(PUB_FIL) as f:
        pub = f.read().strip()
    return priv, pub


def _interface_finns():
    r = subprocess.run(["ip", "link", "show", HUB_IFACE],
                       capture_output=True, text=True)
    return r.returncode == 0


# --- Publika funktioner -------------------------------------------------------
def server_pubkey():
    """Navets publika nyckel (det klienterna krypterar till)."""
    return _nycklar()[1]


def ensure_hub():
    """Skapa och starta nav-interfacet om det inte redan finns."""
    priv, _ = _nycklar()
    if _interface_finns():
        return
    # Skapa WireGuard-interface och konfigurera det.
    kor("ip", "link", "add", HUB_IFACE, "type", "wireguard")
    kor("wg", "set", HUB_IFACE,
        "private-key", PRIV_FIL,
        "listen-port", str(HUB_PORT))
    kor("ip", "addr", "add", f"{HUB_IP}/24", "dev", HUB_IFACE)
    kor("ip", "link", "set", HUB_IFACE, "up")


def add_peer(pub, vpn_ip):
    """Lägg till en enhet som peer i navet (live)."""
    kor("wg", "set", HUB_IFACE, "peer", pub, "allowed-ips", f"{vpn_ip}/32")


def remove_peer(pub):
    """Ta bort en enhet ur navet."""
    kor("wg", "set", HUB_IFACE, "peer", pub, "remove", tillat_fel=True)


def gen_klientnycklar():
    """Generera ett nyckelpar åt en ny enhet."""
    priv = kor("wg", "genkey")
    pub = kor("wg", "pubkey", indata=priv)
    return priv, pub
