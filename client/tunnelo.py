#!/usr/bin/env python3
"""
Tunnelo — klient-agent.

Genererar WireGuard-nycklar, registrerar sig hos koordinationsservern och
sätter upp en krypterad tunnel (interface `tunnelo0`) mot alla andra noder.

Kommandon:
    sudo python3 tunnelo.py up      # anslut (skapar nycklar första gången)
    sudo python3 tunnelo.py down    # koppla ner tunneln
    python3 tunnelo.py status       # visa eget IP + peers + wg-status
    sudo python3 tunnelo.py sync     # hämta peers på nytt och uppdatera tunneln

Kräver sudo för up/down/sync eftersom nätverksinterface skapas.
Config läses från config.ini (kopiera från config.example.ini).
"""
import configparser
import json
import os
import subprocess
import sys
import urllib.request

# --- Sökvägar ----------------------------------------------------------------
HAR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FIL = os.path.join(HAR, "config.ini")
# Nycklar sparas i användarens hemkatalog. Vid sudo pekar HOME ofta på root,
# så vi använder den riktiga inloggade användaren om SUDO_USER finns.
def tunnelo_dir():
    home = os.path.expanduser("~" + os.environ.get("SUDO_USER", "")) \
        if os.environ.get("SUDO_USER") else os.path.expanduser("~")
    d = os.path.join(home, ".tunnelo")
    os.makedirs(d, exist_ok=True)
    return d


# --- Config ------------------------------------------------------------------
def las_config():
    if not os.path.exists(CONFIG_FIL):
        sys.exit("Ingen config.ini — kopiera config.example.ini och fyll i.")
    cp = configparser.ConfigParser()
    cp.read(CONFIG_FIL)
    return cp["tunnelo"]


# --- WireGuard-nycklar -------------------------------------------------------
def wg(*args, indata=None):
    """Kör ett wg-kommando och returnera stdout (strippad)."""
    r = subprocess.run(
        args, input=indata, capture_output=True, text=True
    )
    if r.returncode != 0:
        sys.exit(f"Kommando misslyckades: {' '.join(args)}\n{r.stderr}")
    return r.stdout.strip()


def hamta_nycklar():
    """Läs (eller skapa vid första körning) nodens nyckelpar."""
    d = tunnelo_dir()
    priv_fil = os.path.join(d, "private.key")
    pub_fil = os.path.join(d, "public.key")

    if not os.path.exists(priv_fil):
        priv = wg("wg", "genkey")
        pub = wg("wg", "pubkey", indata=priv)
        with open(priv_fil, "w") as f:
            f.write(priv)
        os.chmod(priv_fil, 0o600)
        with open(pub_fil, "w") as f:
            f.write(pub)
        print(f"Nya nycklar skapade i {d}")

    with open(priv_fil) as f:
        priv = f.read().strip()
    with open(pub_fil) as f:
        pub = f.read().strip()
    return priv, pub


# --- Server-anrop ------------------------------------------------------------
def api(cfg, metod, vag, body=None):
    """Enkelt HTTP-anrop mot koordinationsservern med token-header."""
    url = cfg["server_url"].rstrip("/") + vag
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=metod)
    req.add_header("Authorization", f"Bearer {cfg['token']}")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def registrera(cfg, pub):
    """Registrera noden och få tillbaka tilldelat VPN-IP."""
    svar = api(cfg, "POST", "/register", {
        "namn": cfg["namn"],
        "publik_nyckel": pub,
        "endpoint": cfg["endpoint"],
    })
    return svar["vpn_ip"]


def hamta_peers(cfg, pub):
    return api(cfg, "GET", f"/peers?nyckel={pub}")["peers"]


# --- WireGuard-konfig --------------------------------------------------------
def bygg_config(cfg, priv, vpn_ip, peers):
    """Bygg en wg-quick-konfigfil (/etc/wireguard/<iface>.conf-format)."""
    iface = cfg["interface"]
    # Lyssningsport tas ur endpoint (ip:port) så andra noder når oss.
    port = cfg["endpoint"].rsplit(":", 1)[-1]

    rader = [
        "[Interface]",
        f"PrivateKey = {priv}",
        f"Address = {vpn_ip}/24",
        f"ListenPort = {port}",
        "",
    ]
    for p in peers:
        rader += [
            "[Peer]",
            f"# {p['namn']}",
            f"PublicKey = {p['publik_nyckel']}",
            f"AllowedIPs = {p['vpn_ip']}/32",
            f"Endpoint = {p['endpoint']}",
            "PersistentKeepalive = 25",
            "",
        ]
    return iface, "\n".join(rader)


def skriv_wg_config(iface, innehall):
    """Skriv konfigen till /etc/wireguard/<iface>.conf (kräver root)."""
    sokvag = f"/etc/wireguard/{iface}.conf"
    os.makedirs("/etc/wireguard", exist_ok=True)
    with open(sokvag, "w") as f:
        f.write(innehall)
    os.chmod(sokvag, 0o600)
    return sokvag


# --- Kommandon ---------------------------------------------------------------
def cmd_up(cfg):
    priv, pub = hamta_nycklar()
    vpn_ip = registrera(cfg, pub)
    peers = hamta_peers(cfg, pub)
    iface, innehall = bygg_config(cfg, priv, vpn_ip, peers)
    skriv_wg_config(iface, innehall)

    # Om interfacet redan finns, ta ner det först (så vi kan läsa om configen).
    subprocess.run(["wg-quick", "down", iface],
                   capture_output=True, text=True)
    r = subprocess.run(["wg-quick", "up", iface],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"wg-quick up misslyckades:\n{r.stderr}")
    print(f"Uppe! Ditt VPN-IP: {vpn_ip}  ({len(peers)} peers)")


def cmd_down(cfg):
    iface = cfg["interface"]
    r = subprocess.run(["wg-quick", "down", iface],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"wg-quick down misslyckades:\n{r.stderr}")
    print("Nere.")


def cmd_sync(cfg):
    """Hämta peers på nytt och bygg om tunneln (samma som up)."""
    cmd_up(cfg)


def cmd_status(cfg):
    priv, pub = hamta_nycklar()
    print(f"Namn:          {cfg['namn']}")
    print(f"Publik nyckel: {pub}")
    print(f"Server:        {cfg['server_url']}")
    try:
        peers = hamta_peers(cfg, pub)
        print(f"Peers ({len(peers)}):")
        for p in peers:
            print(f"  - {p['namn']:12} {p['vpn_ip']:12} {p['endpoint']}")
    except Exception as e:
        print(f"Kunde inte hämta peers: {e}")
    print("--- wg show ---")
    subprocess.run(["wg", "show", cfg["interface"]])


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    kommando = sys.argv[1]
    cfg = las_config()
    {
        "up": cmd_up,
        "down": cmd_down,
        "sync": cmd_sync,
        "status": cmd_status,
    }.get(kommando, lambda _: sys.exit(f"Okänt kommando: {kommando}"))(cfg)


if __name__ == "__main__":
    main()
