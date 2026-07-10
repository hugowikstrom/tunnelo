# Tunnelo

Ett privat, krypterat VPN i Tailscale-stil, byggt i Python ovanpå WireGuard.
Kan köras på två sätt:

- **Webbportal (hub-and-spoke)** ← *det snygga flödet.* Logga in på en websida,
  skapa en enhet, scanna en QR-kod med officiella WireGuard-appen → uppkopplad.
- **Mesh (klient-agent)** — noder kopplar direkt till varandra via en CLI.
  (Se längst ner.)

---

## Webbportal (rekommenderat)

### Så funkar det
```
   telefon/dator  ──scanna QR──►  WireGuard-app  ──UDP-tunnel──►  Tunnelo-nav (servern)
        ▲                                                              │
        └────────── webbsida på port 80/443 (Caddy → Flask) ──────────┘
                    (här loggar du in & skapar enheten)
```

- **Webbsidan** (Flask) körs på port 80/443 — där loggar du in och skapar enheter.
- **Navet** är ett WireGuard-interface (`tunnelo-hub`, 10.44.0.1) som alla enheter
  kopplar in mot. Servern lägger till din enhet som *peer* live.
- **Klienten** är den **officiella WireGuard-appen** (iOS/Android/dator, gratis).
  Du scannar bara QR-koden — ingen egen app behövs.

> **Obs:** WireGuard är UDP och går på port 51820, inte "genom" port 80.
> Webb*portalen* går på 80/443; VPN-*tunneln* på UDP 51820.

### Kör
```bash
cd server
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Flask kör som root (behövs för wg-kommandon):
sudo -E env \
  TUNNELO_ENDPOINT="tunnelo.nattviken.com" \
  TUNNELO_WEBPORT=8090 \
  TUNNELO_SMTP_HOST="smtp.din-mailleverantör.se" \
  TUNNELO_SMTP_USER="..." TUNNELO_SMTP_PASS="..." \
  ./venv/bin/python webapp.py
```
> Utan `TUNNELO_SMTP_HOST` skrivs inloggningskoden i serverloggen istället för
> att mailas — praktiskt vid test.

**Caddy** står redan framför på `tunnelo.nattviken.com` (i `/etc/caddy/Caddyfile`)
och proxar till Flask på 8090 med automatisk HTTPS.

### Första start & inloggning (email-tvåstegsverifiering)
1. **Första gången** portalen startas finns ingen användare → du skickas till en
   *setup-sida* som frågar efter **admin-mailadressen**. En kod mailas; ange den
   så skapas admin och du loggas in.
2. **Admin** kan sedan gå till *Hantera användare* och lägga till fler mailadresser.
3. **Inloggning** för alla: ange mailadress → en 6-siffrig engångskod mailas (gäller
   10 min, engångs) → ange koden. Adresser som inte är registrerade får:
   *"Adressen är inte registrerad i tvåstegsverifieringen"*.

Användarna sparas i `server/users.json` (gitignorad).

### Miljövariabler (webapp)
| Variabel | Default | Betydelse |
|----------|---------|-----------|
| `TUNNELO_ENDPOINT` | maskinens IP | serverns publika `ip:port` som enheter kopplar mot |
| `TUNNELO_WEBPORT` | `80` | port Flask lyssnar på (sätt 8090 bakom Caddy) |
| `TUNNELO_HUB_PORT` | `51820` | WireGuard-navets UDP-port (byt om upptagen) |
| `TUNNELO_ALLOWED` | `10.44.0.0/24` | vad som routas genom VPN. `0.0.0.0/0` = **full tunnel** |
| `TUNNELO_SMTP_HOST` | (ingen) | SMTP-server för koder. Utan denna loggas koden istället |
| `TUNNELO_SMTP_PORT/USER/PASS/FROM` | `587` / — | SMTP-inloggning |

### Web-terminal (SSH i webbläsaren)
Portalen har en inbyggd SSH-terminal (`Öppna SSH-terminal` på startsidan).
Den kör i webbläsaren (xterm.js) och kopplar via en websocket till en riktig
SSH-session (paramiko på servern). Praktiskt på **mobilen** där SSH annars är
krångligt — logga in på portalen, öppna terminalen mot servern eller en maskin
på VPN-nätet (`10.44.0.x`). Skyddas av samma inloggning som resten av portalen.

Portalen är **mobilanpassad** (responsiv layout, staplas snyggt på små skärmar).

---

## Om NAT och brandväggar
Hub-and-spoke löser det mesta av NAT-problemet automatiskt: klienter bakom
brandvägg skickar *utgående* UDP till navet, och `PersistentKeepalive = 25`
(finns i klient-configen) håller hålet öppet så trafik kan gå både in och ut —
**så länge navet har en publik, nåbar IP**. Då behövs ingen hålslagning.

Det WireGuard *inte* löser själv är **direkt peer-to-peer mellan två NAT:ade
klienter** (mesh utan att gå via navet). Det kräver STUN (upptäck egen publik
ip:port), UDP-hålslagning och ett relä (TURN/DERP) som fallback — se *Nästa steg*.

---

## Mesh (klient-agent) — alternativ

Noder kopplar direkt till varandra via en CLI istället för mot ett nav.

```bash
# server
cd server && source venv/bin/activate
TUNNELO_TOKEN="min-token" TUNNELO_PORT=8088 python app.py

# klient
cd client && cp config.example.ini config.ini   # fyll i server_url + token
sudo python3 tunnelo.py up        # up | down | status | sync
```

---

## Avgränsningar (MVP)
- **Ingen NAT-traversering** ännu — servern/navet behöver publik, nåbar IP.
- Servern genererar enhetens privata nyckel (standard för QR-portaler, men mindre
  "rent" än att klienten gör det själv). Nyckeln finns bara i den nedladdade filen.
- Enkel inloggning (delat lösen). Riktig per-användare-auth blir senare.

Se `../.claude/plans/soft-scribbling-whale.md` för plan och nästa steg.
