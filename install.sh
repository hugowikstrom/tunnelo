#!/usr/bin/env bash
#
# Tunnelo — installationsskript. Hämtar koden från GitHub, ställer några frågor
# och sätter upp allt (Python-miljö, .env, valfri Caddy + systemd).
#
# Kör:
#   curl -sSL https://raw.githubusercontent.com/hugowikstrom/tunnelo/master/install.sh | bash
# (privat repo → gör det publikt eller ha git-inloggning; annars: klona själv och
#  kör  bash install.sh  inifrån mappen.)
#
set -e

REPO="https://github.com/hugowikstrom/tunnelo.git"
DIR="${TUNNELO_DIR:-$HOME/tunnelo}"

blip(){ printf "\n\033[1;36m==> %s\033[0m\n" "$1"; }
fraga(){ local svar; read -rp "$1" svar; echo "${svar:-$2}"; }

blip "Tunnelo-installation"

# 1) Hämta/uppdatera koden ----------------------------------------------------
if [ -d "$DIR/.git" ]; then
  echo "Uppdaterar befintlig installation i $DIR"
  git -C "$DIR" pull --ff-only || true
elif [ -d server ] && [ -f server/webapp.py ]; then
  DIR="$(pwd)"; echo "Kör i befintlig kopia: $DIR"
else
  echo "Klonar Tunnelo till $DIR"
  git clone "$REPO" "$DIR"
fi
cd "$DIR/server"

# 2) Frågor -------------------------------------------------------------------
blip "Konfiguration (tryck Enter för förslaget inom hakparentes)"
DOMAN=$(fraga "Domän (t.ex. tunnelo.exempel.se) [localhost]: " "localhost")
WEBPORT=$(fraga "Flask-port bakom Caddy [8090]: " "8090")
HUBPORT=$(fraga "WireGuard-navets UDP-port [51820]: " "51820")
RESEND=$(fraga "Resend API-nyckel för mail (valfritt, Enter för hoppa över): " "")
MAILFROM=$(fraga "Avsändaradress [Tunnelo <onboarding@resend.dev>]: " "Tunnelo <onboarding@resend.dev>")

# 3) Python-miljö -------------------------------------------------------------
blip "Skapar Python-miljö och installerar beroenden"
command -v python3 >/dev/null || { echo "python3 saknas — installera det först."; exit 1; }
python3 -m venv venv
./venv/bin/pip install -q --upgrade pip
./venv/bin/pip install -q -r requirements.txt
echo "Klart."

# 4) .env ---------------------------------------------------------------------
blip "Skriver server/.env"
cat > .env <<ENV
TUNNELO_ENDPOINT=$DOMAN
TUNNELO_WEBPORT=$WEBPORT
TUNNELO_HUB_PORT=$HUBPORT
TUNNELO_RESEND_KEY=$RESEND
TUNNELO_MAIL_FROM=$MAILFROM
ENV
chmod 600 .env
echo ".env skapad (hemligheter, gitignorad)."

# 5) WireGuard-koll -----------------------------------------------------------
command -v wg >/dev/null || echo "OBS: WireGuard (wg) saknas — installera: sudo apt install wireguard"

# 6) Caddy (valfritt) ---------------------------------------------------------
if command -v caddy >/dev/null && [ "$DOMAN" != "localhost" ]; then
  if [[ "$(fraga "Lägg till Caddy-block för $DOMAN (HTTPS)? [j/N]: " "N")" =~ ^[jJyY] ]]; then
    sudo cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.tunnelo-$(date +%s)" 2>/dev/null || true
    sudo tee -a /etc/caddy/Caddyfile >/dev/null <<CADDY

$DOMAN {
	encode zstd gzip
	reverse_proxy localhost:$WEBPORT
}
CADDY
    sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && \
      sudo systemctl reload caddy && echo "Caddy uppdaterad."
  fi
fi

# 7) systemd-tjänst (valfritt) ------------------------------------------------
if [[ "$(fraga "Starta Tunnelo automatiskt vid boot (systemd)? [j/N]: " "N")" =~ ^[jJyY] ]]; then
  sudo tee /etc/systemd/system/tunnelo.service >/dev/null <<UNIT
[Unit]
Description=Tunnelo VPN-portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$DIR/server
ExecStart=$DIR/server/venv/bin/python $DIR/server/webapp.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now tunnelo.service
  echo "Tjänsten 'tunnelo' startad och aktiverad vid boot."
else
  blip "Starta manuellt"
  echo "  cd $DIR/server && sudo ./venv/bin/python webapp.py"
fi

blip "Färdigt!"
echo "Öppna  https://$DOMAN  och skapa administratören vid första inloggningen."
