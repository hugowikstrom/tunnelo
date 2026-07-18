#!/usr/bin/env bash
#
# Tunnelo – installationsskript.
# Installerar ALLA beroenden (tmux, screen, ffmpeg, ev. VNC, KB-Whisper …),
# drar koden från GitHub och sätter upp systemd-tjänsten. Kör sedan
# konfigurera.py för admin-inloggning och ev. nycklar.
#
# Kör som root:
#   curl -sSL https://raw.githubusercontent.com/hugowikstrom/tunnelo/master/install.sh | sudo bash
# eller från en klon:
#   sudo bash install.sh
#
set -euo pipefail

# ---- Inställningar (kan överstyras med miljövariabler) ----
REPO="${TUNNELO_REPO:-https://github.com/hugowikstrom/tunnelo.git}"
DIR="${TUNNELO_DIR:-/opt/tunnelo}"            # var koden hamnar
PORT="${TUNNELO_WEBPORT:-8090}"               # Flask-port (bakom Caddy)
SERVICE_USER="${TUNNELO_USER:-root}"          # tjänsten kör som denna användare
LOGGDIR="${TUNNELO_LOGG:-/var/log/tunnelo}"

say(){ printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }
# Läs från terminalen (funkar även vid  curl … | sudo bash )
fraga(){ local s; read -rp "$1 [j/N]: " s </dev/tty; [[ "$s" =~ ^[jJyY]$ ]]; }

[[ $EUID -eq 0 ]] || { echo "Kör som root (sudo bash install.sh)"; exit 1; }

# ---- 1. Systempaket (grund) ----
say "Installerar systempaket"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y git python3 python3-venv python3-pip tmux screen ffmpeg curl

say "Grafiskt skrivbord (VNC + xfce) – stort, behövs bara för Grafik-läget."
if fraga "Installera TigerVNC + xfce"; then
  apt-get install -y tigervnc-standalone-server tigervnc-common xfce4 xfce4-terminal dbus-x11 || true
  VNC=1
else
  VNC=0
fi

fraga "Installera espeak-ng (bara för att testa tal-till-text)" && apt-get install -y espeak-ng || true

# ---- 2. Hämta koden ----
say "Hämtar koden till $DIR"
if [[ -d "$DIR/.git" ]]; then
  git -C "$DIR" pull --ff-only
else
  mkdir -p "$(dirname "$DIR")"
  git clone "$REPO" "$DIR"
fi
cd "$DIR/server"

# ---- 3. Python-miljö + beroenden ----
say "Skapar venv och installerar Python-beroenden"
python3 -m venv venv
./venv/bin/python -m pip install --upgrade pip -q
./venv/bin/python -m pip install -q -r requirements.txt

# ---- 4. Ladda ner KB-Whisper (svensk tal-till-text) ----
say "Laddar ner KB-Whisper – kan ta en stund"
./venv/bin/python - <<'PY' || echo "  (misslyckades – laddas vid första mic-användningen i stället)"
from faster_whisper import WhisperModel
WhisperModel("KBLab/kb-whisper-small", device="cpu", compute_type="int8")
print("  KB-Whisper nedladdad")
PY

# ---- 5. Hemligheter + loggkatalog ----
say "Förbereder nyckel och loggkatalog"
[[ -f secret.key ]] || ./venv/bin/python -c "import secrets,pathlib; pathlib.Path('secret.key').write_text(secrets.token_hex(32))"
chmod 600 secret.key
mkdir -p "$LOGGDIR"

# ---- 6. systemd-tjänst ----
say "Installerar systemd-tjänsten tunnelo-portal"
cat > /etc/systemd/system/tunnelo-portal.service <<EOF
[Unit]
Description=Tunnelo portal (Flask, port $PORT, bakom Caddy)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$DIR/server
Environment=TUNNELO_WEBPORT=$PORT
ExecStart=$DIR/server/venv/bin/python webapp.py
Restart=on-failure
RestartSec=3
StandardOutput=append:$LOGGDIR/tunnelo-portal.log
StandardError=append:$LOGGDIR/tunnelo-portal.log

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

# ---- 7. VNC-skrivbord (om valt) ----
if [[ "${VNC:-0}" == "1" ]]; then
  say "Sätter upp VNC-skrivbord (xfce) på :1 / localhost:5901"
  HOME_DIR=$(getent passwd "$SERVICE_USER" | cut -d: -f6)
  mkdir -p "$HOME_DIR/.vnc"
  cat > "$HOME_DIR/.vnc/xstartup" <<'EOF'
#!/bin/sh
unset SESSION_MANAGER; unset DBUS_SESSION_BUS_ADDRESS
exec dbus-launch startxfce4
EOF
  chmod +x "$HOME_DIR/.vnc/xstartup"
  echo "  Starta skrivbordet: vncserver :1 -geometry 1440x900 -localhost yes -SecurityTypes None"
fi

# ---- 8. Konfiguration (admin-login, ev. nycklar) ----
say "Kör konfigurationen"
./venv/bin/python "$DIR/konfigurera.py" || \
  echo "  Hoppade över – kör senare: $DIR/server/venv/bin/python $DIR/konfigurera.py"

# ---- 9. Starta tjänsten ----
say "Startar tjänsten"
systemctl enable --now tunnelo-portal
sleep 2
systemctl --no-pager --lines=0 status tunnelo-portal || true

cat <<EOF

$(printf '\033[1;32mKlart!\033[0m') Tunnelo körs på http://localhost:$PORT

För HTTPS – lägg en Caddy-block (byt domän):

  din-domän.se {
      encode zstd gzip
      reverse_proxy localhost:$PORT {
          transport http { read_timeout 600s; write_timeout 600s }
      }
  }

Nycklar (Resend/SMTP) kan läggas in nu eller senare under "Konfiguration" i appen.
EOF
