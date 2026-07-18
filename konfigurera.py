#!/usr/bin/env python3
"""
Tunnelo – interaktiv konfiguration.

Frågar om admin-inloggning och (valfria) nycklar, och skriver server/users.json
+ server/konfig.json. Allt utom admin-mejl är valfritt och kan läggas in senare
under "Konfiguration" i appen.

Kör:  python3 konfigurera.py     (helst med venv-pythonen)
"""
import os
import sys
import json
import hashlib

# Läs från terminalen även om skriptet startas via en pipe (curl … | bash)
try:
    if not sys.stdin.isatty() and os.path.exists("/dev/tty"):
        sys.stdin = open("/dev/tty")
except OSError:
    pass

HAR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server")
USERS = os.path.join(HAR, "users.json")
KONFIG = os.path.join(HAR, "konfig.json")


def fraga(text, dolt=False):
    if dolt:
        import getpass
        return getpass.getpass(text).strip()
    return input(text).strip()


def las(fil, standard):
    if os.path.exists(fil):
        with open(fil) as f:
            return json.load(f)
    return standard


def skriv(fil, data):
    with open(fil, "w") as f:
        json.dump(data, f, indent=2)


print("\n=== Tunnelo-konfiguration ===")
print("(Tryck Enter för att hoppa över valfria fält – de kan läggas in senare i appen.)\n")

# --- Admin (krävs) ---
epost = ""
while "@" not in epost:
    epost = fraga("Admin-mejladress (den som får logga in): ").lower()
users = las(USERS, [])
if not any(u.get("epost") == epost for u in users):
    users.append({"epost": epost, "admin": True, "allowed_ips": ""})
else:
    for u in users:
        if u.get("epost") == epost:
            u["admin"] = True
skriv(USERS, users)
print(f"  ✓ Admin satt: {epost}")

konfig = las(KONFIG, {})

# --- Installationslösenord (valfritt, bootstrap) ---
print("\nInstallationslösenord = logga in direkt utan mejl innan e-post är konfigurerad.")
print("Rekommenderas att tas bort under Konfiguration när e-posten fungerar.")
pw = fraga("Installationslösenord (Enter = inget): ", dolt=True)
if pw:
    konfig["install_losen_hash"] = hashlib.sha256(pw.encode()).hexdigest()
    print("  ✓ Installationslösenord satt")

# --- Mejlutskick: Resend eller SMTP (valfritt) ---
print("\nE-postutskick (för inloggningslänkar). Välj en – eller hoppa över.")
resend = fraga("Resend API-nyckel (re_…, Enter = hoppa): ")
if resend:
    konfig["resend_key"] = resend
    mf = fraga("Avsändaradress [Tunnelo <onboarding@resend.dev>]: ") or "Tunnelo <onboarding@resend.dev>"
    konfig["mail_from"] = mf
    print("  ✓ Resend satt")
else:
    host = fraga("SMTP-värd (Enter = hoppa): ")
    if host:
        konfig["smtp_host"] = host
        konfig["smtp_port"] = fraga("SMTP-port [587]: ") or "587"
        konfig["smtp_user"] = fraga("SMTP-användare: ")
        konfig["smtp_pass"] = fraga("SMTP-lösenord: ", dolt=True)
        konfig["mail_from"] = fraga("Avsändaradress: ") or konfig.get("smtp_user", "")
        print("  ✓ SMTP satt")

skriv(KONFIG, konfig)
for f in (USERS, KONFIG):
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass

print("\nKlart. Filerna server/users.json och server/konfig.json är skrivna (gitignorerade).")
print("Starta om tjänsten om den redan kör:  sudo systemctl restart tunnelo-portal")
print("Fler nycklar kan läggas in senare under 'Konfiguration' i appen.\n")
