#!/usr/bin/env bash
# MyTunnel installer:  bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USER/mytunnel/main/install.sh)
set -euo pipefail

REPO="YOUR_USER/mytunnel"      # <-- change to your GitHub user/repo
BRANCH="main"
URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/mytunnel.py"
DEST="/usr/local/bin/mytunnel"

[ "$(id -u)" -eq 0 ] || { echo "Run as root (use sudo)."; exit 1; }

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found, installing..."
  if command -v apt-get >/dev/null 2>&1; then apt-get update -y && apt-get install -y python3
  elif command -v dnf >/dev/null 2>&1; then dnf install -y python3
  elif command -v yum >/dev/null 2>&1; then yum install -y python3
  else echo "Install python3 manually and run again."; exit 1; fi
fi

TMP="$(mktemp)"
if [ -f "./mytunnel.py" ] && [ "${1:-}" = "--local" ]; then
  cp ./mytunnel.py "$TMP"                     # offline install: run from the folder with mytunnel.py
else
  curl -fsSL "$URL" -o "$TMP"
fi

python3 -m py_compile "$TMP"                  # refuse to install a broken/partial download
install -m 0755 "$TMP" "$DEST"
rm -f "$TMP"
echo "Installed: $DEST  (version $("$DEST" --version))"

[ -t 0 ] && exec "$DEST"
echo "Run:  sudo mytunnel"
