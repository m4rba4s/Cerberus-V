#!/usr/bin/env bash
set -euo pipefail

echo "[+] Cerberus-V bootstrap (ops)"

ROOT="/home/outspoken/Cerberus-V"

echo "[+] Python deps (backend)"
if [ -x "$ROOT/gui/backend/venv/bin/python" ]; then
  PIP="$ROOT/gui/backend/venv/bin/pip"
else
  python3 -m venv "$ROOT/gui/backend/venv"
  PIP="$ROOT/gui/backend/venv/bin/pip"
fi
"$PIP" install -r "$ROOT/gui/backend/requirements.txt"

echo "[+] Install logrotate"
chmod +x "$ROOT/scripts/ops/install_logrotate.sh"
sudo "$ROOT/scripts/ops/install_logrotate.sh"

echo "[✓] Bootstrap complete"


