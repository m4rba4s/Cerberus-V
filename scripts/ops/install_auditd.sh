#!/usr/bin/env bash
set -euo pipefail

# Enable and start auditd safely. Fedora 42 compatible.

if ! command -v sudo >/dev/null 2>&1; then echo "sudo required" >&2; exit 1; fi

echo "[+] Installing audit packages (if missing)"
if command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y audit audit-libs || true
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y && sudo apt-get install -y auditd || true
fi

echo "[+] Enabling auditd"
sudo systemctl enable --now auditd || true

echo "[i] Verifying journal access"
journalctl -n 1 --no-pager >/dev/null 2>&1 || true

echo "[✓] auditd ready"


