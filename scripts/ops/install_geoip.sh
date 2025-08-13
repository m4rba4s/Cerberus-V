#!/usr/bin/env bash
set -euo pipefail

# Install GeoLite2-Country.mmdb into a standard location.
# Usage: scripts/ops/install_geoip.sh /path/to/GeoLite2-Country.mmdb

SRC=${1:-}
if [[ -z "$SRC" || ! -f "$SRC" ]]; then
  echo "Usage: $0 /path/to/GeoLite2-Country.mmdb" >&2
  exit 2
fi

DEST=/usr/share/GeoIP/GeoLite2-Country.mmdb

echo "[+] Installing GeoIP DB -> $DEST"
sudo install -D -m 0644 -o root -g root "$SRC" "$DEST"

echo "[i] You can override path at runtime via CERB_GEOIP_DB=$DEST"
echo "[✓] Done"


