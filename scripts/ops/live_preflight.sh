#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-}

echo "[+] Cerberus LIVE Preflight"

echo "[1/5] Backend health"
curl -fsS :8000/api/system/status >/dev/null || { echo "Backend down"; exit 1; }

echo "[2/5] Interfaces"
if [[ -n "$IFACE" ]]; then
  ip link show "$IFACE" >/dev/null || { echo "Iface $IFACE missing"; exit 1; }
  ethtool -k "$IFACE" 2>/dev/null | awk '/(gro|lro|gso):/ && $2!="off" {bad=1} END{exit bad}' || { echo "Disable offloads on $IFACE"; exit 1; }
fi

echo "[3/5] GeoIP DB"
DB="${CERB_GEOIP_DB:-}"
for p in "$DB" /usr/share/GeoIP/GeoLite2-Country.mmdb /usr/local/share/GeoIP/GeoLite2-Country.mmdb "$HOME/.local/share/GeoIP/GeoLite2-Country.mmdb"; do
  [[ -n "$p" && -f "$p" ]] && { DB="$p"; break; }
done
[[ -f "$DB" ]] || echo "(info) GeoIP DB not found; geo analytics will be N/A"

echo "[4/5] VPP alive"
vppctl show version >/dev/null 2>&1 || echo "(info) VPP not running"

echo "[5/5] Auditd"
systemctl is-active --quiet auditd && echo "auditd: active" || echo "(info) auditd not active"

echo "[✓] Preflight OK"


