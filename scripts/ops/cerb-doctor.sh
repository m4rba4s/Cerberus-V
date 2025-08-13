#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-}

echo "== Cerberus Doctor =="
echo "Host: $(hostname)  Kernel: $(uname -r)"

echo "-- Interfaces --"
ip -j link 2>/dev/null | jq -r '.[] | "\(.ifname)	state=\(.operstate)"' || ip -o link show | awk -F': ' '{print $2}'

if [[ -n "$IFACE" ]]; then
  echo "-- Offloads ($IFACE) --"
  ethtool -k "$IFACE" 2>/dev/null | egrep 'gro|lro|gso|tso' || true
  echo "-- Queues ($IFACE) --"
  ethtool -l "$IFACE" 2>/dev/null || true
  echo "-- XDP ($IFACE) --"
  ip link show "$IFACE" | grep -i xdp || true
fi

echo "-- BPF maps --"
bpftool map show 2>/dev/null | sed -n '1,80p' || echo "bpftool not available"

echo "-- VPP --"
vppctl show interface 2>/dev/null | sed -n '1,60p' || echo "vppctl not available"

echo "-- GeoIP --"
if [[ -n "${CERB_GEOIP_DB:-}" ]]; then
  echo "CERB_GEOIP_DB=$CERB_GEOIP_DB ($( [ -f "$CERB_GEOIP_DB" ] && echo present || echo missing))"
else
  for p in /usr/share/GeoIP/GeoLite2-Country.mmdb /usr/local/share/GeoIP/GeoLite2-Country.mmdb "$HOME/.local/share/GeoIP/GeoLite2-Country.mmdb"; do
    [[ -f "$p" ]] && { echo "GeoIP DB: $p"; break; }
  done || true
fi

echo "-- Auditd --"
systemctl is-active auditd 2>/dev/null || echo "auditd not active"

echo "== Done =="


