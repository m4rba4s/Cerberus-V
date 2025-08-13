#!/usr/bin/env bash
set -euo pipefail

# Cerberus-V: install/update logrotate rule without opening editors as root
# Safe, idempotent, SELinux-aware. Does not touch application sources.

LOGDIR="/var/log/cerberus"
CONF="/etc/logrotate.d/cerberus"

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
require install
require tee

echo "[+] Ensuring log directory $LOGDIR"
sudo install -d -m 0755 -o root -g root "$LOGDIR"

TMP=$(mktemp)
cat >"$TMP" <<'EOF'
/var/log/cerberus/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    maxsize 100M
    create 0640 root root
    postrotate
        systemctl reload rsyslog 2>/dev/null || true
    endscript
}
EOF

echo "[+] Installing logrotate rule to $CONF"
sudo install -D -m 0644 -o root -g root "$TMP" "$CONF"
rm -f "$TMP"

# SELinux context (Fedora/RHEL)
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
  echo "[+] Aligning SELinux context for $LOGDIR"
  sudo semanage fcontext -a -t var_log_t '/var/log/cerberus(/.*)?' 2>/dev/null || \
  sudo semanage fcontext -m -t var_log_t '/var/log/cerberus(/.*)?' || true
  sudo restorecon -Rv /var/log/cerberus >/dev/null || true
fi

echo "[+] Dry-run logrotate check"
if command -v logrotate >/dev/null 2>&1; then
  sudo logrotate -d "$CONF" | sed -n '1,80p' || true
fi

echo "[✓] Done"


