#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install/repair logrotate config for Cerberus-V in an immutable/SELinux-safe way

set -euo pipefail

LOGROTATE_FILE=/etc/logrotate.d/cerberus
TMP_FILE=$(mktemp /tmp/cerberus-logrotate.XXXXXX)
REPO_CONF="$(dirname "$0")/../config/logrotate/cerberus.conf"

echo "[install-logrotate] Preparing directories and contexts"

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

# Ensure log directory exists with sane perms
install -d -m 0750 -o root -g root /var/log/cerberus

# SELinux: label as var_log_t when tools available
if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -a -t var_log_t '/var/log/cerberus(/.*)?' 2>/dev/null || true
fi
command -v restorecon >/dev/null 2>&1 && restorecon -R /var/log/cerberus || true

echo "[install-logrotate] Rendering config → $TMP_FILE (atomic)"
if [[ -f "$REPO_CONF" ]]; then
  # Use repo-provided config if present
  cp "$REPO_CONF" "$TMP_FILE"
else
cat > "$TMP_FILE" <<'EOF'
/var/log/cerberus/*.log {
    daily
    rotate 7
    maxsize 100M
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    su root root
    copytruncate
    prerotate
        # Drop immutability/append-only before rotation
        for f in /var/log/cerberus/*.log; do
            [ -f "$f" ] || continue
            chattr -i "$f" 2>/dev/null || true
            chattr -a "$f" 2>/dev/null || true
        done
    endscript
    postrotate
        systemctl reload rsyslog 2>/dev/null || true
        for f in /var/log/cerberus/*.log; do
            [ -f "$f" ] || continue
            # Re-enable append-only (safer for live writes than immutable)
            chattr +a "$f" 2>/dev/null || true
        done
    endscript
}
EOF
fi

echo "[install-logrotate] Installing $LOGROTATE_FILE (handles +i)"
install -d -m 0755 /etc/logrotate.d

# If target exists and is immutable, drop +i before replace
HAD_IMMUTABLE=0
if [[ -e "$LOGROTATE_FILE" ]]; then
  if lsattr "$LOGROTATE_FILE" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
    HAD_IMMUTABLE=1
    chattr -i "$LOGROTATE_FILE" || true
  fi
fi

install -o root -g root -m 0644 "$TMP_FILE" "$LOGROTATE_FILE"
rm -f "$TMP_FILE"

# Restore SELinux context and (re)apply immutability
command -v restorecon >/dev/null 2>&1 && restorecon -v "$LOGROTATE_FILE" || true
if [[ $HAD_IMMUTABLE -eq 1 ]]; then
  chattr +i "$LOGROTATE_FILE" || true
fi

echo "[install-logrotate] OK: $(ls -l $LOGROTATE_FILE | awk '{print $1, $3":"$4, $9}')"

# Apply append-only (+a) to existing live logs; remove immutable if mistakenly applied
for f in /var/log/cerberus/*.log; do
  [ -f "$f" ] || continue
  chattr -i "$f" 2>/dev/null || true
  chattr +a "$f" 2>/dev/null || true
done


