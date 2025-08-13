#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Host Hardening: Immutable Logs & Logrotate
set -euo pipefail

log() { echo -e "\033[1;34m[INFO]\033[0m $1"; }
err() { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; exit 1; }
success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }

# 1. Create log directories if missing
log "Checking /var/log/cerberus..."
sudo mkdir -p /var/log/cerberus || err "Failed to create /var/log/cerberus"
sudo chown root:root /var/log/cerberus
sudo chmod 750 /var/log/cerberus

# 2. Ensure /var/log/audit exists
log "Checking /var/log/audit..."
sudo mkdir -p /var/log/audit || err "Failed to create /var/log/audit"
sudo chown root:root /var/log/audit
sudo chmod 750 /var/log/audit

# 3. Handle audit.log immutable logic
AUDIT_LOG="/var/log/audit/audit.log"
AUDIT_DIR="/var/log/audit"
if [ ! -f "$AUDIT_LOG" ]; then
  log "audit.log does not exist, temporarily removing immutable from audit dir..."
  sudo chattr -i "$AUDIT_DIR" 2>/dev/null || true
  sudo touch "$AUDIT_LOG" || err "Failed to create audit.log"
  sudo chown root:root "$AUDIT_LOG"
  sudo chmod 600 "$AUDIT_LOG"
  sudo chattr +i "$AUDIT_DIR" 2>/dev/null || true
fi
log "Temporarily removing immutable from audit.log..."
sudo chattr -i "$AUDIT_LOG" 2>/dev/null || true
log "Setting audit.log immutable..."
sudo chattr +i "$AUDIT_LOG" || err "Failed to set chattr +i on audit.log"

# 4. Set cerberus logs immutable
log "Setting /var/log/cerberus/current.log immutable..."
CERBERUS_LOG="/var/log/cerberus/current.log"
sudo touch "$CERBERUS_LOG"
sudo chattr +i "$CERBERUS_LOG" || err "Failed to set chattr +i on cerberus/current.log"

# 5. Setup logrotate for cerberus logs
log "Configuring logrotate for /var/log/cerberus/*.log..."
cat <<EOF | sudo tee /etc/logrotate.d/cerberus > /dev/null
/var/log/cerberus/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        chattr +i /var/log/cerberus/current.log 2>/dev/null || true
    endscript
}
EOF

# 6. Setup logrotate for audit.log with immutable handling
log "Configuring logrotate for /var/log/audit/audit.log with immutable handling..."
cat <<EOF | sudo tee /etc/logrotate.d/cerberus_audit > /dev/null
/var/log/audit/audit.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0600 root root
    prerotate
        chattr -i /var/log/audit/audit.log 2>/dev/null || true
    endscript
    postrotate
        chattr +i /var/log/audit/audit.log 2>/dev/null || true
    endscript
}
EOF

success "Immutable logs and logrotate configured (with safe handling)." 