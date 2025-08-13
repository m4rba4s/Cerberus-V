#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Create systemd drop-ins that provision /var/log/cerberus via LogsDirectory= (fish-safe, no heredocs into sudo)

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi

install -d -m 0750 -o root -g root /var/log/cerberus

install -d -m 0755 /etc/systemd/system/cerberus-ctrl.service.d
install -d -m 0755 /etc/systemd/system/cerberus-dataplane.service.d

cat > /etc/systemd/system/cerberus-ctrl.service.d/paths.conf <<'EOF'
[Service]
LogsDirectory=cerberus
LogsDirectoryMode=0750
EOF

cat > /etc/systemd/system/cerberus-dataplane.service.d/paths.conf <<'EOF'
[Service]
LogsDirectory=cerberus
LogsDirectoryMode=0750
EOF

systemctl daemon-reload
echo "[install-systemd-logsdir] Drop-ins installed. Restart services if needed."


