#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apply systemd hardening for Cerberus-V units and add ExecStartPre preflight

set -euo pipefail

echo "[install-systemd] Applying systemd hardening"

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

# Ensure service user exists
if ! id cerberus >/dev/null 2>&1; then
  useradd -r -s /sbin/nologin -d /var/lib/cerberus -c "Cerberus-V" cerberus
fi

install -d -m 0755 /etc/systemd/system

# Drop-ins for ctrl and dataplane
mkdir -p /etc/systemd/system/cerberus-ctrl.service.d
cat > /etc/systemd/system/cerberus-ctrl.service.d/hardening.conf <<'EOF'
[Service]
User=cerberus
Group=cerberus
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
ReadWritePaths=/var/log/cerberus /sys/fs/bpf /run/cerberus
EOF

mkdir -p /etc/systemd/system/cerberus-dataplane.service.d
cat > /etc/systemd/system/cerberus-dataplane.service.d/hardening.conf <<'EOF'
[Service]
User=cerberus
Group=cerberus
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN
ReadWritePaths=/var/log/cerberus /sys/fs/bpf /run/cerberus /dev/hugepages
ExecStartPre=/home/outspoken/Cerberus-V/scripts/preflight-network.sh
EOF

systemctl daemon-reload
echo "[install-systemd] Done"


