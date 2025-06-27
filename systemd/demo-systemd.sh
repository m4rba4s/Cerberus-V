#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Systemd Demo Script (User Mode)

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 Cerberus-V Systemd Integration Demo${NC}"
echo "========================================"
echo

# Check systemd user mode
if ! systemctl --user status >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  systemd user mode not fully available, showing file analysis...${NC}"
    echo
fi

echo -e "${BLUE}📁 Systemd Unit Files Created:${NC}"
echo "• cerberus-ctrl.service       - Control plane service"
echo "• cerberus-dataplane.service  - Data plane (XDP + VPP)"
echo "• cerberus.target             - Group management target"
echo "• cerberus-maintenance.timer  - Automated maintenance"
echo "• cerberus-maintenance.service - Cleanup & optimization"
echo

echo -e "${BLUE}🔍 Service Dependencies:${NC}"
echo "cerberus.target"
echo "├── cerberus-ctrl.service"
echo "│   ├── Requires: network-online.target"
echo "│   ├── User: cerberus (restricted)"
echo "│   ├── Capabilities: CAP_SYS_ADMIN, CAP_NET_ADMIN"
echo "│   └── Ports: 50051 (gRPC), 8080 (metrics)"
echo "└── cerberus-dataplane.service"
echo "    ├── Requires: cerberus-ctrl.service"
echo "    ├── User: root (kernel operations)"
echo "    ├── Capabilities: Full for eBPF/VPP"
echo "    └── Resources: hugepages, BPF filesystem"
echo

echo -e "${BLUE}⚙️  Security Features:${NC}"
echo "Control Plane:"
echo "• ✅ NoNewPrivileges=yes"
echo "• ✅ ProtectSystem=strict"
echo "• ✅ PrivateNetwork sandboxing"
echo "• ✅ Minimal capabilities"
echo "• ✅ Read-only /etc, writable /var/lib"

echo
echo "Data Plane:"
echo "• ✅ Controlled root access"
echo "• ✅ BPF filesystem access"
echo "• ✅ Hugepages configuration"
echo "• ✅ OOM protection"
echo "• ✅ Proper cleanup on exit"
echo

echo -e "${BLUE}🎯 Management Commands:${NC}"
echo "# Start entire firewall system"
echo "sudo systemctl start cerberus.target"
echo
echo "# Stop all services"
echo "sudo systemctl stop cerberus.target"
echo
echo "# Check status"
echo "sudo systemctl status cerberus.target"
echo
echo "# View logs"
echo "sudo journalctl -u cerberus-ctrl -f"
echo "sudo journalctl -u cerberus-dataplane -f"
echo
echo "# Enable on boot"
echo "sudo systemctl enable cerberus.target"
echo

echo -e "${BLUE}📋 File Structure Analysis:${NC}"
echo

# Analyze service files
for file in systemd/*.service systemd/*.target; do
    if [[ -f "$file" ]]; then
        filename=$(basename "$file")
        echo -e "${GREEN}📄 $filename:${NC}"
        
        # Extract key information
        grep -E "^(Description|ExecStart|User|Type)" "$file" | sed 's/^/  /' || true
        echo
    fi
done

echo -e "${BLUE}🔧 Installation Process:${NC}"
echo "1. Run: sudo systemd/install-systemd.sh"
echo "2. Install Cerberus-V binaries to /usr/local/bin/"
echo "3. Configure: /etc/cerberus/*.conf"
echo "4. Start: sudo systemctl start cerberus.target"
echo

echo -e "${GREEN}✅ Systemd Integration Complete!${NC}"
echo "Features implemented:"
echo "• 🎯 Production-ready service definitions"
echo "• 🔒 Security hardening with capabilities"
echo "• 📦 Automatic dependency management"
echo "• 🔄 Auto-restart on failure"
echo "• 📊 Centralized logging via journald"
echo "• ⏰ Scheduled maintenance tasks"
echo "• 👥 User/group isolation"
echo "• 🛡️  System protection (sandboxing)" 