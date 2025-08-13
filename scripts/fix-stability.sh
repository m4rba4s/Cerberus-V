#!/bin/bash
# Cerberus-V Stability Fix Script
# Fixes common Fedora + eBPF + WebSocket issues

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}❌ ERROR:${NC} $1"
}

success() {
    echo -e "${GREEN}✅ SUCCESS:${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠️  WARNING:${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root (sudo)"
    exit 1
fi

log "🔧 Starting Cerberus-V Stability Fix..."

# 1. Fix Firewall Rules
log "1. Configuring firewall rules..."
firewall-cmd --add-port=8000/tcp --permanent
firewall-cmd --add-port=3000/tcp --permanent
firewall-cmd --add-port=8008/tcp --permanent
firewall-cmd --reload
success "Firewall rules configured"

# 2. Temporarily disable SELinux (if needed)
log "2. Checking SELinux status..."
if getenforce | grep -q "Enforcing"; then
    warning "SELinux is enforcing. Temporarily setting to permissive..."
    setenforce 0
    success "SELinux set to permissive"
else
    success "SELinux already permissive or disabled"
fi

# 3. Install required packages
log "3. Installing required packages..."
dnf install -y bpftool kernel-devel kernel-headers python3-pip curl jq bc

# 4. Set up eBPF capabilities
log "4. Setting up eBPF capabilities..."
if command -v bpftool >/dev/null 2>&1; then
    setcap cap_net_admin,cap_net_raw=eip $(which bpftool) 2>/dev/null || true
    success "eBPF capabilities configured"
else
    warning "bpftool not found, skipping capabilities"
fi

# 5. Create log directory
log "5. Setting up logging..."
mkdir -p /var/log/cerberus
chown outspoken:outspoken /var/log/cerberus
chmod 755 /var/log/cerberus
success "Log directory created"

# 6. Make scripts executable
log "6. Making scripts executable..."
chmod +x /home/outspoken/Cerberus-V/scripts/system-monitor.sh
chmod +x /home/outspoken/Cerberus-V/scripts/fix-stability.sh
success "Scripts made executable"

# 7. Install systemd service
log "7. Installing systemd service..."
cp /home/outspoken/Cerberus-V/systemd/cerberus-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable cerberus-monitor.service
success "Systemd service installed"

# 8. Configure system limits
log "8. Configuring system limits..."
cat >> /etc/security/limits.conf << EOF
# Cerberus-V limits
outspoken soft nofile 65536
outspoken hard nofile 65536
outspoken soft nproc 4096
outspoken hard nproc 4096
EOF
success "System limits configured"

# 9. Configure kernel parameters
log "9. Configuring kernel parameters..."
cat >> /etc/sysctl.conf << EOF
# Cerberus-V kernel tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl -p
success "Kernel parameters configured"

# 10. Create health check script
log "10. Creating health check script..."
cat > /home/outspoken/Cerberus-V/scripts/health-check.sh << 'EOF'
#!/bin/bash
# Quick health check for Cerberus-V

BACKEND_URL="http://localhost:8000/api/health"
FRONTEND_URL="http://localhost:3000"

echo "🔍 Cerberus-V Health Check"
echo "=========================="

# Check backend
if curl -s --max-time 5 "$BACKEND_URL" > /dev/null; then
    echo "✅ Backend: HEALTHY"
else
    echo "❌ Backend: UNHEALTHY"
fi

# Check frontend
if curl -s --max-time 5 "$FRONTEND_URL" > /dev/null; then
    echo "✅ Frontend: HEALTHY"
else
    echo "❌ Frontend: UNHEALTHY"
fi

# Check eBPF
if command -v bpftool >/dev/null 2>&1; then
    PROGRAMS=$(bpftool prog list 2>/dev/null | wc -l)
    echo "📊 eBPF Programs: $PROGRAMS"
else
    echo "⚠️  bpftool not available"
fi

# Check system resources
CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
MEM=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
echo "💻 CPU Usage: ${CPU}%"
echo "🧠 Memory Usage: ${MEM}%"
EOF

chmod +x /home/outspoken/Cerberus-V/scripts/health-check.sh
success "Health check script created"

# 11. Start monitoring service
log "11. Starting monitoring service..."
systemctl start cerberus-monitor.service
success "Monitoring service started"

# 12. Final status check
log "12. Performing final status check..."
sleep 3
/home/outspoken/Cerberus-V/scripts/health-check.sh

echo ""
log "🎯 Stability fixes completed!"
echo ""
echo "📋 Next steps:"
echo "1. Open browser: http://localhost:3000"
echo "2. Check logs: journalctl -u cerberus-monitor -f"
echo "3. Health check: ./scripts/health-check.sh"
echo "4. Monitor: systemctl status cerberus-monitor"
echo ""
echo "🔧 If issues persist:"
echo "- Check SELinux: getenforce"
echo "- Check firewall: firewall-cmd --list-all"
echo "- Check logs: tail -f /var/log/cerberus-monitor.log"
echo ""
success "Cerberus-V is ready for Elite-Mode operation!" 