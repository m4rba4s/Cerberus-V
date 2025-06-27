#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Systemd Installation Script

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check if systemd is available
if ! command -v systemctl >/dev/null 2>&1; then
    log_error "systemd is not available on this system"
    exit 1
fi

log_info "🚀 Installing Cerberus-V systemd units..."

# Create cerberus user if it doesn't exist
if ! id "cerberus" >/dev/null 2>&1; then
    log_info "👤 Creating cerberus user..."
    useradd -r -s /bin/false -d /var/lib/cerberus -c "Cerberus-V Firewall" cerberus
    log_success "User cerberus created"
else
    log_info "User cerberus already exists"
fi

# Install systemd units
log_info "📁 Installing systemd unit files..."

# Copy service files
cp cerberus-ctrl.service /etc/systemd/system/
cp cerberus-dataplane.service /etc/systemd/system/
cp cerberus.target /etc/systemd/system/
cp cerberus-maintenance.service /etc/systemd/system/
cp cerberus-maintenance.timer /etc/systemd/system/

log_success "Systemd units installed"

# Install scripts
log_info "📜 Installing system scripts..."
mkdir -p /usr/local/bin

# Copy and make executable
cp scripts/cerberus-prestart /usr/local/bin/
chmod +x /usr/local/bin/cerberus-prestart

# Create placeholder scripts for data plane
cat > /usr/local/bin/cerberus-dataplane << 'EOF'
#!/bin/bash
# Cerberus-V Data Plane Launcher
# This will be replaced by the actual data plane binary
echo "Starting Cerberus-V Data Plane..."
exec /opt/cerberus/bin/dataplane "$@"
EOF

cat > /usr/local/bin/cerberus-maintenance << 'EOF'
#!/bin/bash
# Cerberus-V Maintenance Script
echo "Running Cerberus-V maintenance..."
# Log rotation
journalctl --vacuum-time=30d --identifier=cerberus-ctrl
journalctl --vacuum-time=30d --identifier=cerberus-dataplane
# Cleanup old BPF maps
find /sys/fs/bpf -name "cerberus_*" -mtime +7 -delete 2>/dev/null || true
echo "Maintenance completed"
EOF

chmod +x /usr/local/bin/cerberus-*

log_success "Scripts installed"

# Create directories
log_info "📂 Creating system directories..."
mkdir -p /etc/cerberus
mkdir -p /var/lib/cerberus
mkdir -p /var/log/cerberus
mkdir -p /run/cerberus

# Set permissions
chown cerberus:cerberus /var/lib/cerberus
chown cerberus:cerberus /var/log/cerberus
chown cerberus:cerberus /run/cerberus

log_success "Directories created"

# Create basic configuration files
log_info "⚙️  Creating configuration files..."

cat > /etc/cerberus/ctrl.conf << EOF
# Cerberus-V Control Plane Configuration
grpc_port=50051
metrics_port=8080
log_level=info
bpf_maps_dir=/sys/fs/bpf
EOF

cat > /etc/cerberus/dataplane.conf << EOF
# Cerberus-V Data Plane Configuration
interface=eth0
xdp_mode=native
vpp_config=/etc/cerberus/vpp.conf
hugepages=1024
EOF

chown cerberus:cerberus /etc/cerberus/*.conf

log_success "Configuration files created"

# Reload systemd
log_info "🔄 Reloading systemd daemon..."
systemctl daemon-reload

log_success "Systemd daemon reloaded"

# Enable services (but don't start yet)
log_info "🔧 Enabling Cerberus-V services..."
systemctl enable cerberus.target
systemctl enable cerberus-ctrl.service
systemctl enable cerberus-dataplane.service
systemctl enable cerberus-maintenance.timer

log_success "Services enabled"

# Show status
log_info "📊 Installation summary:"
echo
echo "✅ Systemd Units Installed:"
echo "   • cerberus-ctrl.service"
echo "   • cerberus-dataplane.service"
echo "   • cerberus.target"
echo "   • cerberus-maintenance.timer"
echo
echo "✅ User & Directories:"
echo "   • User: cerberus"
echo "   • Config: /etc/cerberus/"
echo "   • Data: /var/lib/cerberus/"
echo "   • Logs: /var/log/cerberus/"
echo
echo "🎯 Quick Commands:"
echo "   Start:   systemctl start cerberus.target"
echo "   Stop:    systemctl stop cerberus.target"
echo "   Status:  systemctl status cerberus.target"
echo "   Logs:    journalctl -u cerberus-ctrl -f"
echo
echo "⚠️  Note: Install actual Cerberus-V binaries before starting services"

log_success "🎉 Installation completed successfully!" 