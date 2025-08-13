#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Log-Apocalypse Recovery Script for Cerberus-V
# APT-Grade System Recovery and Hardening

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[LOG-APOCALYPSE]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root for system recovery"
        exit 1
    fi
}

# 1.1 Immutable /var/log recovery
recover_logs() {
    log "Recovering from log-apocalypse..."
    
    # Remount /var/log as read-only if possible
    if mountpoint -q /var/log; then
        log "Remounting /var/log as read-only..."
        mount -o remount,ro /var/log || warning "Could not remount /var/log as read-only"
    fi
    
    # Make audit log immutable
    if [[ -f /var/log/audit/audit.log ]]; then
        log "Making audit log immutable..."
        chattr +i /var/log/audit/audit.log || warning "Could not make audit log immutable"
    fi
    
    # Create Cerberus-V log directory with proper permissions
    mkdir -p /var/log/cerberus
    chown root:root /var/log/cerberus
    chmod 750 /var/log/cerberus
    
    success "Log recovery completed"
}

# 1.2 Nuke stale BPF maps
cleanup_bpf_maps() {
    log "Cleaning up stale BPF maps..."
    
    # Find and remove Cerberus-V BPF maps
    if command -v bpftool >/dev/null; then
        bpftool map show | awk '/cerberus/ {print $1}' | while read -r map_id; do
            if [[ -n "$map_id" ]]; then
                log "Removing stale BPF map: $map_id"
                bpftool map pin "$map_id" /sys/fs/bpf/cerberus_reset_$map_id 2>/dev/null || true
            fi
        done
    fi
    
    # Clean up any pinned maps
    rm -f /sys/fs/bpf/cerberus_* 2>/dev/null || true
    
    success "BPF maps cleanup completed"
}

# 1.3 Reclaim hugepages
reclaim_hugepages() {
    log "Reclaiming hugepages..."
    
    # Reset hugepages
    echo 0 | tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages >/dev/null 2>&1 || true
    
    # Reallocate hugepages for VPP
    echo 2048 | tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages >/dev/null 2>&1 || warning "Could not allocate hugepages"
    
    success "Hugepages reclaimed"
}

# 2.1 Setup tamper-proof logging
setup_tamper_proof_logging() {
    log "Setting up tamper-proof logging..."
    
    # Create logrotate configuration for Cerberus-V
    cat > /etc/logrotate.d/cerberus << 'EOF'
/var/log/cerberus/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        chattr +i /var/log/cerberus/current.log 2>/dev/null || true
        systemctl reload cerberus-ctrl 2>/dev/null || true
    endscript
}
EOF
    
    # Create current log file and make it immutable
    touch /var/log/cerberus/current.log
    chattr +i /var/log/cerberus/current.log 2>/dev/null || warning "Could not make current log immutable"
    
    success "Tamper-proof logging configured"
}

# 2.2 Setup systemd security hardening
setup_systemd_security() {
    log "Setting up systemd security hardening..."
    
    # Create systemd drop-in for Cerberus-V services
    mkdir -p /etc/systemd/system/cerberus-ctrl.service.d
    cat > /etc/systemd/system/cerberus-ctrl.service.d/security.conf << 'EOF'
[Service]
# Security hardening
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/cerberus /sys/fs/bpf /run/vpp
SystemCallFilter=@system-service
SystemCallArchitectures=native
LockPersonality=true
RestrictNamespaces=uts ipc pid net
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    success "Systemd security hardening configured"
}

# 2.3 Setup emergency wipe capability
setup_emergency_wipe() {
    log "Setting up emergency wipe capability..."
    
    # Create panic script
    cat > /usr/local/bin/cerberus-panic.sh << 'EOF'
#!/bin/bash
# Emergency wipe script for Cerberus-V
# WARNING: This will destroy all data and reboot the system

echo "🚨 CERBERUS-V EMERGENCY WIPE INITIATED 🚨"
echo "This will destroy all data and reboot in 10 seconds..."
echo "Press Ctrl+C to abort"

sleep 10

# Wipe BPF maps
bpftool map show | awk '/cerberus/ {system("bpftool map delete "$1)}' 2>/dev/null || true

# Stop services
systemctl stop cerberus-ctrl 2>/dev/null || true
systemctl stop cerberus-vpp 2>/dev/null || true

# Wipe VPP data
shred -n 3 -z /var/lib/vpp/* 2>/dev/null || true

# Wipe logs
shred -n 3 -z /var/log/cerberus/* 2>/dev/null || true

# Reboot
reboot -f
EOF
    
    chmod +x /usr/local/bin/cerberus-panic.sh
    
    success "Emergency wipe capability configured"
}

# Main recovery function
main() {
    log "Starting Cerberus-V log-apocalypse recovery..."
    log "System: $(uname -a)"
    log "Date: $(date)"
    
    check_root
    
    # Phase 1: Immediate recovery
    recover_logs
    cleanup_bpf_maps
    reclaim_hugepages
    
    # Phase 2: Security hardening
    setup_tamper_proof_logging
    setup_systemd_security
    setup_emergency_wipe
    
    log "Recovery completed successfully!"
    log "Next steps:"
    log "1. Run: make verify"
    log "2. Test: cerberus-panic.sh (in emergency)"
    log "3. Monitor: /var/log/cerberus/current.log"
    
    success "Log-apocalypse recovery completed - system hardened"
}

# Run main function
main "$@" 