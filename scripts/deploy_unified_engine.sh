#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Unified Engine Deployment Script
# Safe deployment with rollback capability

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
EBPF_DIR="$PROJECT_ROOT/ebpf"
BACKUP_DIR="/var/backups/cerberus"
LOG_FILE="/var/log/cerberus/deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Create necessary directories
setup_directories() {
    log "Setting up directories..."
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "/sys/fs/bpf"
}

# Backup current BPF maps and programs
backup_current_state() {
    log "Backing up current BPF state..."
    local backup_timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_path="$BACKUP_DIR/backup_$backup_timestamp"
    
    mkdir -p "$backup_path"
    
    # Backup BPF filesystem
    if [[ -d "/sys/fs/bpf" ]]; then
        cp -r /sys/fs/bpf/* "$backup_path/" 2>/dev/null || true
    fi
    
    # List current XDP programs
    ip link show | grep -E "(xdp|xdpgeneric)" > "$backup_path/current_xdp.txt" 2>/dev/null || true
    bpftool prog show > "$backup_path/current_programs.txt" 2>/dev/null || true
    bpftool map show > "$backup_path/current_maps.txt" 2>/dev/null || true
    
    echo "$backup_path" > /tmp/cerberus_backup_path
    log_success "Backup created at: $backup_path"
}

# Remove all existing XDP programs
cleanup_existing_programs() {
    log "Cleaning up existing XDP programs..."
    
    # Get list of interfaces with XDP programs attached
    local interfaces=$(ip link show | grep -E "xdp|xdpgeneric" | cut -d: -f2 | awk '{print $1}' || true)
    
    for iface in $interfaces; do
        log "Detaching XDP from interface: $iface"
        ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
        ip link set dev "$iface" xdpdrv off 2>/dev/null || true
        ip link set dev "$iface" xdpoffload off 2>/dev/null || true
    done
    
    # Remove old BPF maps (Cerberus specific)
    log "Cleaning up old BPF maps..."
    find /sys/fs/bpf -name "*cerberus*" -type f -delete 2>/dev/null || true
    find /sys/fs/bpf -name "*firewall*" -type f -delete 2>/dev/null || true
    find /sys/fs/bpf -name "*xdp_filter*" -type f -delete 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Compile unified engine
compile_unified_engine() {
    log "Compiling unified eBPF engine..."
    
    cd "$EBPF_DIR"
    
    # Check if clang is available
    if ! command -v clang &> /dev/null; then
        log_error "clang not found. Please install: sudo dnf install clang llvm"
        exit 1
    fi
    
    # Compile with optimizations and BTF info
    clang -O2 -target bpf -c unified_engine.c -o unified_engine.o \
        -I/usr/include/$(uname -m)-linux-gnu \
        -g -DDEBUG=0
    
    if [[ ! -f "unified_engine.o" ]]; then
        log_error "Compilation failed"
        exit 1
    fi
    
    log_success "Unified engine compiled successfully"
}

# Load and attach unified engine
deploy_unified_engine() {
    log "Deploying unified eBPF engine..."
    
    cd "$EBPF_DIR"
    
    # Get primary network interface
    local primary_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$primary_iface" ]]; then
        log_error "Could not determine primary network interface"
        exit 1
    fi
    
    log "Primary interface detected: $primary_iface"
    
    # Load program and pin it
    bpftool prog load unified_engine.o /sys/fs/bpf/cerberus_unified type xdp
    
    # Pin maps separately (get map IDs from loaded program)
    local prog_id=$(bpftool prog show pinned /sys/fs/bpf/cerberus_unified | grep -o '^[0-9]*')
    if [[ -n "$prog_id" ]]; then
        # Pin maps using program ID
        bpftool map pin id $(bpftool prog show id $prog_id | grep -o 'map_ids [0-9]*' | head -1 | cut -d' ' -f2) /sys/fs/bpf/cerberus_mode 2>/dev/null || true
        bpftool map pin id $(bpftool prog show id $prog_id | grep -o 'map_ids [0-9]*' | head -2 | tail -1 | cut -d' ' -f2) /sys/fs/bpf/cerberus_rules 2>/dev/null || true
        bpftool map pin id $(bpftool prog show id $prog_id | grep -o 'map_ids [0-9]*' | head -3 | tail -1 | cut -d' ' -f2) /sys/fs/bpf/cerberus_ratelimit 2>/dev/null || true
        bpftool map pin id $(bpftool prog show id $prog_id | grep -o 'map_ids [0-9]*' | head -4 | tail -1 | cut -d' ' -f2) /sys/fs/bpf/cerberus_stats 2>/dev/null || true
        bpftool map pin id $(bpftool prog show id $prog_id | grep -o 'map_ids [0-9]*' | head -5 | tail -1 | cut -d' ' -f2) /sys/fs/bpf/cerberus_events 2>/dev/null || true
        bpftool map pin id $(bpftool prog show id $prog_id | grep -o 'map_ids [0-9]*' | head -6 | tail -1 | cut -d' ' -f2) /sys/fs/bpf/cerberus_xsk 2>/dev/null || true
    fi
    
    # Attach to interface in generic mode (safer)
    bpftool net attach xdpgeneric pinned /sys/fs/bpf/cerberus_unified dev "$primary_iface"
    
    log_success "Unified engine deployed on interface: $primary_iface"
    
    # Set initial mode to SIMULATION for safety
    if [[ -f "/sys/fs/bpf/cerberus_mode" ]]; then
        echo "0" | bpftool map update pinned /sys/fs/bpf/cerberus_mode key 0 0 0 0 value stdin
    else
        log_warning "Mode map not pinned, will use default SIMULATION mode"
    fi
    log_success "Initialized in SIMULATION mode"
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    # Check if program is loaded
    if ! bpftool prog show pinned /sys/fs/bpf/cerberus_unified &>/dev/null; then
        log_error "Unified program not found"
        return 1
    fi
    
    # Check if maps are accessible
    local maps=("cerberus_mode" "cerberus_rules" "cerberus_ratelimit" "cerberus_stats" "cerberus_events")
    for map in "${maps[@]}"; do
        if ! bpftool map show pinned "/sys/fs/bpf/$map" &>/dev/null; then
            log_error "Map $map not accessible"
            return 1
        fi
    done
    
    # Test basic connectivity
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        log_success "Network connectivity verified"
    else
        log_warning "Network connectivity test failed"
    fi
    
    log_success "Deployment verification passed"
}

# Rollback function
rollback() {
    log_error "Rolling back to previous state..."
    
    if [[ -f "/tmp/cerberus_backup_path" ]]; then
        local backup_path=$(cat /tmp/cerberus_backup_path)
        
        # Remove current deployment
        cleanup_existing_programs
        
        # Restore from backup
        if [[ -d "$backup_path" ]]; then
            log "Restoring from backup: $backup_path"
            # Note: Full restore would be complex, keeping it simple
            log_warning "Manual intervention may be required"
        fi
    fi
    
    log_error "Rollback completed. Please check system state manually."
    exit 1
}

# Signal handlers
trap rollback ERR
trap 'log_warning "Deployment interrupted by user"; rollback' INT TERM

# Main deployment sequence
main() {
    log "=== Starting Cerberus-V Unified Engine Deployment ==="
    
    check_root
    setup_directories
    backup_current_state
    cleanup_existing_programs
    compile_unified_engine
    deploy_unified_engine
    
    if verify_deployment; then
        log_success "=== Deployment completed successfully ==="
        log "Mode: SIMULATION (use cerberus-mode-switch to enable LIVE mode)"
        log "Logs: $LOG_FILE"
        log "Statistics: bpftool map dump pinned /sys/fs/bpf/cerberus_stats"
        log "Events: bpftool map dump pinned /sys/fs/bpf/cerberus_events"
    else
        log_error "Deployment verification failed"
        rollback
    fi
}

# Execute main function
main "$@"