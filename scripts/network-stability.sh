#!/usr/bin/env bash
# scripts/network-stability.sh
# Elite APT-Grade Network Stability & Adaptive Firewall Loading
set -euo pipefail

# Set unlimited memlock for eBPF
ulimit -l unlimited 2>/dev/null || true

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EBPF_DIR="$PROJECT_DIR/ebpf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Detect interface type
detect_interface_type() {
    local iface="$1"
    local driver
    
    if ! command -v ethtool >/dev/null; then
        error "ethtool not found - installing..."
        sudo dnf install -y ethtool
    fi
    
    driver=$(ethtool -i "$iface" 2>/dev/null | grep driver | cut -d: -f2 | tr -d ' ')
    
    case "$driver" in
        ath9k_htc|iwlwifi|rtl8xxxu|brcmfmac|mt76*|b43|wl)
            echo "wifi"
            ;;
        e1000e|igb|ixgbe|i40e|mlx4_en|mlx5_core|bnx2x|qede|enic|nfp)
            echo "ethernet"
            ;;
        *)
            warn "Unknown driver '$driver' for interface '$iface' - assuming Wi-Fi"
            echo "wifi"
            ;;
    esac
}

# Check XDP support
check_xdp_support() {
    local iface="$1"
    
    # Check if interface exists
    if ! ip link show "$iface" >/dev/null 2>&1; then
        error "Interface $iface does not exist"
        return 1
    fi
    
    # Check driver XDP support
    if ethtool -S "$iface" 2>/dev/null | grep -q xdp; then
        return 0
    else
        return 1
    fi
}

# Load XDP firewall
load_xdp_firewall() {
    local iface="$1"
    local xdp_obj="$EBPF_DIR/xdp_filter_hardened.o"
    
    log "Loading XDP firewall on $iface"
    
    # Check if XDP object exists
    if [[ ! -f "$xdp_obj" ]]; then
        error "XDP object not found: $xdp_obj"
        return 1
    fi
    
    # Create BPF maps if they don't exist
    if [[ ! -d /sys/fs/bpf/cerberus ]]; then
        log "Creating BPF maps directory"
        sudo mkdir -p /sys/fs/bpf/cerberus
    fi
    
    # Create rate limit map
    if [[ ! -f /sys/fs/bpf/cerberus/rate_limit ]]; then
        log "Creating rate limit map"
        sudo bpftool map create /sys/fs/bpf/cerberus/rate_limit type lru_hash key 4 value 8 entries 10000 name rate_limit
    fi
    
    # Create rules map
    if [[ ! -f /sys/fs/bpf/cerberus/rules ]]; then
        log "Creating rules map"
        sudo bpftool map create /sys/fs/bpf/cerberus/rules type hash key 4 value 1 entries 1024 name rules
    fi
    
    # Load XDP program
    log "Loading XDP program"
    sudo bpftool prog load "$xdp_obj" /sys/fs/bpf/cerberus/xdp_firewall \
        map name rate_limit pinned /sys/fs/bpf/cerberus/rate_limit \
        map name rules pinned /sys/fs/bpf/cerberus/rules
    
    # Attach XDP program
    log "Attaching XDP program to $iface"
    if ! sudo bpftool net attach xdp pinned /sys/fs/bpf/cerberus/xdp_firewall dev "$iface"; then
        warn "XDP attach failed - trying generic mode"
        sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/cerberus/xdp_firewall dev "$iface"
    fi
    
    success "XDP firewall loaded successfully on $iface"
}

# Load TC firewall
load_tc_firewall() {
    local iface="$1"
    local tc_obj="$EBPF_DIR/tc_firewall.o"
    
    log "Loading TC firewall on $iface"
    
    # Check if TC object exists
    if [[ ! -f "$tc_obj" ]]; then
        error "TC object not found: $tc_obj"
        return 1
    fi
    
    # Create BPF maps if they don't exist (same as XDP)
    if [[ ! -d /sys/fs/bpf/cerberus ]]; then
        log "Creating BPF maps directory"
        sudo mkdir -p /sys/fs/bpf/cerberus
    fi
    
    # Create maps (reuse XDP maps)
    if [[ ! -f /sys/fs/bpf/cerberus/rate_limit ]]; then
        log "Creating rate limit map"
        sudo bpftool map create /sys/fs/bpf/cerberus/rate_limit type lru_hash key 4 value 8 entries 10000 name rate_limit
    fi
    
    if [[ ! -f /sys/fs/bpf/cerberus/rules ]]; then
        log "Creating rules map"
        sudo bpftool map create /sys/fs/bpf/cerberus/rules type hash key 4 value 1 entries 1024 name rules
    fi
    
    # Load TC program
    log "Loading TC program"
    sudo bpftool prog load "$tc_obj" /sys/fs/bpf/cerberus/tc_firewall \
        map name rate_limit pinned /sys/fs/bpf/cerberus/rate_limit \
        map name rules pinned /sys/fs/bpf/cerberus/rules
    
    # Create TC qdisc
    log "Creating TC qdisc"
    sudo tc qdisc add dev "$iface" clsact 2>/dev/null || true
    
    # Attach TC program
    log "Attaching TC program to $iface"
    sudo tc filter add dev "$iface" ingress bpf da obj /sys/fs/bpf/cerberus/tc_firewall sec tc
    
    success "TC firewall loaded successfully on $iface"
}

# Unload firewall
unload_firewall() {
    local iface="$1"
    
    log "Unloading firewall from $iface"
    
    # Detach XDP
    sudo bpftool net detach xdp dev "$iface" 2>/dev/null || true
    sudo bpftool net detach xdpgeneric dev "$iface" 2>/dev/null || true
    
    # Detach TC
    sudo tc filter del dev "$iface" ingress 2>/dev/null || true
    sudo tc qdisc del dev "$iface" clsact 2>/dev/null || true
    
    # Remove BPF programs
    sudo rm -f /sys/fs/bpf/cerberus/xdp_firewall 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/cerberus/tc_firewall 2>/dev/null || true
    
    success "Firewall unloaded from $iface"
}

# Adaptive firewall loading
load_firewall_adaptive() {
    local iface="$1"
    local iface_type
    
    log "Starting adaptive firewall loading for $iface"
    
    # Detect interface type
    iface_type=$(detect_interface_type "$iface")
    log "Interface $iface: $iface_type driver detected"
    
    # Unload any existing firewall
    unload_firewall "$iface"
    
    if [[ "$iface_type" == "wifi" ]]; then
        warn "Wi-Fi detected - using TC-BPF fallback"
        load_tc_firewall "$iface"
    else
        log "Ethernet detected - checking XDP support"
        if check_xdp_support "$iface"; then
            log "XDP supported - using XDP"
            load_xdp_firewall "$iface"
        else
            warn "XDP not supported - falling back to TC-BPF"
            load_tc_firewall "$iface"
        fi
    fi
    
    # Verify loading
    if bpftool net show | grep -q "$iface"; then
        success "Firewall successfully loaded on $iface"
        return 0
    else
        error "Firewall loading verification failed"
        return 1
    fi
}

# Main function
main() {
    local iface="${1:-wlp0s20f0u12}"
    local action="${2:-load}"
    
    case "$action" in
        load)
            load_firewall_adaptive "$iface"
            ;;
        unload)
            unload_firewall "$iface"
            ;;
        reload)
            unload_firewall "$iface"
            sleep 1
            load_firewall_adaptive "$iface"
            ;;
        status)
            echo "=== Firewall Status ==="
            bpftool net show
            echo "=== BPF Maps ==="
            ls -la /sys/fs/bpf/cerberus/ 2>/dev/null || echo "No BPF maps found"
            ;;
        *)
            echo "Usage: $0 <interface> [load|unload|reload|status]"
            echo "Default interface: wlp0s20f0u12"
            echo "Default action: load"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@" 