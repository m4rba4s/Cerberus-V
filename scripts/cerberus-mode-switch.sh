#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Mode Switch: SIMULATION ↔ LIVE
# Safety-first mode switching with guards and rollback

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
MODE_MAP="/sys/fs/bpf/cerberus_mode"
STATS_MAP="/sys/fs/bpf/cerberus_stats"
LOG_FILE="/var/log/cerberus/mode-switch.log"

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

# Check if unified engine is loaded
check_engine_status() {
    if ! bpftool prog show pinned /sys/fs/bpf/cerberus_unified &>/dev/null; then
        log_error "Cerberus unified engine not loaded. Run deploy_unified_engine.sh first."
        exit 1
    fi
}

# Get current mode
get_current_mode() {
    local mode_value=$(bpftool map lookup pinned "$MODE_MAP" key 0 0 0 0 2>/dev/null | grep -o 'value.*' | awk '{print $2}' || echo "unknown")
    case "$mode_value" in
        "00") echo "SIMULATION" ;;
        "01") echo "LIVE" ;;
        *) echo "UNKNOWN" ;;
    esac
}

# Safety preflight checks
preflight_checks() {
    log "Running preflight safety checks..."
    
    # Check network connectivity
    if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        log_error "Network connectivity test failed. Aborting mode switch."
        exit 1
    fi
    
    # Check system load
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    if (( $(echo "$load_avg > 10.0" | bc -l) )); then
        log_warning "High system load detected: $load_avg"
        read -p "Continue anyway? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Mode switch cancelled by user"
            exit 0
        fi
    fi
    
    # Check available memory
    local mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    if (( mem_available < 100000 )); then  # Less than 100MB
        log_warning "Low memory available: ${mem_available}KB"
    fi
    
    log_success "Preflight checks passed"
}

# Switch to LIVE mode with safety guards
switch_to_live() {
    log "=== SWITCHING TO LIVE MODE ==="
    log_warning "This will enable REAL packet dropping!"
    
    # Double confirmation for LIVE mode
    echo -e "${RED}WARNING: LIVE mode will DROP packets in real-time!${NC}"
    echo "Type 'LIVE' to confirm:"
    read -r confirmation
    
    if [[ "$confirmation" != "LIVE" ]]; then
        log "Live mode activation cancelled"
        exit 0
    fi
    
    # Additional confirmation
    echo "Are you absolutely sure? Type 'YES' to proceed:"
    read -r final_confirmation
    
    if [[ "$final_confirmation" != "YES" ]]; then
        log "Live mode activation cancelled"
        exit 0
    fi
    
    preflight_checks
    
    # Set mode to LIVE (1)
    echo "1" | bpftool map update pinned "$MODE_MAP" key 0 0 0 0 value stdin
    
    log_success "LIVE mode activated"
    log_warning "Cerberus-V is now DROPPING packets in real-time!"
    
    # Monitor for 30 seconds
    log "Monitoring system for 30 seconds..."
    for i in {30..1}; do
        if ! ping -c 1 -W 1 8.8.8.8 &>/dev/null; then
            log_error "Network connectivity lost! Auto-reverting to SIMULATION mode"
            echo "0" | bpftool map update pinned "$MODE_MAP" key 0 0 0 0 value stdin
            log_success "Reverted to SIMULATION mode"
            exit 1
        fi
        echo -ne "\rMonitoring... ${i}s remaining"
        sleep 1
    done
    echo
    
    log_success "LIVE mode monitoring completed - system stable"
}

# Switch to SIMULATION mode
switch_to_simulation() {
    log "=== SWITCHING TO SIMULATION MODE ==="
    
    # Set mode to SIMULATION (0)
    echo "0" | bpftool map update pinned "$MODE_MAP" key 0 0 0 0 value stdin
    
    log_success "SIMULATION mode activated"
    log "Cerberus-V is now in SIMULATION mode (logging only, no dropping)"
}

# Show current status
show_status() {
    echo
    echo "=== CERBERUS-V STATUS ==="
    
    local current_mode=$(get_current_mode)
    case "$current_mode" in
        "SIMULATION")
            echo -e "Mode: ${GREEN}SIMULATION${NC} (Safe - logging only)"
            ;;
        "LIVE")
            echo -e "Mode: ${RED}LIVE${NC} (Active - dropping packets)"
            ;;
        *)
            echo -e "Mode: ${YELLOW}UNKNOWN${NC}"
            ;;
    esac
    
    # Show statistics
    echo
    echo "=== STATISTICS ==="
    if bpftool map dump pinned "$STATS_MAP" &>/dev/null; then
        echo "Packets Total:      $(bpftool map dump pinned "$STATS_MAP" | grep -A1 '"key":.*00.*00.*00.*00' | grep '"value"' | cut -d'"' -f4 | head -1 || echo 0)"
        echo "Packets Dropped:    $(bpftool map dump pinned "$STATS_MAP" | grep -A1 '"key":.*01.*00.*00.*00' | grep '"value"' | cut -d'"' -f4 | head -1 || echo 0)"
        echo "Packets Passed:     $(bpftool map dump pinned "$STATS_MAP" | grep -A1 '"key":.*02.*00.*00.*00' | grep '"value"' | cut -d'"' -f4 | head -1 || echo 0)"
    else
        echo "Statistics not available"
    fi
    
    echo
}

# Show help
show_help() {
    echo "Cerberus-V Mode Switch"
    echo
    echo "Usage: $0 [COMMAND]"
    echo
    echo "Commands:"
    echo "  live        Switch to LIVE mode (real packet dropping)"
    echo "  simulation  Switch to SIMULATION mode (logging only)"
    echo "  status      Show current mode and statistics"
    echo "  help        Show this help message"
    echo
    echo "Safety Features:"
    echo "  - Automatic rollback if network connectivity is lost"
    echo "  - Double confirmation for LIVE mode"
    echo "  - Preflight checks for system stability"
    echo "  - 30-second monitoring period after switching to LIVE"
    echo
}

# Main function
main() {
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    check_engine_status
    
    case "${1:-status}" in
        "live")
            switch_to_live
            ;;
        "simulation")
            switch_to_simulation
            ;;
        "status")
            show_status
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
    
    show_status
}

main "$@"