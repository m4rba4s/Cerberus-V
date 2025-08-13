#!/usr/bin/env bash
# Cerberus-V Network Monitor
# Usage: ./scripts/network-monitor.sh [--daemon]

set -euo pipefail

MONITOR_INTERVAL=30
LOG_FILE="/var/log/cerberus/network-monitor.log"
PID_FILE="/var/run/cerberus-network-monitor.pid"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [NETWORK-MONITOR] $1" | tee -a "$LOG_FILE"
}

check_connectivity() {
    # Check internet connectivity
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        return 1
    fi
    
    # Check DNS
    if ! nslookup google.com >/dev/null 2>&1; then
        return 1
    fi
    
    return 0
}

check_ebpf_programs() {
    # Check for stuck eBPF programs
    if sudo bpftool prog list | grep -q "xdp.*attached"; then
        return 1
    fi
    
    return 0
}

check_network_interfaces() {
    # Check if any interface is stuck
    for iface in $(ip link show | awk -F: '/^[0-9]+:/ {print $2}' | tr -d ' ' | grep -v lo); do
        if ! ip link show $iface | grep -q "UP"; then
            return 1
        fi
    done
    
    return 0
}

recover_network() {
    log "Network failure detected - starting recovery..."
    
    # Stop Cerberus services
    sudo systemctl stop cerberus-ctrl cerberus-dataplane || true
    
    # Run panic recovery
    sudo ./scripts/panic.sh
    
    # Wait for recovery
    sleep 10
    
    # Test connectivity
    if check_connectivity; then
        log "Network recovery successful"
        return 0
    else
        log "Network recovery failed"
        return 1
    fi
}

monitor_loop() {
    log "Starting network monitor (interval: ${MONITOR_INTERVAL}s)"
    
    while true; do
        # Check connectivity
        if ! check_connectivity; then
            log "Connectivity check failed"
            recover_network
        fi
        
        # Check eBPF programs
        if ! check_ebpf_programs; then
            log "eBPF programs check failed"
            recover_network
        fi
        
        # Check network interfaces
        if ! check_network_interfaces; then
            log "Network interfaces check failed"
            recover_network
        fi
        
        sleep $MONITOR_INTERVAL
    done
}

# Main execution
case "${1:-}" in
    --daemon)
        # Run as daemon
        if [[ -f "$PID_FILE" ]]; then
            pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                log "Monitor already running (PID: $pid)"
                exit 1
            fi
        fi
        
        echo $$ > "$PID_FILE"
        trap 'rm -f "$PID_FILE"; exit 0' INT TERM EXIT
        
        monitor_loop
        ;;
    --stop)
        # Stop daemon
        if [[ -f "$PID_FILE" ]]; then
            pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid"
                log "Monitor stopped (PID: $pid)"
            else
                log "Monitor not running"
            fi
            rm -f "$PID_FILE"
        else
            log "PID file not found"
        fi
        ;;
    --status)
        # Check status
        if [[ -f "$PID_FILE" ]]; then
            pid=$(cat "$PID_FILE")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Monitor running (PID: $pid)"
            else
                echo "Monitor not running (stale PID file)"
            fi
        else
            echo "Monitor not running"
        fi
        ;;
    *)
        # Run once
        log "Running single network check"
        if ! check_connectivity; then
            log "Network check failed"
            recover_network
        else
            log "Network check passed"
        fi
        ;;
esac 