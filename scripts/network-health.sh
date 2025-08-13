#!/usr/bin/env bash
# Network Health Monitor for Cerberus-V
# Monitors connectivity and automatically recovers

set -euo pipefail

LOG_FILE="/var/log/cerberus/network-health.log"
FAILURE_COUNT_FILE="/tmp/cerberus_network_failures"
MAX_FAILURES=3

# Create log directory
sudo mkdir -p /var/log/cerberus
sudo chown outspoken:outspoken /var/log/cerberus

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | sudo tee -a "$LOG_FILE"
}

check_connectivity() {
    # Try multiple methods
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        return 0
    fi
    
    if ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1; then
        return 0
    fi
    
    if curl -s --connect-timeout 5 --max-time 10 https://google.com >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

check_interface_status() {
    local iface="$1"
    
    # Check if interface exists and is up
    if ! ip link show "$iface" >/dev/null 2>&1; then
        return 1
    fi
    
    if ! ip link show "$iface" | grep -q "UP"; then
        return 1
    fi
    
    # For wireless, check if connected
    if iwconfig "$iface" 2>/dev/null | grep -q "IEEE 802.11"; then
        if ! iwconfig "$iface" 2>/dev/null | grep -q "ESSID"; then
            return 1
        fi
    fi
    
    return 0
}

recover_network() {
    log "🔄 Attempting network recovery..."
    
    # Restart NetworkManager
    sudo systemctl restart NetworkManager
    sleep 5
    
    # Reconnect wireless interfaces
    if [[ -f /tmp/cerberus_wireless_interfaces ]]; then
        while read -r iface; do
            log "   Reconnecting wireless interface: $iface"
            sudo nmcli device disconnect "$iface" 2>/dev/null || true
            sleep 2
            sudo nmcli device connect "$iface" 2>/dev/null || true
        done < /tmp/cerberus_wireless_interfaces
    fi
    
    # Wait for connection
    sleep 10
    
    # Check if recovery worked
    if check_connectivity; then
        log "✅ Network recovery successful"
        echo "0" > "$FAILURE_COUNT_FILE"
        return 0
    else
        log "❌ Network recovery failed"
        return 1
    fi
}

# Main monitoring loop
main() {
    log "🔍 Starting network health monitoring..."
    
    # Initialize failure counter
    if [[ ! -f "$FAILURE_COUNT_FILE" ]]; then
        echo "0" > "$FAILURE_COUNT_FILE"
    fi
    
    while true; do
        if check_connectivity; then
            # Reset failure counter on success
            echo "0" > "$FAILURE_COUNT_FILE"
            sleep 30
            continue
        fi
        
        # Increment failure counter
        local failures=$(($(cat "$FAILURE_COUNT_FILE") + 1))
        echo "$failures" > "$FAILURE_COUNT_FILE"
        
        log "❌ Network connectivity lost (failure $failures/$MAX_FAILURES)"
        
        # Check interface status
        if [[ -f /tmp/cerberus_wireless_interfaces ]]; then
            while read -r iface; do
                if ! check_interface_status "$iface"; then
                    log "   Interface $iface is down"
                fi
            done < /tmp/cerberus_wireless_interfaces
        fi
        
        if [[ $failures -ge $MAX_FAILURES ]]; then
            log "🚨 Maximum failures reached, attempting recovery..."
            if recover_network; then
                log "✅ Recovery successful, continuing monitoring"
            else
                log "💀 Recovery failed, consider manual intervention"
                # Wait longer before next attempt
                sleep 60
            fi
        else
            # Wait before next check
            sleep 10
        fi
    done
}

# Run main function
main "$@"
