#!/usr/bin/env bash
# Adaptive XDP Loader for Cerberus-V
# Only loads XDP on supported interfaces

set -euo pipefail

XDP_PROGRAM="ebpf/xdp_filter.o"

# Check if program exists
if [[ ! -f "$XDP_PROGRAM" ]]; then
    echo "❌ XDP program not found: $XDP_PROGRAM"
    exit 1
fi

# Load XDP only on ethernet interfaces
if [[ -f /tmp/cerberus_ethernet_interfaces ]]; then
    while read -r iface; do
        echo "🔧 Loading XDP on ethernet interface: $iface"
        
        # Check if interface is up
        if ! ip link show "$iface" | grep -q "UP"; then
            echo "⚠️  Interface $iface is down, skipping"
            continue
        fi
        
        # Load XDP program
        if sudo ip link set "$iface" xdp obj "$XDP_PROGRAM" sec xdp; then
            echo "✅ XDP loaded on $iface"
        else
            echo "❌ Failed to load XDP on $iface"
        fi
    done < /tmp/cerberus_ethernet_interfaces
else
    echo "⚠️  No ethernet interfaces found for XDP"
fi

# For wireless interfaces, use TC instead
if [[ -f /tmp/cerberus_wireless_interfaces ]]; then
    echo "📡 Wireless interfaces detected - using TC filters instead of XDP"
    
    # Compile TC program if needed
    TC_PROGRAM="ebpf/tc_firewall.o"
    if [[ ! -f "$TC_PROGRAM" ]]; then
        echo "🔧 Compiling TC firewall program..."
        cd ebpf
        make tc_firewall.o || {
            echo "❌ Failed to compile TC program"
            exit 1
        }
        cd ..
    fi
    
    while read -r iface; do
        echo "🔧 Setting up TC filters on wireless interface: $iface"
        
        # Add TC qdisc
        sudo tc qdisc add dev "$iface" clsact 2>/dev/null || true
        
        # Load TC ingress filter
        if sudo tc filter add dev "$iface" ingress bpf da obj "$TC_PROGRAM" sec tc; then
            echo "✅ TC ingress filter loaded on $iface"
        else
            echo "❌ Failed to load TC ingress filter on $iface"
        fi
        
        # Load TC egress filter
        if sudo tc filter add dev "$iface" egress bpf da obj "$TC_PROGRAM" sec tc; then
            echo "✅ TC egress filter loaded on $iface"
        else
            echo "❌ Failed to load TC egress filter on $iface"
        fi
    done < /tmp/cerberus_wireless_interfaces
fi

echo "✅ Adaptive XDP loading completed"
