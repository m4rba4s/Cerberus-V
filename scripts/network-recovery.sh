#!/usr/bin/env bash
# Comprehensive Network Recovery Script
# Handles all types of network failures

set -euo pipefail

echo "🚨 CERBERUS-V NETWORK RECOVERY"
echo "==============================="

# Stop all Cerberus services
echo "1. Stopping Cerberus services..."
sudo systemctl stop cerberus-ctrl.service 2>/dev/null || true
sudo systemctl stop cerberus-dataplane.service 2>/dev/null || true
sudo systemctl stop cerberus-network-health.service 2>/dev/null || true

# Kill any remaining processes
echo "2. Killing remaining processes..."
sudo pkill -f "cerberus" 2>/dev/null || true
sudo pkill -f "af_xdp_loader" 2>/dev/null || true

# Clean up XDP programs
echo "3. Cleaning up XDP programs..."
for iface in $(ip link show | grep -E "^[0-9]+:" | awk -F: '{print $2}' | tr -d ' '); do
    if [[ "$iface" == "lo" ]]; then
        continue
    fi
    sudo ip link set "$iface" xdp off 2>/dev/null || true
done

# Clean up BPF maps
echo "4. Cleaning up BPF maps..."
sudo bpftool map list | grep -E "(cerberus|blackhole|firewall)" | awk '{print $1}' | \
xargs -I{} sudo bpftool map delete {} 2>/dev/null || true

# Reset network interfaces
echo "5. Resetting network interfaces..."
if [[ -f /tmp/cerberus_wireless_interfaces ]]; then
    while read -r iface; do
        echo "   Resetting wireless interface: $iface"
        sudo nmcli device disconnect "$iface" 2>/dev/null || true
        sudo ip link set "$iface" down 2>/dev/null || true
        sudo ip link set "$iface" up 2>/dev/null || true
        sudo nmcli device connect "$iface" 2>/dev/null || true
    done < /tmp/cerberus_wireless_interfaces
fi

# Restart network services
echo "6. Restarting network services..."
sudo systemctl restart NetworkManager
sudo systemctl restart wpa_supplicant 2>/dev/null || true

# Clear firewall rules
echo "7. Clearing firewall rules..."
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo nft flush ruleset 2>/dev/null || true

# Force DHCP renewal
echo "8. Forcing DHCP renewal..."
for iface in $(ip link show | grep -E "^[0-9]+:" | awk -F: '{print $2}' | tr -d ' '); do
    if [[ "$iface" == "lo" ]]; then
        continue
    fi
    sudo dhclient -r "$iface" 2>/dev/null || true
    sudo dhclient "$iface" 2>/dev/null || true
done

# Wait for network
echo "9. Waiting for network..."
sleep 10

# Test connectivity
echo "10. Testing connectivity..."
if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Network recovery successful"
    
    # Restart Cerberus services
    echo "11. Restarting Cerberus services..."
    sudo systemctl start cerberus-network-health.service
    sudo systemctl start cerberus-dataplane.service
    sudo systemctl start cerberus-ctrl.service
    
    echo "✅ Recovery completed successfully"
else
    echo "❌ Network recovery failed"
    echo "   Consider rebooting the system"
    exit 1
fi
