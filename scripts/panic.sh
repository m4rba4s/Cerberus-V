#!/usr/bin/env bash
# Cerberus-V Emergency Network Recovery
# Usage: sudo ./scripts/panic.sh

set -euo pipefail

echo "🚨 CERBERUS-V EMERGENCY NETWORK RECOVERY"
echo "========================================"

# 1. Stop all Cerberus services
echo "1. Stopping Cerberus services..."
sudo systemctl stop cerberus-ctrl cerberus-dataplane cerberus-maintenance || true
sudo systemctl stop cerberus-vpp || true

# 2. Kill any remaining processes
echo "2. Killing remaining processes..."
sudo pkill -f "cerberus" || true
sudo pkill -f "vpp" || true
sudo pkill -f "af_xdp_loader" || true

# 3. Unload ALL eBPF programs
echo "3. Unloading eBPF programs..."
sudo bpftool prog list | awk '/xdp/ {print $1}' | xargs -I{} sudo bpftool prog unload {} || true
sudo bpftool prog list | awk '/cerberus/ {print $1}' | xargs -I{} sudo bpftool prog unload {} || true

# 4. Delete ALL eBPF maps
echo "4. Deleting eBPF maps..."
sudo bpftool map list | awk '/cerberus/ {print $1}' | xargs -I{} sudo bpftool map delete {} || true
sudo bpftool map list | awk '/blackhole/ {print $1}' | xargs -I{} sudo bpftool map delete {} || true

# 5. Reset network interfaces
echo "5. Resetting network interfaces..."
for iface in $(ip link show | awk -F: '/^[0-9]+:/ {print $2}' | tr -d ' ' | grep -v lo); do
    echo "  Resetting $iface..."
    sudo ip link set $iface down || true
    sudo ip link set $iface up || true
done

# 6. Reset NetworkManager
echo "6. Resetting NetworkManager..."
sudo systemctl restart NetworkManager
sleep 3

# 7. Clear nftables rules (except firewalld)
echo "7. Clearing nftables rules..."
sudo nft list tables | grep -v firewalld | awk '{print $2}' | xargs -I{} sudo nft delete table {} || true

# 8. Clear iptables
echo "8. Clearing iptables..."
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X

# 9. Check network connectivity
echo "9. Testing network connectivity..."
sleep 5
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Network connectivity restored!"
else
    echo "❌ Network still down - attempting additional recovery..."
    
    # Additional recovery steps
    sudo systemctl restart systemd-networkd || true
    sudo systemctl restart wpa_supplicant || true
    
    # Force DHCP renewal
    for iface in $(ip link show | awk -F: '/^[0-9]+:/ {print $2}' | tr -d ' ' | grep -v lo); do
        sudo dhclient -r $iface || true
        sudo dhclient $iface || true
    done
    
    sleep 10
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "✅ Network connectivity restored after additional recovery!"
    else
        echo "❌ Network still down - manual intervention required"
        echo "Consider: sudo systemctl reboot"
    fi
fi

echo "========================================"
echo "🚨 EMERGENCY RECOVERY COMPLETE" 