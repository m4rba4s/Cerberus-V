#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Safe preflight for XDP/TC attach to avoid host network loss

set -euo pipefail

iface=${XDP_INTERFACE:-$(ip route | awk '/default/ {print $5; exit}')}
[ -n "${iface:-}" ] || { echo "[preflight] no interface" >&2; exit 1; }

state=$(ip -o link show "$iface" | sed -n 's/.* state \([^ ]*\) .*/\1/p')
if [[ "$state" != "UP" && "$state" != "UNKNOWN" ]]; then
  echo "[preflight] iface $iface not UP (state=$state)" >&2
  exit 1
fi

# Ensure BPF fs
if ! mountpoint -q /sys/fs/bpf; then
  echo "[preflight] mounting /sys/fs/bpf"
  mount -t bpf bpf /sys/fs/bpf
fi

echo "[preflight] OK: iface=$iface, bpf fs ready"

#!/usr/bin/env bash
# Cerberus-V Network Preflight Check
# Usage: ./scripts/preflight-network.sh

set -euo pipefail

echo "🔍 CERBERUS-V NETWORK PREFLIGHT CHECK"
echo "====================================="

# 1. Check if we have network connectivity
echo "1. Checking network connectivity..."
if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Internet connectivity OK"
else
    echo "❌ No internet connectivity detected!"
    echo "   Please check your network connection before starting Cerberus"
    exit 1
fi

# 2. Check for active eBPF programs
echo "2. Checking for existing eBPF programs..."
if sudo bpftool prog list | grep -q "xdp"; then
    echo "⚠️  Found existing XDP programs:"
    sudo bpftool prog list | grep "xdp"
    echo "   Consider running: sudo ./scripts/panic.sh"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ No existing XDP programs found"
fi

# 3. Check for active eBPF maps
echo "3. Checking for existing eBPF maps..."
if sudo bpftool map list | grep -q "cerberus\|blackhole"; then
    echo "⚠️  Found existing Cerberus maps:"
    sudo bpftool map list | grep "cerberus\|blackhole"
    echo "   Consider running: sudo ./scripts/panic.sh"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ No existing Cerberus maps found"
fi

# 4. Check network interfaces
echo "4. Checking network interfaces..."
for iface in $(ip link show | awk -F: '/^[0-9]+:/ {print $2}' | tr -d ' ' | grep -v lo); do
    state=$(ip link show $iface | grep -o "state [A-Z]*" | cut -d' ' -f2)
    echo "   $iface: $state"
    if [[ "$state" == "DOWN" ]]; then
        echo "⚠️  Interface $iface is DOWN"
    fi
done

# 5. Check for conflicting services
echo "5. Checking for conflicting services..."
if systemctl is-active --quiet vpp; then
    echo "⚠️  VPP service is running - may conflict with Cerberus"
fi

if systemctl is-active --quiet firewalld; then
    echo "ℹ️  firewalld is running - will be coordinated with Cerberus"
fi

# 6. Check available memory
echo "6. Checking available memory..."
mem_available=$(free -m | awk '/^Mem:/ {print $7}')
echo "   Available memory: ${mem_available}MB"
if [[ $mem_available -lt 512 ]]; then
    echo "⚠️  Low memory available - Cerberus may not start properly"
fi

# 7. Check hugepages
echo "7. Checking hugepages..."
hugepages_available=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
echo "   Available hugepages: $hugepages_available"
if [[ $hugepages_available -lt 1024 ]]; then
    echo "⚠️  Insufficient hugepages - performance may be degraded"
fi

echo "====================================="
echo "✅ PREFLIGHT CHECK COMPLETE"
echo "   Cerberus can start safely" 