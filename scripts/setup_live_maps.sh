#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V LIVE Mode BPF Maps Setup
# Elite-Mode APT-Grade Map Initialization

set -euo pipefail

echo "🔧 CERBERUS-V LIVE MODE BPF MAPS SETUP"
echo "======================================"

# Create BPF filesystem if not exists
if [[ ! -d /sys/fs/bpf ]]; then
    echo "📁 Creating BPF filesystem..."
    sudo mount -t bpf bpf /sys/fs/bpf
fi

# Create Cerberus directory
sudo mkdir -p /sys/fs/bpf/cerberus

echo "🗺️ Creating LIVE mode BPF maps..."

# 1. Live state map (array, 1 entry)
echo "   Creating live_state_map..."
sudo bpftool map create /sys/fs/bpf/cerberus/live_state_map \
    type array \
    key 4 \
    value 32 \
    entries 1 \
    name live_state_map

# 2. Live shadow map (array of maps, 2 entries)
echo "   Creating live_shadow..."
# Create a simple hash map instead of array_of_maps for now
sudo bpftool map create /sys/fs/bpf/cerberus/live_shadow \
    type hash \
    key 4 \
    value 4 \
    entries 2 \
    name live_shadow

# 3. Live drops histogram (per-cpu array, 256 entries)
echo "   Creating live_drops..."
sudo bpftool map create /sys/fs/bpf/cerberus/live_drops \
    type percpu_array \
    key 4 \
    value 8 \
    entries 256 \
    name live_drops

# 4. Rate limiter (LRU hash, 10000 entries)
echo "   Creating rate_limiter..."
sudo bpftool map create /sys/fs/bpf/cerberus/rate_limiter \
    type lru_hash \
    key 4 \
    value 8 \
    entries 10000 \
    name rate_limiter

# Initialize live state with simulation mode
echo "🔧 Initializing live state..."
INIT_STATE="01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
sudo bpftool map update pinned /sys/fs/bpf/cerberus/live_state_map \
    key 00 00 00 00 \
    value $INIT_STATE

echo "✅ LIVE mode BPF maps created successfully"
echo "======================================"
echo "📊 Map Summary:"
echo "   live_state_map: /sys/fs/bpf/cerberus/live_state_map"
echo "   live_shadow: /sys/fs/bpf/cerberus/live_shadow"
echo "   live_drops: /sys/fs/bpf/cerberus/live_drops"
echo "   rate_limiter: /sys/fs/bpf/cerberus/rate_limiter"
echo "======================================" 