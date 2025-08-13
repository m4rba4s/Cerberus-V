#!/usr/bin/env bash
# Cerberus-V Hugepages Setup Script
# Usage: sudo ./scripts/setup-hugepages.sh

set -euo pipefail

echo "🔧 CERBERUS-V HUGEPAGES SETUP"
echo "=============================="

# 1. Set hugepages
echo "1. Setting hugepages..."
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# 2. Create sysctl config
echo "2. Creating sysctl configuration..."
sudo tee /etc/sysctl.d/99-cerberus-hugepages.conf > /dev/null <<EOF
# Cerberus-V Hugepages Configuration
# 1024 x 2MB hugepages = 2GB total
vm.nr_hugepages = 1024
vm.nr_hugepages_mempolicy = 1024

# Hugepage mount point
vm.hugetlb_shm_group = 1000

# Transparent hugepages (optional)
vm.transparent_hugepage.enabled = always
vm.transparent_hugepage.defrag = defer
EOF

# 3. Apply sysctl
echo "3. Applying sysctl configuration..."
sudo sysctl -p /etc/sysctl.d/99-cerberus-hugepages.conf

# 4. Verify setup
echo "4. Verifying hugepages setup..."
echo "   Available hugepages: $(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
echo "   Free hugepages: $(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages)"
echo "   Total memory: $(($(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages) * 2048))MB"

echo "=============================="
echo "✅ HUGEPAGES SETUP COMPLETE" 