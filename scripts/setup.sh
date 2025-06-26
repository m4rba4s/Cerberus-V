#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Author: vppebpf  Date: 2024-12-19
# Production-grade setup script for VPP + eBPF firewall

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="/tmp/vppebpf-setup.log"
readonly REQUIRED_KERNEL_VERSION="5.8"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
}

# Error handling
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Setup failed! Check log file: $LOG_FILE"
    fi
    exit $exit_code
}

trap cleanup EXIT

# Utility functions
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "Don't run this script as root!"
        log_info "Use sudo only for specific commands when prompted"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/fedora-release ]]; then
        log_error "This script is designed for Fedora Linux"
        log_info "Detected OS: $(uname -s)"
        exit 1
    fi
    
    local fedora_version
    fedora_version=$(grep -oP 'Fedora release \K\d+' /etc/fedora-release)
    log_info "Detected Fedora $fedora_version"
    
    if [[ $fedora_version -lt 38 ]]; then
        log_warning "Fedora $fedora_version may not have all required packages"
        log_info "Recommended: Fedora 38 or newer"
    fi
}

check_kernel() {
    local kernel_version
    kernel_version=$(uname -r | cut -d'-' -f1)
    log_info "Kernel version: $kernel_version"
    
    if ! version_ge "$kernel_version" "$REQUIRED_KERNEL_VERSION"; then
        log_error "Kernel $kernel_version is too old"
        log_info "Required: $REQUIRED_KERNEL_VERSION or newer"
        log_info "Install newer kernel: sudo dnf update kernel"
        exit 1
    fi
    
    # Check if kernel headers are available
    local kernel_headers="/usr/src/kernels/$(uname -r)"
    if [[ ! -d "$kernel_headers" ]]; then
        log_warning "Kernel headers not found at $kernel_headers"
        log_info "Will install kernel-devel package"
    fi
}

install_system_packages() {
    log_info "🔧 Installing system packages..."
    
    local packages=(
        # Build tools
        "make"
        "clang"
        "llvm"
        "gcc"
        "git"
        
        # eBPF development
        "libbpf-devel"
        "libxdp-devel"
        "bpftool"
        "kernel-devel"
        
        # Python development
        "python3-pip"
        "python3-devel"
        
        # Networking tools
        "iproute"
        "tcpdump"
        "netcat"
        "iputils"
        
        # Development utilities
        "strace"
        "perf"
        "gdb"
    )
    
    # Update package cache
    sudo dnf makecache --refresh
    
    # Install packages
    for package in "${packages[@]}"; do
        if dnf list installed "$package" &>/dev/null; then
            log_info "✓ $package already installed"
        else
            log_info "Installing $package..."
            sudo dnf install -y "$package"
        fi
    done
    
    # Install kernel headers for current kernel
    sudo dnf install -y "kernel-devel-$(uname -r)" || {
        log_warning "Failed to install headers for current kernel"
        log_info "Installing latest kernel-devel instead"
        sudo dnf install -y kernel-devel
    }
}

install_python_packages() {
    log_info "🐍 Installing Python packages..."
    
    # Create virtual environment if it doesn't exist
    local venv_dir="$PROJECT_ROOT/.venv"
    if [[ ! -d "$venv_dir" ]]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv "$venv_dir"
    fi
    
    # Activate virtual environment
    source "$venv_dir/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install required packages
    local python_packages=(
        "scapy>=2.5.0"
        "pyroute2>=0.7.0"
        "pytest>=7.0.0"
        "pytest-timeout>=2.1.0"
    )
    
    for package in "${python_packages[@]}"; do
        log_info "Installing $package..."
        pip install "$package"
    done
    
    log_success "Python environment configured at $venv_dir"
    log_info "To activate: source $venv_dir/bin/activate"
}

verify_tools() {
    log_info "🔍 Verifying development tools..."
    
    local tools=(
        "clang:C compiler for eBPF"
        "bpftool:eBPF program management"
        "ip:Network configuration"
        "make:Build system"
        "python3:Test framework"
    )
    
    for tool_desc in "${tools[@]}"; do
        local tool="${tool_desc%%:*}"
        local desc="${tool_desc#*:}"
        
        if command_exists "$tool"; then
            local version
            case "$tool" in
                clang) version=$(clang --version | head -1) ;;
                bpftool) version=$(bpftool version 2>/dev/null | head -1 || echo "unknown") ;;
                ip) version=$(ip -V 2>&1 | head -1) ;;
                make) version=$(make --version | head -1) ;;
                python3) version=$(python3 --version) ;;
            esac
            log_success "✓ $tool ($desc): $version"
        else
            log_error "✗ $tool not found"
            exit 1
        fi
    done
}

configure_system() {
    log_info "⚙️  Configuring system settings..."
    
    # Increase locked memory limit for eBPF
    local limits_conf="/etc/security/limits.d/99-ebpf.conf"
    if [[ ! -f "$limits_conf" ]]; then
        log_info "Configuring memory limits for eBPF..."
        sudo tee "$limits_conf" >/dev/null <<EOF
# eBPF memory limits
* soft memlock unlimited
* hard memlock unlimited
EOF
        log_success "Memory limits configured"
    fi
    
    # Configure sysctl for networking
    local sysctl_conf="/etc/sysctl.d/99-vppebpf.conf"
    if [[ ! -f "$sysctl_conf" ]]; then
        log_info "Configuring kernel networking parameters..."
        sudo tee "$sysctl_conf" >/dev/null <<EOF
# VPP + eBPF firewall configuration
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 5000
kernel.unprivileged_bpf_disabled = 0
EOF
        sudo sysctl -p "$sysctl_conf"
        log_success "Kernel parameters configured"
    fi
    
    # Ensure bpffs is mounted
    if ! mount | grep -q bpffs; then
        log_info "Mounting BPF filesystem..."
        sudo mount -t bpf bpffs /sys/fs/bpf/
        
        # Add to fstab for persistence
        if ! grep -q bpffs /etc/fstab; then
            echo "bpffs /sys/fs/bpf bpf defaults 0 0" | sudo tee -a /etc/fstab
        fi
        log_success "BPF filesystem mounted"
    fi
}

test_build() {
    log_info "🧪 Testing build system..."
    
    cd "$PROJECT_ROOT"
    
    # Test eBPF compilation
    log_info "Testing eBPF compilation..."
    make -C ebpf clean
    make -C ebpf
    
    if [[ -f "ebpf/xdp_filter.o" ]]; then
        log_success "eBPF program compiled successfully"
    else
        log_error "eBPF compilation failed"
        exit 1
    fi
    
    # Test userspace compilation
    log_info "Testing userspace compilation..."
    make -C userspace clean
    make -C userspace
    
    if [[ -f "userspace/af_xdp_loader" ]]; then
        log_success "Userspace program compiled successfully"
    else
        log_error "Userspace compilation failed"
        exit 1
    fi
    
    # Verify eBPF program
    if command_exists bpftool; then
        log_info "Verifying eBPF program..."
        if bpftool prog load ebpf/xdp_filter.o /sys/fs/bpf/test_prog 2>/dev/null; then
            rm -f /sys/fs/bpf/test_prog
            log_success "eBPF program verification passed"
        else
            log_warning "eBPF program verification failed (this may be normal)"
        fi
    fi
}

create_project_structure() {
    log_info "📁 Creating project structure..."
    
    local dirs=(
        "$PROJECT_ROOT/logs"
        "$PROJECT_ROOT/configs"
        "$PROJECT_ROOT/tests/data"
        "$PROJECT_ROOT/.venv"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        fi
    done
}

print_summary() {
    log_success "🎉 Setup completed successfully!"
    echo
    echo "==============================================="
    echo "         VPP + eBPF Firewall Setup"
    echo "==============================================="
    echo
    echo "📋 What was installed:"
    echo "  • System packages (clang, libbpf, libxdp, etc.)"
    echo "  • Python virtual environment with testing tools"
    echo "  • Kernel configuration for eBPF"
    echo "  • Build system verification"
    echo
    echo "🚀 Next steps:"
    echo "  1. Activate Python environment:"
    echo "     source .venv/bin/activate"
    echo
    echo "  2. Build the project:"
    echo "     make -C ebpf && make -C userspace"
    echo
    echo "  3. Run tests (as root):"
    echo "     sudo python3 ebpf/test_xdp.py"
    echo
    echo "  4. Start the firewall:"
    echo "     sudo userspace/af_xdp_loader -v"
    echo
    echo "📖 Documentation:"
    echo "  • Project: $PROJECT_ROOT"
    echo "  • Logs: $LOG_FILE"
    echo "  • Python env: $PROJECT_ROOT/.venv"
    echo
}

main() {
    log_info "🚀 Starting VPP + eBPF Firewall setup..."
    log_info "Log file: $LOG_FILE"
    
    check_root
    check_os
    check_kernel
    install_system_packages
    install_python_packages
    verify_tools
    configure_system
    create_project_structure
    test_build
    print_summary
}

# Run main function
main "$@" 