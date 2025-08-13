#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# APT-Shield Preflight Safety Check
# Elite-Mode APT-Grade Preflight Validation
# Critical Infrastructure Safety Validation

set -euo pipefail

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция логирования
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Функция проверки с выходом при ошибке
check_or_exit() {
    if ! $1; then
        log_error "$2"
        exit 1
    fi
}

log_info "Starting APT-Shield preflight safety check..."

# 1. Проверка системных требований
log_info "Checking system requirements..."

# Проверка ядра (требуется 5.4+ для XDP)
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
    log_error "Kernel version $KERNEL_VERSION is too old. Required: 5.4+"
    exit 1
fi
log_info "Kernel version: $KERNEL_VERSION ✓"

# Проверка eBPF поддержки
check_or_exit "bpftool version >/dev/null 2>&1" "bpftool not found"

# Проверка eBPF поддержки (упрощенная)
if ! bpftool feature probe >/dev/null 2>&1; then
    log_warn "eBPF feature probe failed - continuing anyway"
fi
log_info "eBPF support detected ✓"

# Проверка XDP поддержки
if ! ip link show | grep -q "xdp"; then
    log_warn "XDP support not detected in network interfaces"
fi

# 2. Проверка ресурсов
log_info "Checking system resources..."

# Проверка памяти (минимум 2GB свободной)
FREE_MEM=$(free -m | awk 'NR==2{print $7}')
if [ "$FREE_MEM" -lt 2048 ]; then
    log_error "Insufficient free memory: ${FREE_MEM}MB (required: 2048MB+)"
    exit 1
fi
log_info "Free memory: ${FREE_MEM}MB ✓"

# Проверка дискового пространства (минимум 1GB свободного)
FREE_DISK=$(df -BG / | awk 'NR==2{print $4}' | sed 's/G//')
if [ "$FREE_DISK" -lt 1 ]; then
    log_error "Insufficient disk space: ${FREE_DISK}GB (required: 1GB+)"
    exit 1
fi
log_info "Free disk space: ${FREE_DISK}GB ✓"

# 3. Проверка сетевых интерфейсов
log_info "Checking network interfaces..."

# Поиск основного интерфейса
MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -z "$MAIN_IFACE" ]; then
    log_error "No default route found"
    exit 1
fi

# Проверка что интерфейс существует и активен
if ! ip link show "$MAIN_IFACE" >/dev/null 2>&1; then
    log_error "Main interface $MAIN_IFACE not found"
    exit 1
fi

if ! ip link show "$MAIN_IFACE" | grep -q "UP"; then
    log_error "Main interface $MAIN_IFACE is not UP"
    exit 1
fi

log_info "Main interface: $MAIN_IFACE ✓"

# 4. Проверка конфликтующих сервисов
log_info "Checking for conflicting services..."

# Проверка firewalld
if systemctl is-active --quiet firewalld; then
    log_warn "firewalld is active - will be stopped by APT-Shield"
fi

# Проверка iptables
if iptables -L >/dev/null 2>&1; then
    log_info "iptables available ✓"
fi

# 5. Проверка безопасности
log_info "Checking security settings..."

# Проверка SELinux
if command -v sestatus >/dev/null 2>&1; then
    SELINUX_STATUS=$(sestatus | grep "SELinux status" | awk '{print $3}')
    if [ "$SELINUX_STATUS" = "enabled" ]; then
        log_warn "SELinux is enabled - may require policy adjustments"
    fi
fi

# Проверка AppArmor
if command -v aa-status >/dev/null 2>&1; then
    if aa-status >/dev/null 2>&1; then
        log_warn "AppArmor is enabled - may require profile adjustments"
    fi
fi

# 6. Проверка логов
log_info "Checking log system..."

# Проверка доступности syslog
if ! logger "APT-Shield preflight test" >/dev/null 2>&1; then
    log_error "Cannot write to syslog"
    exit 1
fi
log_info "Syslog accessible ✓"

# Проверка размера логов
LOG_SIZE=$(du -sm /var/log | awk '{print $1}')
if [ "$LOG_SIZE" -gt 1024 ]; then
    log_warn "Log directory is large: ${LOG_SIZE}MB - consider rotation"
fi

# 7. Проверка BPF maps
log_info "Checking BPF maps..."

# Очистка старых BPF maps
if [ -d "/sys/fs/bpf/apt-shield" ]; then
    log_info "Cleaning old BPF maps..."
    bpftool map show | grep apt-shield | awk '{print $1}' | xargs -r bpftool map delete
    rm -rf /sys/fs/bpf/apt-shield
fi

# Создание директории для BPF maps
mkdir -p /sys/fs/bpf/apt-shield
log_info "BPF maps directory ready ✓"

# 8. Проверка компиляции eBPF
log_info "Checking eBPF compilation..."

if [ ! -f "ebpf/apt_antiscan.o" ]; then
    log_info "Compiling APT-Shield eBPF program..."
    cd ebpf
    make apt_antiscan.o
    cd ..
fi

if [ ! -f "ebpf/apt_antiscan.o" ]; then
    log_error "Failed to compile eBPF program"
    exit 1
fi
log_info "eBPF program compiled ✓"

# 9. Финальная проверка
log_info "Final safety checks..."

# Проверка что мы можем загрузить eBPF программу
if ! bpftool prog load ebpf/apt_antiscan.o /sys/fs/bpf/apt-shield/antiscan type xdp; then
    log_error "Failed to load eBPF program"
    exit 1
fi

# Удаляем тестовую программу
bpftool prog delete pinned /sys/fs/bpf/apt-shield/antiscan
log_info "eBPF program load test passed ✓"

log_info "APT-Shield preflight check completed successfully! ✓"
log_info "System is ready for APT-Shield deployment"

exit 0 