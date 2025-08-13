#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# APT-Shield Deployment Script
# Elite-Mode APT-Grade Critical Infrastructure Deployment
# Government-Level Security Implementation

set -euo pipefail

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции логирования
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Проверка root прав
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

log_step "🛡️ APT-Shield Critical Infrastructure Deployment"
log_info "Starting deployment for government-level security..."

# 1. Preflight проверка
log_step "1. Running preflight safety check..."
if ! ./scripts/apt-shield-preflight.sh; then
    log_error "Preflight check failed - deployment aborted"
    exit 1
fi

# 2. Остановка конфликтующих сервисов
log_step "2. Stopping conflicting services..."
if systemctl is-active --quiet firewalld; then
    log_info "Stopping firewalld..."
    systemctl stop firewalld
    systemctl disable firewalld
fi

# 3. Компиляция eBPF программ
log_step "3. Compiling APT-Shield eBPF programs..."
cd ebpf
make clean
make apt-shield
cd ..

# 4. Создание BPF maps
log_step "4. Creating BPF maps..."
mkdir -p /sys/fs/bpf/apt-shield

# Создание ring-buffer для сканирований
bpftool map create /sys/fs/bpf/apt-shield/scan_log type ringbuf key 0 value 0 entries 1048576 name scan_log

# Создание LRU hash для rate limiting
bpftool map create /sys/fs/bpf/apt-shield/rate_limiter type lru_hash key 4 value 12 entries 10000 name rate_limiter

# Создание per-CPU array для статистики
bpftool map create /sys/fs/bpf/apt-shield/apt_stats type percpu_array key 4 value 8 entries 256 name apt_stats

# 5. Загрузка eBPF программы
log_step "5. Loading APT-Shield eBPF program..."
MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

bpftool prog load ebpf/apt_antiscan.o /sys/fs/bpf/apt-shield/antiscan type xdp \
    map name scan_log pinned /sys/fs/bpf/apt-shield/scan_log \
    map name rate_limiter pinned /sys/fs/bpf/apt-shield/rate_limiter \
    map name apt_stats pinned /sys/fs/bpf/apt-shield/apt_stats

# 6. Привязка к сетевому интерфейсу
log_step "6. Attaching APT-Shield to network interface: $MAIN_IFACE"
bpftool net attach xdpgeneric pinned /sys/fs/bpf/apt-shield/antiscan dev "$MAIN_IFACE"

# 7. Компиляция userspace компонентов
log_step "7. Compiling userspace components..."
cd userspace
gcc -o rb_to_syslog rb_to_syslog.c -lbpf -lelf -lz
cd ..

# 8. Установка systemd сервисов
log_step "8. Installing systemd services..."
cp systemd/apt-shield.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable apt-shield.service

# 9. Настройка logrotate
log_step "9. Configuring log rotation..."
cat > /etc/logrotate.d/apt-shield << 'EOF'
/var/log/apt-shield.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload rsyslog
    endscript
}
EOF

# 10. Настройка syslog
log_step "10. Configuring syslog..."
cat > /etc/rsyslog.d/apt-shield.conf << 'EOF'
# APT-Shield logging configuration
if $programname == 'apt-shield' then /var/log/apt-shield.log
if $programname == 'apt-shield' then stop
EOF

systemctl reload rsyslog

# 11. Запуск APT-Shield
log_step "11. Starting APT-Shield service..."
systemctl start apt-shield.service

# 12. Проверка статуса
log_step "12. Verifying deployment..."
sleep 3

if systemctl is-active --quiet apt-shield.service; then
    log_info "APT-Shield service is running ✓"
else
    log_error "APT-Shield service failed to start"
    systemctl status apt-shield.service
    exit 1
fi

# Проверка eBPF программы
if bpftool prog show | grep -q "apt_antiscan"; then
    log_info "APT-Shield eBPF program is loaded ✓"
else
    log_error "APT-Shield eBPF program not found"
    exit 1
fi

# Проверка BPF maps
if bpftool map show | grep -q "scan_log"; then
    log_info "APT-Shield BPF maps are created ✓"
else
    log_error "APT-Shield BPF maps not found"
    exit 1
fi

# 13. Финальная проверка
log_step "13. Final verification..."

# Тестовый ping для проверки ICMP блокировки
log_info "Testing ICMP blocking..."
if ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then
    log_warn "ICMP is not blocked - check configuration"
else
    log_info "ICMP blocking working ✓"
fi

# Проверка логов
if journalctl -u apt-shield.service --since "1 minute ago" | grep -q "APT-Shield"; then
    log_info "APT-Shield logging is working ✓"
else
    log_warn "APT-Shield logging not detected"
fi

log_step "🎉 APT-Shield deployment completed successfully!"
log_info "Critical infrastructure is now protected by APT-Shield"
log_info "Monitor logs: journalctl -u apt-shield.service -f"
log_info "Check status: systemctl status apt-shield.service"
log_info "View BPF programs: bpftool prog show"

exit 0 