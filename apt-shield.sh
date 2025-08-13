#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# APT-Shield: Anti-Reconnaissance Firewall
# Elite-Mode APT-Grade Protection in One Script
# Portable, Simple, Effective

set -euo pipefail

# Конфигурация
INTERFACE=${1:-$(ip route | grep default | awk '{print $5}' | head -1)}
LOG_FILE=${2:-/var/log/apt-shield.log}
BPF_DIR="/sys/fs/bpf/apt-shield"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[APT-Shield]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Проверка root
[[ $EUID -eq 0 ]] || { error "Run as root"; exit 1; }

# Функция создания eBPF программы
create_ebpf() {
    cat > /tmp/apt_antiscan.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} scan_log SEC(".maps");

struct scan_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 scan_type;
    __u64 timestamp;
};

SEC("xdp")
int apt_antiscan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return XDP_PASS;
    
    if (iph->version != 4)
        return XDP_PASS;
    
    __u32 src_ip = iph->saddr;
    __u64 current_time = bpf_ktime_get_ns();
    
    // TCP SYN scan detection
    if (iph->protocol == IPPROTO_TCP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
            
        struct tcphdr *tcp = data + sizeof(*eth) + (iph->ihl << 2);
        
        if (tcp->syn && !tcp->ack) {
            struct scan_event *event = bpf_ringbuf_reserve(&scan_log, sizeof(*event), 0);
            if (event) {
                event->src_ip = src_ip;
                event->dst_ip = iph->daddr;
                event->src_port = bpf_ntohs(tcp->source);
                event->dst_port = bpf_ntohs(tcp->dest);
                event->protocol = IPPROTO_TCP;
                event->scan_type = 1;
                event->timestamp = current_time;
                bpf_ringbuf_submit(event, 0);
            }
            return XDP_DROP;
        }
    }
    
    // ICMP scan detection
    if (iph->protocol == IPPROTO_ICMP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct icmphdr) > data_end)
            return XDP_PASS;
            
        struct icmphdr *icmp = data + sizeof(*eth) + (iph->ihl << 2);
        
        if (icmp->type == ICMP_ECHO) {
            struct scan_event *event = bpf_ringbuf_reserve(&scan_log, sizeof(*event), 0);
            if (event) {
                event->src_ip = src_ip;
                event->dst_ip = iph->daddr;
                event->src_port = 0;
                event->dst_port = 0;
                event->protocol = IPPROTO_ICMP;
                event->scan_type = 3;
                event->timestamp = current_time;
                bpf_ringbuf_submit(event, 0);
            }
            return XDP_DROP;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
EOF
}

# Функция компиляции eBPF
compile_ebpf() {
    log "Compiling eBPF program..."
    clang -O2 -g -Wall -Wextra -target bpf -D__TARGET_ARCH_x86 \
          -I/usr/include/bpf -I/usr/include -fno-stack-protector \
          -c /tmp/apt_antiscan.c -o /tmp/apt_antiscan.o
    llvm-strip -g /tmp/apt_antiscan.o
}

# Функция создания BPF maps
create_maps() {
    log "Creating BPF maps..."
    mkdir -p "$BPF_DIR"
    bpftool map create "$BPF_DIR/scan_log" type ringbuf key 0 value 0 entries 65536 name scan_log
}

# Функция загрузки eBPF
load_ebpf() {
    log "Loading eBPF program..."
    bpftool prog load /tmp/apt_antiscan.o "$BPF_DIR/antiscan" type xdp \
        map name scan_log pinned "$BPF_DIR/scan_log"
}

# Функция привязки к интерфейсу
attach_ebpf() {
    log "Attaching to interface: $INTERFACE"
    bpftool net attach xdpgeneric pinned "$BPF_DIR/antiscan" dev "$INTERFACE"
}

# Функция логирования
start_logging() {
    log "Starting logging to: $LOG_FILE"
    
    # Создаем простой logger
    cat > /tmp/apt_logger.c << 'EOF'
#include <bpf/libbpf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

struct scan_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 scan_type;
    __u64 timestamp;
};

static volatile bool running = true;
static struct ring_buffer *rb = NULL;

void signal_handler(int sig) {
    running = false;
}

int handle_event(void *ctx, void *data, size_t len) {
    if (len != sizeof(struct scan_event)) return 0;
    
    struct scan_event *event = (struct scan_event *)data;
    char src_ip[16], dst_ip[16];
    
    inet_ntop(AF_INET, &event->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &event->dst_ip, dst_ip, sizeof(dst_ip));
    
    const char *scan_type = event->scan_type == 1 ? "SYN_SCAN" : "ICMP_SCAN";
    const char *protocol = event->protocol == IPPROTO_TCP ? "TCP" : "ICMP";
    
    printf("[APT-Shield] %s: %s -> %s:%u (%s)\n", 
           scan_type, src_ip, dst_ip, event->dst_port, protocol);
    
    return 0;
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    struct bpf_object *obj = bpf_object__open("/tmp/apt_antiscan.o");
    if (libbpf_get_error(obj)) return 1;
    
    if (bpf_object__load(obj)) return 1;
    
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "scan_log");
    if (!map) return 1;
    
    rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (libbpf_get_error(rb)) return 1;
    
    printf("APT-Shield logger started. Press Ctrl+C to stop.\n");
    
    while (running) {
        if (ring_buffer__poll(rb, 100) < 0) break;
    }
    
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
EOF

    gcc -o /tmp/apt_logger /tmp/apt_logger.c -lbpf -lelf -lz
    /tmp/apt_logger &
    echo $! > /tmp/apt_logger.pid
}

# Функция остановки
stop_apt_shield() {
    log "Stopping APT-Shield..."
    
    # Остановка logger
    if [ -f /tmp/apt_logger.pid ]; then
        kill $(cat /tmp/apt_logger.pid) 2>/dev/null || true
        rm -f /tmp/apt_logger.pid
    fi
    
    # Отключение eBPF
    bpftool net detach xdpgeneric dev "$INTERFACE" 2>/dev/null || true
    
    # Удаление BPF maps
    rm -rf "$BPF_DIR"
    
    # Очистка временных файлов
    rm -f /tmp/apt_antiscan.c /tmp/apt_antiscan.o /tmp/apt_logger.c /tmp/apt_logger
    
    log "APT-Shield stopped"
}

# Функция статуса
show_status() {
    echo "=== APT-Shield Status ==="
    echo "Interface: $INTERFACE"
    echo "BPF Directory: $BPF_DIR"
    echo "Log File: $LOG_FILE"
    echo ""
    
    if bpftool prog show | grep -q "apt_antiscan"; then
        echo "✅ eBPF program: LOADED"
    else
        echo "❌ eBPF program: NOT LOADED"
    fi
    
    if [ -d "$BPF_DIR" ]; then
        echo "✅ BPF maps: CREATED"
    else
        echo "❌ BPF maps: NOT CREATED"
    fi
    
    if [ -f /tmp/apt_logger.pid ] && kill -0 $(cat /tmp/apt_logger.pid) 2>/dev/null; then
        echo "✅ Logger: RUNNING"
    else
        echo "❌ Logger: NOT RUNNING"
    fi
}

# Главная функция
main() {
    case "${1:-start}" in
        start)
            log "Starting APT-Shield..."
            create_ebpf
            compile_ebpf
            create_maps
            load_ebpf
            attach_ebpf
            start_logging
            log "APT-Shield started successfully!"
            ;;
        stop)
            stop_apt_shield
            ;;
        restart)
            stop_apt_shield
            sleep 1
            main start
            ;;
        status)
            show_status
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status}"
            echo "  start   - Start APT-Shield"
            echo "  stop    - Stop APT-Shield"
            echo "  restart - Restart APT-Shield"
            echo "  status  - Show status"
            exit 1
            ;;
    esac
}

# Обработка сигналов
trap 'stop_apt_shield; exit 0' INT TERM

# Запуск
main "$@" 