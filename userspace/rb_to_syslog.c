// SPDX-License-Identifier: GPL-2.0
// APT-Shield: Ring-buffer to Syslog Service
// Elite-Mode APT-Grade Logging Service
// Critical Infrastructure Monitoring

#include <bpf/libbpf.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

// Структура события сканирования (должна совпадать с eBPF)
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

// Signal handler для graceful shutdown
static void signal_handler(int sig) {
    printf("Received signal %d, shutting down gracefully...\n", sig);
    running = false;
}

// Обработчик событий из ring-buffer
static int handle_event(void *ctx, void *data, size_t len) {
    if (len != sizeof(struct scan_event)) {
        syslog(LOG_WARNING, "APT_SHIELD: Invalid event size: %zu", len);
        return 0;
    }
    
    struct scan_event *event = (struct scan_event *)data;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &event->src_ip, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &event->dst_ip, dst_ip_str, sizeof(dst_ip_str));
    
    const char *protocol_str;
    const char *scan_type_str;
    
    switch (event->protocol) {
        case IPPROTO_TCP:
            protocol_str = "TCP";
            break;
        case IPPROTO_UDP:
            protocol_str = "UDP";
            break;
        case IPPROTO_ICMP:
            protocol_str = "ICMP";
            break;
        default:
            protocol_str = "UNKNOWN";
    }
    
    switch (event->scan_type) {
        case 1:
            scan_type_str = "SYN_SCAN";
            break;
        case 2:
            scan_type_str = "UDP_SCAN";
            break;
        case 3:
            scan_type_str = "ICMP_SCAN";
            break;
        default:
            scan_type_str = "UNKNOWN_SCAN";
    }
    
    // Логируем в syslog с высоким приоритетом
    syslog(LOG_ALERT, 
           "APT_SHIELD_SCAN: type=%s protocol=%s src=%s:%u dst=%s:%u timestamp=%llu",
           scan_type_str, protocol_str, src_ip_str, event->src_port,
           dst_ip_str, event->dst_port, event->timestamp);
    
    return 0;
}

int main(int argc, char **argv) {
    int err;
    
    // Установка signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Открытие syslog
    openlog("apt-shield", LOG_PID | LOG_CONS, LOG_LOCAL0);
    syslog(LOG_INFO, "APT-Shield ring-buffer to syslog service starting...");
    
    // Загрузка BPF объекта
    struct bpf_object *obj = bpf_object__open("ebpf/apt_antiscan.o");
    if (libbpf_get_error(obj)) {
        syslog(LOG_ERR, "Failed to open BPF object: %s", strerror(errno));
        return 1;
    }
    
    // Загрузка BPF программы в ядро
    err = bpf_object__load(obj);
    if (err) {
        syslog(LOG_ERR, "Failed to load BPF object: %s", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    // Поиск ring-buffer map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "scan_log");
    if (!map) {
        syslog(LOG_ERR, "Failed to find scan_log map");
        bpf_object__close(obj);
        return 1;
    }
    
    // Создание ring-buffer
    rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (libbpf_get_error(rb)) {
        syslog(LOG_ERR, "Failed to create ring buffer: %s", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    syslog(LOG_INFO, "APT-Shield ring-buffer service started successfully");
    
    // Основной цикл обработки событий
    while (running) {
        err = ring_buffer__poll(rb, 100); // 100ms timeout
        if (err < 0) {
            if (err == -EINTR) {
                // Interrupted by signal, continue
                continue;
            }
            syslog(LOG_ERR, "Ring buffer poll error: %s", strerror(-err));
            break;
        }
    }
    
    // Cleanup
    syslog(LOG_INFO, "APT-Shield ring-buffer service shutting down...");
    ring_buffer__free(rb);
    bpf_object__close(obj);
    closelog();
    
    return 0;
} 