/*
 * Cerberus-V2: Userspace Control Plane
 * Elite APT-Grade Firewall Management
 */

#define _GNU_SOURCE
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

// XDP flags
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 1)
#endif

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 2)
#endif

// Configuration
#define RING_SIZE (1 << 16)

// Event structure (must match eBPF)
struct event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;
    __u64 timestamp;
};

// Global state
static volatile int running = 1;
static int ring_fd = -1;
static struct ring_buffer *rb = NULL;

// Signal handler
static void sig_handler(int sig) {
    (void)sig; // Suppress unused parameter warning
    running = 0;
}

// Event handler for ring buffer
static int handle_event(void *ctx, void *data, size_t len) {
    if (len != sizeof(struct event)) {
        return 0;
    }
    
    struct event *evt = (struct event *)data;
    char src_ip[16], dst_ip[16];
    
    inet_ntop(AF_INET, &evt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &evt->dst_ip, dst_ip, sizeof(dst_ip));
    
    const char *proto = evt->protocol == IPPROTO_TCP ? "TCP" : "ICMP";
    const char *action = evt->action == 0 ? "BLOCKED" : "ALLOWED";
    
    printf("[%s] %s:%u -> %s:%u (%s) %s\n", 
           proto, src_ip, evt->src_port, dst_ip, evt->dst_port, proto, action);
    
    return 0;
}

// Load BPF program
static int load_bpf_program(const char *interface) {
    // Load BPF object
    struct bpf_object *obj = bpf_object__open("cerberus-ebpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return -1;
    }
    
    // Load BPF program
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return -1;
    }
    
    // Get program FD
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "cerberus_filter");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return -1;
    }
    
    int prog_fd = bpf_program__fd(prog);
    
    // Attach to interface
    int ifindex = if_nametoindex(interface);
    if (!ifindex) {
        perror("if_nametoindex");
        bpf_object__close(obj);
        return -1;
    }
    
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL) < 0) {
        // Fallback to generic mode
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            perror("bpf_xdp_attach");
            bpf_object__close(obj);
            return -1;
        }
    }
    
    return prog_fd;
}

// Event processing
static void process_events() {
    while (running) {
        if (ring_buffer__poll(rb, 100) < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
    }
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    
    const char *interface = argv[1];
    
    // Set signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Cerberus-V2: Elite APT-Grade Firewall\n");
    printf("Interface: %s\n", interface);
    
    // Load BPF program
    int prog_fd = load_bpf_program(interface);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }
    
    // Create ring buffer
    ring_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "events", 0, 0, RING_SIZE, NULL);
    if (ring_fd < 0) {
        perror("bpf_map_create ringbuf");
        return 1;
    }
    
    // Create ring buffer
    rb = ring_buffer__new(ring_fd, handle_event, NULL, NULL);
    if (libbpf_get_error(rb)) {
        perror("ring_buffer__new");
        close(ring_fd);
        return 1;
    }
    
    printf("Cerberus-V2 started. Press Ctrl+C to stop.\n");
    
    // Process events
    process_events();
    
    // Cleanup
    ring_buffer__free(rb);
    close(ring_fd);
    
    printf("Cerberus-V2 stopped.\n");
    return 0;
} 