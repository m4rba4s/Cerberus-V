// SPDX-License-Identifier: Apache-2.0
// Author: vppebpf  Date: 2024-12-19
// AF_XDP userspace loader: Production-grade TCP packet processor

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <net/if.h>

// Configuration constants
#define PROG_NAME "af_xdp_loader"
#define DEFAULT_XDP_PROG "ebpf/xdp_filter.o"
#define DEFAULT_IFACE "veth-a"
#define UMEM_NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX

// Application state
struct app_config {
    const char *ifname;
    const char *prog_path;
    int ifindex;
    bool verbose;
    int queue_id;
};

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    uint64_t umem_frame_addr[UMEM_NUM_FRAMES];
    uint32_t umem_frame_free;
    uint32_t outstanding_tx;
};

// Global state (initialized properly)
static struct app_config config = {
    .ifname = DEFAULT_IFACE,
    .prog_path = DEFAULT_XDP_PROG,
    .ifindex = 0,
    .verbose = false,
    .queue_id = 0
};

static struct xsk_socket_info *xsk_socket_info = NULL;
static struct bpf_object *bpf_obj = NULL;
static volatile bool keep_running = true;

// Logging macros - C99 compatible
#define LOG_INFO(...) \
    do { if (config.verbose) printf("[INFO] " __VA_ARGS__); printf("\n"); } while(0)
#define LOG_ERROR(...) \
    do { fprintf(stderr, "[ERROR] " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define LOG_DEBUG(...) \
    do { if (config.verbose) { printf("[DEBUG] " __VA_ARGS__); printf("\n"); } } while(0)

// Cleanup and signal handling
static void cleanup_and_exit(int exit_code) {
    LOG_INFO("🧹 Cleaning up resources...");
    
    if (xsk_socket_info) {
        if (xsk_socket_info->xsk) {
            xsk_socket__delete(xsk_socket_info->xsk);
        }
        if (xsk_socket_info->umem && xsk_socket_info->umem->umem) {
            xsk_umem__delete(xsk_socket_info->umem->umem);
        }
        if (xsk_socket_info->umem && xsk_socket_info->umem->buffer) {
            free(xsk_socket_info->umem->buffer);
        }
        free(xsk_socket_info->umem);
        free(xsk_socket_info);
    }

    if (bpf_obj) {
        bpf_object__close(bpf_obj);
    }

    if (config.ifindex > 0) {
        bpf_xdp_detach(config.ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        LOG_INFO("XDP program detached from interface");
    }

    exit(exit_code);
}

static void signal_handler(int signum) {
    LOG_INFO("Received signal %d, shutting down...", signum);
    keep_running = false;
}

// Memory management
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
    if (xsk->umem_frame_free >= UMEM_NUM_FRAMES) {
        LOG_ERROR("umem frame free list overflow");
        return;
    }
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

// XDP program management
static int load_xdp_program(void) {
    struct bpf_program *prog;
    int prog_fd, map_fd;
    int ret;

    // Set up libbpf logging
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    
    bpf_obj = bpf_object__open(config.prog_path);
    if (libbpf_get_error(bpf_obj)) {
        LOG_ERROR("Failed to open BPF object file: %s", config.prog_path);
        return -1;
    }

    ret = bpf_object__load(bpf_obj);
    if (ret) {
        LOG_ERROR("Failed to load BPF object: %s", strerror(-ret));
        bpf_object__close(bpf_obj);
        return -1;
    }

    prog = bpf_object__find_program_by_name(bpf_obj, "xdp_firewall");
    if (!prog) {
        LOG_ERROR("Failed to find XDP program 'xdp_firewall'");
        bpf_object__close(bpf_obj);
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        LOG_ERROR("Failed to get program fd");
        bpf_object__close(bpf_obj);
        return -1;
    }

    ret = bpf_xdp_attach(config.ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (ret < 0) {
        LOG_ERROR("Failed to attach XDP program: %s", strerror(-ret));
        bpf_object__close(bpf_obj);
        return -1;
    }

    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xsk_map");
    if (map_fd < 0) {
        LOG_ERROR("Failed to find xsk_map");
        bpf_xdp_detach(config.ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        bpf_object__close(bpf_obj);
        return -1;
    }

    LOG_INFO("✅ XDP program loaded and attached successfully");
    return map_fd;
}

// AF_XDP socket setup
static struct xsk_socket_info *xsk_configure_socket(int xsk_map_fd) {
    struct xsk_socket_info *xsk_info;
    struct xsk_umem_info *umem;
    int ret;
    size_t umem_size = UMEM_NUM_FRAMES * FRAME_SIZE;

    // Allocate socket info
    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info) {
        LOG_ERROR("Failed to allocate xsk_socket_info");
        return NULL;
    }

    umem = calloc(1, sizeof(*umem));
    if (!umem) {
        LOG_ERROR("Failed to allocate xsk_umem_info");
        free(xsk_info);
        return NULL;
    }
    xsk_info->umem = umem;

    // Allocate UMEM buffer
    umem->buffer = aligned_alloc(sysconf(_SC_PAGESIZE), umem_size);
    if (!umem->buffer) {
        LOG_ERROR("Failed to allocate UMEM buffer");
        free(umem);
        free(xsk_info);
        return NULL;
    }

    // Create UMEM
    ret = xsk_umem__create(&umem->umem, umem->buffer, umem_size,
                           &umem->fq, &umem->cq, NULL);
    if (ret) {
        LOG_ERROR("Failed to create UMEM: %s", strerror(-ret));
        free(umem->buffer);
        free(umem);
        free(xsk_info);
        return NULL;
    }

    // Create socket
    ret = xsk_socket__create(&xsk_info->xsk, config.ifname, config.queue_id,
                             umem->umem, &xsk_info->rx, &xsk_info->tx, NULL);
    if (ret) {
        LOG_ERROR("Failed to create AF_XDP socket: %s", strerror(-ret));
        xsk_umem__delete(umem->umem);
        free(umem->buffer);
        free(umem);
        free(xsk_info);
        return NULL;
    }

    // Update XSK map
    ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
    if (ret) {
        LOG_ERROR("Failed to update XSK map: %s", strerror(-ret));
        xsk_socket__delete(xsk_info->xsk);
        xsk_umem__delete(umem->umem);
        free(umem->buffer);
        free(umem);
        free(xsk_info);
        return NULL;
    }

    // Initialize frame allocator
    for (int i = 0; i < UMEM_NUM_FRAMES; i++) {
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }
    xsk_info->umem_frame_free = UMEM_NUM_FRAMES;

    LOG_INFO("✅ AF_XDP socket configured successfully");
    return xsk_info;
}

// Main packet processing loop
static void process_packets(void) {
    struct pollfd fds[1];
    uint32_t idx_rx = 0;
    unsigned int rcvd;
    int ret;

    fds[0].fd = xsk_socket__fd(xsk_socket_info->xsk);
    fds[0].events = POLLIN;

    LOG_INFO("🚀 Packet processing started. Waiting for TCP packets...");

    while (keep_running) {
        ret = poll(fds, 1, 1000);  // 1 second timeout
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("Poll failed: %s", strerror(errno));
            break;
        }
        if (ret == 0) continue;  // Timeout

        rcvd = xsk_ring_cons__peek(&xsk_socket_info->rx, RX_BATCH_SIZE, &idx_rx);
        if (!rcvd) continue;

        // Process received packets
        for (unsigned int i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&xsk_socket_info->rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&xsk_socket_info->rx, idx_rx)->len;
            
            LOG_DEBUG("📦 Received TCP packet: %u bytes", len);
            
            // In production: process packet here (DPI, logging, forwarding)
            // For now, just count it
            static uint64_t packet_count = 0;
            packet_count++;
            if (packet_count % 1000 == 0) {
                printf("📊 Processed %lu TCP packets\n", packet_count);
            }

            // Free the frame back to UMEM
            xsk_free_umem_frame(xsk_socket_info, addr);
            idx_rx++;
        }

        xsk_ring_cons__release(&xsk_socket_info->rx, rcvd);
    }

    LOG_INFO("📊 Packet processing stopped");
}

// Command line parsing
static void parse_arguments(int argc, char **argv) {
    int option;
    
    while ((option = getopt(argc, argv, "i:p:vq:h")) != -1) {
        switch (option) {
        case 'i':
            config.ifname = optarg;
            break;
        case 'p':
            config.prog_path = optarg;
            break;
        case 'v':
            config.verbose = true;
            break;
        case 'q':
            config.queue_id = atoi(optarg);
            break;
        case 'h':
            printf("Usage: %s [OPTIONS]\n", PROG_NAME);
            printf("  -i <interface>  Network interface (default: %s)\n", DEFAULT_IFACE);
            printf("  -p <path>       XDP program path (default: %s)\n", DEFAULT_XDP_PROG);
            printf("  -q <queue_id>   Queue ID (default: 0)\n");
            printf("  -v              Verbose output\n");
            printf("  -h              Show this help\n");
            exit(0);
        default:
            exit(1);
        }
    }
}

int main(int argc, char **argv) {
    int xsk_map_fd;

    parse_arguments(argc, argv);

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Get interface index
    config.ifindex = if_nametoindex(config.ifname);
    if (!config.ifindex) {
        LOG_ERROR("Failed to get ifindex for %s: %s", config.ifname, strerror(errno));
        return EXIT_FAILURE;
    }

    LOG_INFO("🚀 Starting %s on interface %s (ifindex: %d)", 
             PROG_NAME, config.ifname, config.ifindex);

    // Load and attach XDP program
    xsk_map_fd = load_xdp_program();
    if (xsk_map_fd < 0) {
        return EXIT_FAILURE;
    }

    // Configure AF_XDP socket
    xsk_socket_info = xsk_configure_socket(xsk_map_fd);
    if (!xsk_socket_info) {
        cleanup_and_exit(EXIT_FAILURE);
    }

    // Main processing loop
    process_packets();

    cleanup_and_exit(EXIT_SUCCESS);
} 