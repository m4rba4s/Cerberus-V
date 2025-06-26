// SPDX-License-Identifier: Apache-2.0
// Author: vppebpf  Date: 2025-06-26
// VPP eBPF Classification Node: Production-grade dual protection

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

// eBPF integration headers
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define EBPF_CLASSIFY_PLUGIN_VERSION_MAJOR 1
#define EBPF_CLASSIFY_PLUGIN_VERSION_MINOR 0

// BPF map paths (shared with XDP program)
#define SHARED_ACL_MAP_PATH "/sys/fs/bpf/vpp_acl_v4"
#define SHARED_STATS_MAP_PATH "/sys/fs/bpf/vpp_stats"
#define SHARED_SESSION_MAP_PATH "/sys/fs/bpf/vpp_sessions"

// Graph node indices
typedef enum {
    EBPF_CLASSIFY_NEXT_DROP,
    EBPF_CLASSIFY_NEXT_IP4_LOOKUP,
    EBPF_CLASSIFY_NEXT_IP6_LOOKUP,
    EBPF_CLASSIFY_NEXT_ETHERNET_INPUT,
    EBPF_CLASSIFY_N_NEXT,
} ebpf_classify_next_t;

// Error codes  
typedef enum {
    EBPF_CLASSIFY_ERROR_PROCESSED,
    EBPF_CLASSIFY_ERROR_DROPPED,
    EBPF_CLASSIFY_ERROR_MAP_LOOKUP_FAILED,
    EBPF_CLASSIFY_ERROR_INVALID_PACKET,
} ebpf_classify_error_t;

// ACL rule structure (shared with eBPF)
typedef struct {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;  // 0=drop, 1=allow, 2=log
    __u16 priority;
} __attribute__((packed)) acl_rule_t;

// Session entry structure
typedef struct {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 state;   // TCP state or connection state
    __u64 last_seen;
    __u64 bytes_rx;
    __u64 bytes_tx;
} __attribute__((packed)) session_entry_t;

// Statistics structure
typedef struct {
    __u64 packets_processed;
    __u64 packets_dropped;
    __u64 packets_allowed;
    __u64 map_lookups;
    __u64 map_hits;
    __u64 sessions_created;
    __u64 sessions_deleted;
} __attribute__((packed)) ebpf_stats_t;

// Plugin main structure
typedef struct {
    // BPF map file descriptors
    int acl_map_fd;
    int stats_map_fd;
    int session_map_fd;
    
    // Configuration
    u8 dual_protection_enabled;
    u8 stateful_mode;
    u32 session_timeout;
    
    // Statistics (local copy)
    ebpf_stats_t stats;
    
    // VPP references
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;
    
} ebpf_classify_main_t;

ebpf_classify_main_t ebpf_classify_main;

// Error strings
static char *ebpf_classify_error_strings[] = {
    [EBPF_CLASSIFY_ERROR_PROCESSED] = "Packets processed",
    [EBPF_CLASSIFY_ERROR_DROPPED] = "Packets dropped by eBPF rules",
    [EBPF_CLASSIFY_ERROR_MAP_LOOKUP_FAILED] = "BPF map lookup failed",
    [EBPF_CLASSIFY_ERROR_INVALID_PACKET] = "Invalid packet format",
};

// Function declarations
static uword ebpf_classify_node_fn(vlib_main_t *vm, 
                                   vlib_node_runtime_t *node,
                                   vlib_frame_t *frame);

// BPF map helper functions
static int load_bpf_maps(ebpf_classify_main_t *em) {
    // Load pinned BPF maps shared with XDP program
    em->acl_map_fd = bpf_obj_get(SHARED_ACL_MAP_PATH);
    if (em->acl_map_fd < 0) {
        clib_warning("Failed to load ACL map from %s: %s", 
                     SHARED_ACL_MAP_PATH, strerror(errno));
        return -1;
    }
    
    em->stats_map_fd = bpf_obj_get(SHARED_STATS_MAP_PATH);
    if (em->stats_map_fd < 0) {
        clib_warning("Failed to load stats map from %s: %s",
                     SHARED_STATS_MAP_PATH, strerror(errno));
        close(em->acl_map_fd);
        return -1;
    }
    
    em->session_map_fd = bpf_obj_get(SHARED_SESSION_MAP_PATH);
    if (em->session_map_fd < 0) {
        clib_warning("Failed to load session map from %s: %s",
                     SHARED_SESSION_MAP_PATH, strerror(errno));
        close(em->acl_map_fd);
        close(em->stats_map_fd);
        return -1;
    }
    
    clib_info("✅ BPF maps loaded successfully for dual protection");
    return 0;
}

static inline int lookup_acl_rule(ebpf_classify_main_t *em,
                                  u32 src_ip, u32 dst_ip,
                                  u16 src_port, u16 dst_port,
                                  u8 protocol, acl_rule_t *rule) {
    // Create lookup key
    struct {
        u32 src_ip;
        u32 dst_ip;
        u16 src_port;
        u16 dst_port;
        u8 protocol;
    } key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol
    };
    
    // Lookup in shared BPF map
    int ret = bpf_map_lookup_elem(em->acl_map_fd, &key, rule);
    
    // Update statistics
    u32 stats_key = 0;
    ebpf_stats_t stats;
    if (bpf_map_lookup_elem(em->stats_map_fd, &stats_key, &stats) == 0) {
        stats.map_lookups++;
        if (ret == 0) stats.map_hits++;
        bpf_map_update_elem(em->stats_map_fd, &stats_key, &stats, BPF_ANY);
    }
    
    return ret;
}

static inline int update_session(ebpf_classify_main_t *em,
                                 u32 src_ip, u32 dst_ip,
                                 u16 src_port, u16 dst_port,
                                 u8 protocol, u32 packet_len) {
    if (!em->stateful_mode) return 0;
    
    // Create session key
    struct {
        u32 src_ip;
        u32 dst_ip;
        u16 src_port;
        u16 dst_port;
        u8 protocol;
    } key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol
    };
    
    session_entry_t session;
    int ret = bpf_map_lookup_elem(em->session_map_fd, &key, &session);
    
    if (ret == 0) {
        // Update existing session
        session.last_seen = vlib_time_now(em->vlib_main);
        session.bytes_rx += packet_len;
    } else {
        // Create new session
        session.src_ip = src_ip;
        session.dst_ip = dst_ip;
        session.src_port = src_port;
        session.dst_port = dst_port;
        session.protocol = protocol;
        session.state = 1; // SYN_SENT or ESTABLISHED
        session.last_seen = vlib_time_now(em->vlib_main);
        session.bytes_rx = packet_len;
        session.bytes_tx = 0;
    }
    
    return bpf_map_update_elem(em->session_map_fd, &key, &session, BPF_ANY);
}

// Main processing function
static uword ebpf_classify_node_fn(vlib_main_t *vm,
                                   vlib_node_runtime_t *node,
                                   vlib_frame_t *frame) {
    u32 n_left_from, *from, *to_next;
    ebpf_classify_next_t next_index;
    ebpf_classify_main_t *em = &ebpf_classify_main;
    u32 pkts_processed = 0, pkts_dropped = 0;
    
    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;
    
    while (n_left_from > 0) {
        u32 n_left_to_next;
        
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
        
        while (n_left_from > 0 && n_left_to_next > 0) {
            u32 bi0;
            vlib_buffer_t *b0;
            ethernet_header_t *eth0;
            ip4_header_t *ip0;
            u32 next0 = EBPF_CLASSIFY_NEXT_IP4_LOOKUP;
            
            // Get buffer
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;
            
            b0 = vlib_get_buffer(vm, bi0);
            
            // Parse Ethernet header
            eth0 = vlib_buffer_get_current(b0);
            
            // Only process IPv4 packets
            if (clib_net_to_host_u16(eth0->type) == ETHERNET_TYPE_IP4) {
                ip0 = (ip4_header_t *)(eth0 + 1);
                
                // Validate IP header
                if (PREDICT_TRUE(vlib_buffer_length_in_chain(vm, b0) >= 
                                sizeof(ethernet_header_t) + sizeof(ip4_header_t))) {
                    
                    u32 src_ip = clib_net_to_host_u32(ip0->src_address.as_u32);
                    u32 dst_ip = clib_net_to_host_u32(ip0->dst_address.as_u32);
                    u8 protocol = ip0->protocol;
                    u16 src_port = 0, dst_port = 0;
                    
                    // Extract ports for TCP/UDP
                    if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP) {
                        u16 *ports = (u16 *)(ip0 + 1);
                        if (vlib_buffer_length_in_chain(vm, b0) >= 
                            sizeof(ethernet_header_t) + sizeof(ip4_header_t) + 4) {
                            src_port = clib_net_to_host_u16(ports[0]);
                            dst_port = clib_net_to_host_u16(ports[1]);
                        }
                    }
                    
                    // Lookup ACL rule in shared BPF map
                    acl_rule_t rule;
                    int lookup_result = lookup_acl_rule(em, src_ip, dst_ip, 
                                                       src_port, dst_port, 
                                                       protocol, &rule);
                    
                    if (lookup_result == 0) {
                        // Rule found - apply action
                        if (rule.action == 0) { // DROP
                            next0 = EBPF_CLASSIFY_NEXT_DROP;
                            pkts_dropped++;
                            b0->error = node->errors[EBPF_CLASSIFY_ERROR_DROPPED];
                        } else if (rule.action == 1) { // ALLOW
                            // Update session if stateful mode
                            update_session(em, src_ip, dst_ip, src_port, dst_port,
                                         protocol, vlib_buffer_length_in_chain(vm, b0));
                            pkts_processed++;
                        }
                        // action == 2 (LOG) - continue processing with logging
                    } else {
                        // No rule found - default allow
                        pkts_processed++;
                        b0->error = node->errors[EBPF_CLASSIFY_ERROR_PROCESSED];
                    }
                } else {
                    // Invalid packet
                    next0 = EBPF_CLASSIFY_NEXT_DROP;
                    b0->error = node->errors[EBPF_CLASSIFY_ERROR_INVALID_PACKET];
                }
            }
            
            // Validate and enqueue to next node
            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }
        
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }
    
    // Update local statistics
    em->stats.packets_processed += pkts_processed;
    em->stats.packets_dropped += pkts_dropped;
    
    return frame->n_vectors;
}

// Node registration
VLIB_REGISTER_NODE(ebpf_classify_node) = {
    .function = ebpf_classify_node_fn,
    .name = "ebpf-classify-inline",
    .vector_size = sizeof(u32),
    .format_trace = 0, // format_trace function if needed
    
    .n_errors = ARRAY_LEN(ebpf_classify_error_strings),
    .error_strings = ebpf_classify_error_strings,
    
    .n_next_nodes = EBPF_CLASSIFY_N_NEXT,
    .next_nodes = {
        [EBPF_CLASSIFY_NEXT_DROP] = "error-drop",
        [EBPF_CLASSIFY_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [EBPF_CLASSIFY_NEXT_IP6_LOOKUP] = "ip6-lookup", 
        [EBPF_CLASSIFY_NEXT_ETHERNET_INPUT] = "ethernet-input",
    },
};

// CLI commands for debugging
static clib_error_t *
show_ebpf_classify_command_fn(vlib_main_t *vm,
                              unformat_input_t *input,
                              vlib_cli_command_t *cmd) {
    ebpf_classify_main_t *em = &ebpf_classify_main;
    
    vlib_cli_output(vm, "eBPF Classify Plugin Status:");
    vlib_cli_output(vm, "  Dual Protection: %s", 
                    em->dual_protection_enabled ? "enabled" : "disabled");
    vlib_cli_output(vm, "  Stateful Mode: %s",
                    em->stateful_mode ? "enabled" : "disabled");
    vlib_cli_output(vm, "  ACL Map FD: %d", em->acl_map_fd);
    vlib_cli_output(vm, "  Stats Map FD: %d", em->stats_map_fd);
    vlib_cli_output(vm, "  Session Map FD: %d", em->session_map_fd);
    
    vlib_cli_output(vm, "\nStatistics:");
    vlib_cli_output(vm, "  Packets Processed: %llu", em->stats.packets_processed);
    vlib_cli_output(vm, "  Packets Dropped: %llu", em->stats.packets_dropped);
    vlib_cli_output(vm, "  Packets Allowed: %llu", em->stats.packets_allowed);
    vlib_cli_output(vm, "  Map Lookups: %llu", em->stats.map_lookups);
    vlib_cli_output(vm, "  Map Hits: %llu", em->stats.map_hits);
    vlib_cli_output(vm, "  Sessions Created: %llu", em->stats.sessions_created);
    vlib_cli_output(vm, "  Sessions Deleted: %llu", em->stats.sessions_deleted);
    
    return 0;
}

VLIB_CLI_COMMAND(show_ebpf_classify_command, static) = {
    .path = "show ebpf classify",
    .short_help = "show ebpf classify",
    .function = show_ebpf_classify_command_fn,
};

// Plugin initialization
static clib_error_t *ebpf_classify_init(vlib_main_t *vm) {
    ebpf_classify_main_t *em = &ebpf_classify_main;
    clib_error_t *error = 0;
    
    em->vlib_main = vm;
    em->vnet_main = vnet_get_main();
    
    // Default configuration
    em->dual_protection_enabled = 1;
    em->stateful_mode = 1;
    em->session_timeout = 300; // 5 minutes
    
    // Initialize statistics
    memset(&em->stats, 0, sizeof(em->stats));
    
    // Load shared BPF maps
    if (load_bpf_maps(em) < 0) {
        clib_warning("Failed to load BPF maps - running in compatibility mode");
        em->dual_protection_enabled = 0;
    }
    
    clib_info("eBPF Classify plugin initialized");
    clib_info("  Version: %d.%d", 
              EBPF_CLASSIFY_PLUGIN_VERSION_MAJOR,
              EBPF_CLASSIFY_PLUGIN_VERSION_MINOR);
    clib_info("  Dual Protection: %s", 
              em->dual_protection_enabled ? "enabled" : "disabled");
    
    return error;
}

VLIB_INIT_FUNCTION(ebpf_classify_init);

// Plugin info
VLIB_PLUGIN_REGISTER() = {
    .version = VPP_BUILD_VER,
    .description = "eBPF Integration and Classification Plugin for Dual Protection",
    .default_disabled = 0,
}; 