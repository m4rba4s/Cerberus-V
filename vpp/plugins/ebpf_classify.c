// SPDX-License-Identifier: Apache-2.0
// Author: funcybot@gmail.com  Date: 2025-06-26
// VPP eBPF Classification Plugin - Stateful packet inspection

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

// Plugin registration
VLIB_PLUGIN_REGISTER() = {
    .version = VPP_BUILD_VER,
    .description = "eBPF Classification and Stateful Inspection",
};

// Error strings
char *ebpf_classify_error_strings[] = {
    "Packets processed",
    "Packets dropped",
    "Malware detected",
    "Geo-blocked",
};

typedef enum {
    EBPF_CLASSIFY_ERROR_PROCESSED,
    EBPF_CLASSIFY_ERROR_DROPPED,
    EBPF_CLASSIFY_ERROR_MALWARE,
    EBPF_CLASSIFY_ERROR_GEOBLOCKED,
    EBPF_CLASSIFY_N_ERROR,
} ebpf_classify_error_t;

typedef enum {
    EBPF_CLASSIFY_NEXT_PASS,
    EBPF_CLASSIFY_NEXT_DROP,
    EBPF_CLASSIFY_N_NEXT,
} ebpf_classify_next_t;

typedef struct {
    u32 sw_if_index;
    u32 next_index;
    u32 reason;
} ebpf_classify_trace_t;

// Per-interface configuration
typedef struct {
    u32 enabled;
    u32 drop_count;
    u32 pass_count;
    u32 redirect_count;
} ebpf_classify_interface_t;

// Main plugin state
typedef struct {
    u16 msg_id_base;
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;
    
    // Per-interface state
    ebpf_classify_interface_t *interfaces;
    
    // Global counters
    u64 total_packets;
    u64 total_drops;
    u64 total_bytes;
    
    // Configuration
    u32 tcp_timeout;
    u32 udp_timeout;
    bool geo_blocking_enabled;
} ebpf_classify_main_t;

ebpf_classify_main_t ebpf_classify_main;

// Connection tracking entry
typedef struct {
    ip4_address_t src_ip;
    ip4_address_t dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u32 last_seen;
    u32 bytes_tx;
    u32 bytes_rx;
    u8 state; // 0=NEW, 1=ESTABLISHED, 2=CLOSING
} connection_entry_t;

// Simple hash table for connection tracking
#define CONN_TABLE_SIZE 65536
static connection_entry_t connection_table[CONN_TABLE_SIZE];

// Hash function for connection lookup
static u32 connection_hash(ip4_address_t *src, ip4_address_t *dst, u16 sport, u16 dport, u8 proto) {
    u32 hash = src->as_u32 ^ dst->as_u32 ^ (sport << 16 | dport) ^ proto;
    return hash % CONN_TABLE_SIZE;
}

// Packet classification function
static inline int classify_packet(vlib_buffer_t *b0, u32 *reason) {
    ip4_header_t *ip0 = vlib_buffer_get_current(b0);
    
    // Basic validation
    if (ip0->ip_version_and_header_length != 0x45) {
        *reason = 1; // Invalid IP header
        return 0; // DROP
    }
    
    // Check for suspicious source IPs (basic geo-blocking simulation)
    u32 src_addr = clib_net_to_host_u32(ip0->src_address.as_u32);
    
    // Block RFC1918 private addresses from external interfaces (example)
    if ((src_addr & 0xFF000000) == 0x0A000000 ||  // 10.0.0.0/8
        (src_addr & 0xFFF00000) == 0xAC100000 ||  // 172.16.0.0/12
        (src_addr & 0xFFFF0000) == 0xC0A80000) {  // 192.168.0.0/16
        // In real implementation, check if this is from external interface
        // For demo, we pass these
    }
    
    // Connection tracking
    if (ip0->protocol == IP_PROTOCOL_TCP || ip0->protocol == IP_PROTOCOL_UDP) {
        udp_header_t *udp0 = ip4_next_header(ip0);
        u32 hash = connection_hash(&ip0->src_address, &ip0->dst_address,
                                  udp0->src_port, udp0->dst_port, ip0->protocol);
        
        connection_entry_t *conn = &connection_table[hash];
        u32 now = vlib_time_now(vlib_get_main());
        
        // Update or create connection entry
        if (conn->src_ip.as_u32 == 0 || 
            (now - conn->last_seen) > 300) { // 5 min timeout
            // New connection
            conn->src_ip = ip0->src_address;
            conn->dst_ip = ip0->dst_address;
            conn->src_port = udp0->src_port;
            conn->dst_port = udp0->dst_port;
            conn->protocol = ip0->protocol;
            conn->state = 0; // NEW
            conn->bytes_tx = vlib_buffer_length_in_chain(vlib_get_main(), b0);
            conn->bytes_rx = 0;
        } else {
            // Existing connection
            conn->bytes_rx += vlib_buffer_length_in_chain(vlib_get_main(), b0);
        }
        conn->last_seen = now;
    }
    
    *reason = 0; // NORMAL_TRAFFIC
    return 1; // PASS
}

// Trace format function
static u8 *format_ebpf_classify_trace(u8 *s, va_list *args) {
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    ebpf_classify_trace_t *t = va_arg(*args, ebpf_classify_trace_t *);
    
    s = format(s, "EBPF_CLASSIFY: sw_if_index %d, next index %d, reason %d",
               t->sw_if_index, t->next_index, t->reason);
    return s;
}

// Main packet processing node
VLIB_NODE_FN(ebpf_classify_node) (vlib_main_t *vm,
                                 vlib_node_runtime_t *node,
                                 vlib_frame_t *from_frame) {
    u32 n_left_from, *from, *to_next;
    ebpf_classify_next_t next_index;
    ebpf_classify_main_t *ecm = &ebpf_classify_main;
    u32 pkts_processed = 0;
    u32 pkts_dropped = 0;
    
    from = vlib_frame_vector_args(from_frame);
    n_left_from = from_frame->n_vectors;
    next_index = node->cached_next_index;
    
    while (n_left_from > 0) {
        u32 n_left_to_next;
        
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
        
        while (n_left_from > 0 && n_left_to_next > 0) {
            u32 bi0;
            vlib_buffer_t *b0;
            u32 next0 = EBPF_CLASSIFY_NEXT_PASS;
            u32 sw_if_index0;
            u32 reason = 0;
            
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;
            
            b0 = vlib_get_buffer(vm, bi0);
            sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
            
            // Classify the packet
            if (!classify_packet(b0, &reason)) {
                next0 = EBPF_CLASSIFY_NEXT_DROP;
                pkts_dropped++;
                
                // Update interface stats
                if (sw_if_index0 < vec_len(ecm->interfaces)) {
                    ecm->interfaces[sw_if_index0].drop_count++;
                }
                
                ecm->total_drops++;
            } else {
                // Update interface stats
                if (sw_if_index0 < vec_len(ecm->interfaces)) {
                    ecm->interfaces[sw_if_index0].pass_count++;
                }
            }
            
            pkts_processed++;
            ecm->total_packets++;
            ecm->total_bytes += vlib_buffer_length_in_chain(vm, b0);
            
            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) &&
                             (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                ebpf_classify_trace_t *t = vlib_add_trace(vm, node, b0, sizeof(*t));
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                t->reason = reason;
            }
            
            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }
        
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }
    
    vlib_node_increment_counter(vm, ebpf_classify_node.index,
                               EBPF_CLASSIFY_ERROR_PROCESSED, pkts_processed);
    vlib_node_increment_counter(vm, ebpf_classify_node.index,
                               EBPF_CLASSIFY_ERROR_DROPPED, pkts_dropped);
    
    return from_frame->n_vectors;
}

// Node registration
VLIB_REGISTER_NODE(ebpf_classify_node) = {
    .name = "ebpf-classify",
    .vector_size = sizeof(u32),
    .format_trace = format_ebpf_classify_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    
    .n_errors = ARRAY_LEN(ebpf_classify_error_strings),
    .error_strings = ebpf_classify_error_strings,
    
    .n_next_nodes = EBPF_CLASSIFY_N_NEXT,
    .next_nodes = {
        [EBPF_CLASSIFY_NEXT_PASS] = "ip4-lookup",
        [EBPF_CLASSIFY_NEXT_DROP] = "error-drop",
    },
};

// CLI commands
static clib_error_t *
ebpf_classify_enable_disable_command_fn(vlib_main_t *vm,
                                       unformat_input_t *input,
                                       vlib_cli_command_t *cmd) {
    ebpf_classify_main_t *ecm = &ebpf_classify_main;
    u32 sw_if_index = ~0;
    u8 enable = 1;
    
    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "%U", unformat_vnet_sw_interface,
                    ecm->vnet_main, &sw_if_index))
            ;
        else if (unformat(input, "disable"))
            enable = 0;
        else
            break;
    }
    
    if (sw_if_index == ~0)
        return clib_error_return(0, "Please specify an interface...");
    
    // Enable/disable classification on interface
    vec_validate_init_empty(ecm->interfaces, sw_if_index, 
                           (ebpf_classify_interface_t){0});
    ecm->interfaces[sw_if_index].enabled = enable;
    
    vlib_cli_output(vm, "eBPF classification %s on sw_if_index %d",
                   enable ? "enabled" : "disabled", sw_if_index);
    
    return 0;
}

VLIB_CLI_COMMAND(ebpf_classify_enable_disable_command, static) = {
    .path = "ebpf classify",
    .short_help = "ebpf classify <interface> [disable]",
    .function = ebpf_classify_enable_disable_command_fn,
};

// Show statistics command
static clib_error_t *
ebpf_classify_show_command_fn(vlib_main_t *vm,
                             unformat_input_t *input,
                             vlib_cli_command_t *cmd) {
    ebpf_classify_main_t *ecm = &ebpf_classify_main;
    
    vlib_cli_output(vm, "eBPF Classification Statistics:");
    vlib_cli_output(vm, "  Total packets: %llu", ecm->total_packets);
    vlib_cli_output(vm, "  Total drops: %llu", ecm->total_drops);
    vlib_cli_output(vm, "  Total bytes: %llu", ecm->total_bytes);
    vlib_cli_output(vm, "  Drop rate: %.2f%%", 
                   ecm->total_packets ? 
                   (100.0 * ecm->total_drops / ecm->total_packets) : 0.0);
    
    // Show per-interface stats
    for (int i = 0; i < vec_len(ecm->interfaces); i++) {
        if (ecm->interfaces[i].enabled) {
            vlib_cli_output(vm, "  Interface %d: pass=%u drop=%u redirect=%u",
                           i, ecm->interfaces[i].pass_count,
                           ecm->interfaces[i].drop_count,
                           ecm->interfaces[i].redirect_count);
        }
    }
    
    return 0;
}

VLIB_CLI_COMMAND(ebpf_classify_show_command, static) = {
    .path = "show ebpf classify",
    .short_help = "show ebpf classify",
    .function = ebpf_classify_show_command_fn,
};

// Plugin initialization
static clib_error_t *ebpf_classify_init(vlib_main_t *vm) {
    ebpf_classify_main_t *ecm = &ebpf_classify_main;
    
    ecm->vlib_main = vm;
    ecm->vnet_main = vnet_get_main();
    
    // Initialize default values
    ecm->tcp_timeout = 300; // 5 minutes
    ecm->udp_timeout = 60;  // 1 minute
    ecm->geo_blocking_enabled = false;
    
    // Clear connection table
    memset(connection_table, 0, sizeof(connection_table));
    
    return 0;
}

VLIB_INIT_FUNCTION(ebpf_classify_init); 