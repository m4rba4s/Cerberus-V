/*
 * SPDX-License-Identifier: Apache-2.0
 * Author: funcybot@gmail.com  Date: 2025-06-26
 * Cerberus-V VPP Hello ACL Plugin - Minimal packet inspection with syslog
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <syslog.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    
    /* Per-interface enable/disable */
    u8 *is_enabled;
    
    /* Packet counters */
    u64 packets_processed;
    u64 packets_allowed;
    u64 packets_logged;
    
    /* VPP API */
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;
} hello_acl_main_t;

hello_acl_main_t hello_acl_main;

/* Node error codes */
#define foreach_hello_acl_error \
_(PROCESSED, "Packets processed") \
_(ALLOWED, "Packets allowed") \
_(LOGGED, "Packets logged")

typedef enum {
#define _(sym,str) HELLO_ACL_ERROR_##sym,
    foreach_hello_acl_error
#undef _
    HELLO_ACL_N_ERROR,
} hello_acl_error_t;

static char *hello_acl_error_strings[] = {
#define _(sym,string) string,
    foreach_hello_acl_error
#undef _
};

/* Next nodes */
typedef enum {
    HELLO_ACL_NEXT_INTERFACE_OUTPUT,
    HELLO_ACL_NEXT_DROP,
    HELLO_ACL_N_NEXT,
} hello_acl_next_t;

/* Packet trace structure */
typedef struct {
    u32 sw_if_index;
    u32 next_index;
    u8 is_ipv4;
    u32 src_addr;
    u32 dst_addr;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
} hello_acl_trace_t;

/* Packet trace format function */
static u8 * format_hello_acl_trace(u8 * s, va_list * args)
{
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    hello_acl_trace_t *t = va_arg(*args, hello_acl_trace_t *);
    
    s = format(s, "HELLO_ACL: sw_if_index %d, next index %d, "
              "IPv4: %d.%d.%d.%d -> %d.%d.%d.%d, "
              "ports: %d -> %d, protocol: %d",
              t->sw_if_index, t->next_index,
              (t->src_addr >> 24) & 0xff, (t->src_addr >> 16) & 0xff,
              (t->src_addr >> 8) & 0xff, t->src_addr & 0xff,
              (t->dst_addr >> 24) & 0xff, (t->dst_addr >> 16) & 0xff,
              (t->dst_addr >> 8) & 0xff, t->dst_addr & 0xff,
              t->src_port, t->dst_port, t->protocol);
    
    return s;
}

/* Main packet processing function */
static uword hello_acl_inline(vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame,
                              int is_ip6)
{
    hello_acl_main_t *hm = &hello_acl_main;
    u32 n_left_from, *from, *to_next;
    hello_acl_next_t next_index;
    u32 pkts_processed = 0, pkts_allowed = 0, pkts_logged = 0;
    
    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;
    
    while (n_left_from > 0) {
        u32 n_left_to_next;
        
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
        
        while (n_left_from > 0 && n_left_to_next > 0) {
            u32 bi0;
            vlib_buffer_t *b0;
            u32 next0 = HELLO_ACL_NEXT_INTERFACE_OUTPUT;
            u32 sw_if_index0;
            ip4_header_t *ip0 = 0;
            tcp_header_t *tcp0 = 0;
            udp_header_t *udp0 = 0;
            
            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;
            
            b0 = vlib_get_buffer(vm, bi0);
            sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
            
            /* Check if this interface is enabled */
            if (vec_len(hm->is_enabled) <= sw_if_index0 ||
                !hm->is_enabled[sw_if_index0]) {
                goto skip_processing;
            }
            
            /* Get IP header */
            if (!is_ip6) {
                ip0 = vlib_buffer_get_current(b0);
                
                /* Basic IPv4 header validation */
                if (ip0->ip_version_and_header_length != 0x45) {
                    goto skip_processing;
                }
                
                /* Get transport header */
                u8 *payload = (u8 *)ip0 + sizeof(ip4_header_t);
                
                if (ip0->protocol == IP_PROTOCOL_TCP) {
                    tcp0 = (tcp_header_t *)payload;
                } else if (ip0->protocol == IP_PROTOCOL_UDP) {
                    udp0 = (udp_header_t *)payload;
                }
                
                /* Log interesting packets to syslog */
                if (ip0->protocol == IP_PROTOCOL_ICMP ||
                    (tcp0 && (clib_net_to_host_u16(tcp0->dst_port) == 22 ||
                             clib_net_to_host_u16(tcp0->dst_port) == 80 ||
                             clib_net_to_host_u16(tcp0->dst_port) == 443))) {
                    
                    char log_msg[256];
                    snprintf(log_msg, sizeof(log_msg),
                            "Cerberus-V: %s packet %d.%d.%d.%d -> %d.%d.%d.%d, proto=%d",
                            ip0->protocol == IP_PROTOCOL_ICMP ? "ICMP" : "TCP",
                            (ip0->src_address.as_u32 >> 24) & 0xff,
                            (ip0->src_address.as_u32 >> 16) & 0xff,
                            (ip0->src_address.as_u32 >> 8) & 0xff,
                            ip0->src_address.as_u32 & 0xff,
                            (ip0->dst_address.as_u32 >> 24) & 0xff,
                            (ip0->dst_address.as_u32 >> 16) & 0xff,
                            (ip0->dst_address.as_u32 >> 8) & 0xff,
                            ip0->dst_address.as_u32 & 0xff,
                            ip0->protocol);
                    
                    syslog(LOG_INFO, "%s", log_msg);
                    pkts_logged++;
                }
            }
            
            skip_processing:
            pkts_processed++;
            pkts_allowed++;
            
            /* Add trace if requested */
            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) &&
                             (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                hello_acl_trace_t *t = vlib_add_trace(vm, node, b0, sizeof(*t));
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                if (ip0) {
                    t->is_ipv4 = 1;
                    t->src_addr = ip0->src_address.as_u32;
                    t->dst_addr = ip0->dst_address.as_u32;
                    t->protocol = ip0->protocol;
                    if (tcp0) {
                        t->src_port = clib_net_to_host_u16(tcp0->src_port);
                        t->dst_port = clib_net_to_host_u16(tcp0->dst_port);
                    } else if (udp0) {
                        t->src_port = clib_net_to_host_u16(udp0->src_port);
                        t->dst_port = clib_net_to_host_u16(udp0->dst_port);
                    }
                }
            }
            
            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }
        
        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }
    
    /* Update counters */
    vlib_node_increment_counter(vm, node->node_index,
                               HELLO_ACL_ERROR_PROCESSED, pkts_processed);
    vlib_node_increment_counter(vm, node->node_index,
                               HELLO_ACL_ERROR_ALLOWED, pkts_allowed);
    vlib_node_increment_counter(vm, node->node_index,
                               HELLO_ACL_ERROR_LOGGED, pkts_logged);
    
    hm->packets_processed += pkts_processed;
    hm->packets_allowed += pkts_allowed;
    hm->packets_logged += pkts_logged;
    
    return frame->n_vectors;
}

VLIB_NODE_FN(hello_acl_node) (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return hello_acl_inline(vm, node, frame, 0 /* is_ip6 */);
}

/* Node registration */
VLIB_REGISTER_NODE(hello_acl_node) = {
    .name = "hello-acl",
    .vector_size = sizeof(u32),
    .format_trace = format_hello_acl_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    
    .n_errors = ARRAY_LEN(hello_acl_error_strings),
    .error_strings = hello_acl_error_strings,
    
    .n_next_nodes = HELLO_ACL_N_NEXT,
    .next_nodes = {
        [HELLO_ACL_NEXT_INTERFACE_OUTPUT] = "interface-output",
        [HELLO_ACL_NEXT_DROP] = "error-drop",
    },
};

/* CLI command to enable/disable per interface */
static clib_error_t *
hello_acl_enable_disable_command_fn(vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
{
    hello_acl_main_t *hm = &hello_acl_main;
    u32 sw_if_index = ~0;
    int enable_disable = 1;
    
    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(input, "%U", unformat_vnet_sw_interface,
                    hm->vnet_main, &sw_if_index))
            ;
        else if (unformat(input, "disable"))
            enable_disable = 0;
        else
            break;
    }
    
    if (sw_if_index == ~0)
        return clib_error_return(0, "Please specify an interface...");
    
    /* Extend enable/disable vector */
    vec_validate_init_empty(hm->is_enabled, sw_if_index, 0);
    hm->is_enabled[sw_if_index] = enable_disable;
    
    /* Connect to IP4 feature arc */
    vnet_feature_enable_disable("ip4-unicast", "hello-acl",
                               sw_if_index, enable_disable, 0, 0);
    
    vlib_cli_output(vm, "hello-acl %s on %U",
                   enable_disable ? "enabled" : "disabled",
                   format_vnet_sw_if_index_name,
                   hm->vnet_main, sw_if_index);
    
    return 0;
}

/* CLI command registration */
VLIB_CLI_COMMAND(hello_acl_enable_disable_command, static) = {
    .path = "hello-acl",
    .short_help = "hello-acl <interface-name> [disable]",
    .function = hello_acl_enable_disable_command_fn,
};

/* CLI command to show statistics */
static clib_error_t *
hello_acl_show_command_fn(vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
    hello_acl_main_t *hm = &hello_acl_main;
    
    vlib_cli_output(vm, "Hello ACL Statistics:");
    vlib_cli_output(vm, "  Packets processed: %llu", hm->packets_processed);
    vlib_cli_output(vm, "  Packets allowed:   %llu", hm->packets_allowed);
    vlib_cli_output(vm, "  Packets logged:    %llu", hm->packets_logged);
    
    return 0;
}

VLIB_CLI_COMMAND(hello_acl_show_command, static) = {
    .path = "show hello-acl",
    .short_help = "show hello-acl",
    .function = hello_acl_show_command_fn,
};

/* Feature registration */
VNET_FEATURE_INIT(hello_acl, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "hello-acl",
    .runs_before = VNET_FEATURES("ip4-lookup"),
};

/* Plugin registration */
VLIB_PLUGIN_REGISTER() = {
    .version = "1.0.0",
    .description = "Cerberus-V Hello ACL Plugin",
};

/* Init function */
static clib_error_t * hello_acl_init(vlib_main_t * vm)
{
    hello_acl_main_t *hm = &hello_acl_main;
    clib_error_t *error = 0;
    
    hm->vlib_main = vm;
    hm->vnet_main = vnet_get_main();
    
    /* Initialize syslog */
    openlog("vpp-hello-acl", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    
    /* Log plugin initialization */
    syslog(LOG_INFO, "Cerberus-V Hello ACL plugin initialized");
    
    return error;
}

VLIB_INIT_FUNCTION(hello_acl_init); 