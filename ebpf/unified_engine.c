/*
 * SPDX-License-Identifier: Apache-2.0
 * Cerberus-V Unified eBPF Engine
 * 
 * Single consolidated XDP program to replace ALL conflicting programs:
 * - xdp_filter.c
 * - xdp_filter_hardened.c  
 * - xdp_live_engine.c
 * - apt_antiscan.c
 * - firewall_engine.c
 * 
 * Author: Lethe (AI APT Engineer)
 * Elite APT-Grade Design: Zero conflicts, maximum efficiency
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

char _license[] SEC("license") = "GPL";

// ============================================================================
// CONFIGURATION MAPS (Centralized Control)
// ============================================================================

// Operation mode: 0=SIMULATION, 1=LIVE
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} mode_config SEC(".maps");

// Firewall rules (IP -> Action mapping)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // IP address
    __type(value, __u8);  // 0=DROP, 1=PASS, 2=REDIRECT
} firewall_rules SEC(".maps");

// Rate limiting (IP -> timestamp)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // Source IP
    __type(value, __u64); // Last seen timestamp
} rate_limit SEC(".maps");

// Statistics (per-CPU for performance)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Event logging (ring buffer for userspace)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB ring buffer
} events SEC(".maps");

// AF_XDP socket map for TCP redirect
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

// ============================================================================
// STATISTICS COUNTERS
// ============================================================================
enum stats_counters {
    STAT_PACKETS_TOTAL = 0,
    STAT_PACKETS_DROPPED = 1,
    STAT_PACKETS_PASSED = 2,
    STAT_PACKETS_REDIRECTED = 3,
    STAT_SYN_SCANS_DETECTED = 4,
    STAT_RATE_LIMITED = 5,
    STAT_ICMP_BLOCKED = 6,
    STAT_ERRORS = 7,
};

// ============================================================================
// EVENT LOGGING STRUCTURE
// ============================================================================
struct event_log {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;    // 0=DROP, 1=PASS, 2=REDIRECT
    __u8 reason;    // Reason code
    __u8 padding;
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static __always_inline void update_stats(__u32 counter) {
    __u64 *value = bpf_map_lookup_elem(&stats, &counter);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static __always_inline void log_event(__u32 src_ip, __u32 dst_ip, 
                                     __u16 src_port, __u16 dst_port,
                                     __u8 protocol, __u8 action, __u8 reason) {
    struct event_log *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->timestamp = bpf_ktime_get_ns();
        event->src_ip = src_ip;
        event->dst_ip = dst_ip;
        event->src_port = src_port;
        event->dst_port = dst_port;
        event->protocol = protocol;
        event->action = action;
        event->reason = reason;
        bpf_ringbuf_submit(event, 0);
    }
}

static __always_inline int check_rate_limit(__u32 src_ip) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&rate_limit, &src_ip);
    
    if (last_seen) {
        // Rate limit: 1 packet per second (1,000,000,000 ns)
        if (now - *last_seen < 1000000000) {
            return 1; // Rate limited
        }
    }
    
    // Update timestamp
    bpf_map_update_elem(&rate_limit, &src_ip, &now, BPF_ANY);
    return 0; // Not rate limited
}

static __always_inline int get_firewall_action(__u32 ip) {
    __u8 *action = bpf_map_lookup_elem(&firewall_rules, &ip);
    if (action) {
        return *action;
    }
    return 1; // Default: PASS
}

static __always_inline int is_live_mode(void) {
    __u32 key = 0;
    __u8 *mode = bpf_map_lookup_elem(&mode_config, &key);
    return mode ? *mode : 0; // Default: SIMULATION
}

// ============================================================================
// MAIN XDP PROGRAM
// ============================================================================

SEC("xdp")
int cerberus_unified_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    update_stats(STAT_PACKETS_TOTAL);
    
    // Basic packet validation
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stats(STAT_ERRORS);
        return XDP_ABORTED;
    }
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        update_stats(STAT_PACKETS_PASSED);
        return XDP_PASS;
    }
    
    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        update_stats(STAT_ERRORS);
        return XDP_ABORTED;
    }
    
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    
    // Rate limiting check
    if (check_rate_limit(src_ip)) {
        update_stats(STAT_RATE_LIMITED);
        log_event(src_ip, dst_ip, 0, 0, iph->protocol, 0, 1); // Reason: Rate limited
        if (is_live_mode()) {
            return XDP_DROP;
        }
        // In simulation mode, just log
    }
    
    // Firewall rules check
    int fw_action = get_firewall_action(src_ip);
    if (fw_action == 0) { // DROP
        update_stats(STAT_PACKETS_DROPPED);
        log_event(src_ip, dst_ip, 0, 0, iph->protocol, 0, 2); // Reason: Firewall rule
        if (is_live_mode()) {
            return XDP_DROP;
        }
    }
    
    // Protocol-specific processing
    if (iph->protocol == IPPROTO_ICMP) {
        // Block ICMP in live mode for DDoS protection
        update_stats(STAT_ICMP_BLOCKED);
        log_event(src_ip, dst_ip, 0, 0, IPPROTO_ICMP, 0, 3); // Reason: ICMP blocked
        if (is_live_mode()) {
            return XDP_DROP;
        }
    }
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph) + (iph->ihl << 2);
        if ((void *)(tcp + 1) > data_end) {
            update_stats(STAT_ERRORS);
            return XDP_ABORTED;
        }
        
        // SYN scan detection
        if (tcp->syn && !tcp->ack) {
            update_stats(STAT_SYN_SCANS_DETECTED);
            log_event(src_ip, dst_ip, bpf_ntohs(tcp->source), 
                     bpf_ntohs(tcp->dest), IPPROTO_TCP, 0, 4); // Reason: SYN scan
            
            if (is_live_mode()) {
                return XDP_DROP;
            }
        }
        
        // Redirect TCP to userspace for deep inspection (if configured)
        if (fw_action == 2) { // REDIRECT
            update_stats(STAT_PACKETS_REDIRECTED);
            log_event(src_ip, dst_ip, bpf_ntohs(tcp->source), 
                     bpf_ntohs(tcp->dest), IPPROTO_TCP, 2, 5); // Reason: Redirect to userspace
            return bpf_redirect_map(&xsk_map, 0, 0);
        }
    }
    
    // Default: PASS
    update_stats(STAT_PACKETS_PASSED);
    return XDP_PASS;
}

// ============================================================================
// PROGRAM METADATA
// ============================================================================

// Program version and capabilities
const volatile char version[] = "Cerberus-V Unified Engine v1.0.0";
const volatile __u32 features = 0x000001FF; // All features enabled