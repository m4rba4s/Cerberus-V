// SPDX-License-Identifier: Apache-2.0
// Cerberus-V LIVE Mode XDP Engine
// Elite-Mode APT-Grade Packet Processing

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/if_xdp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "live_shadow.h"

// Firewall rule structure
struct firewall_rule {
    __u32 id;
    __u8 action;        // 0=drop, 1=allow, 2=log
    __u8 protocol;      // 0=any, 6=tcp, 17=udp, 1=icmp
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 enabled;
    __u8 priority;
    __u32 hit_count;
    __u8 live_safe;     // Safe for live mode
};

// Statistics structure
struct firewall_stats {
    __u64 packets_processed;
    __u64 packets_dropped;
    __u64 packets_allowed;
    __u64 bytes_processed;
    __u64 rules_checked;
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 live_drops;   // Drops in live mode
    __u64 live_allows;  // Allows in live mode
};

// Session tracking structure
struct session_entry {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 timestamp;
    __u8 state;         // 0=new, 1=established, 2=closing
    __u8 live_verified; // Verified in live mode
};

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct firewall_rule);
} firewall_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);
    __type(value, struct session_entry);
} session_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct firewall_stats);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000);
    __type(key, __u64);
    __type(value, __u8);
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1000);
    __type(key, __u64);
    __type(value, __u8);
} whitelist SEC(".maps");

// Helper functions
static __always_inline __u32 get_src_ip(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;
    
    return iph->saddr;
}

static __always_inline __u32 get_dst_ip(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;
    
    return iph->daddr;
}

static __always_inline __u8 get_protocol(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;
    
    return iph->protocol;
}

static __always_inline __u16 get_src_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return 0;
        return bpf_ntohs(tcph->source);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return 0;
        return bpf_ntohs(udph->source);
    }
    return 0;
}

static __always_inline __u16 get_dst_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return 0;
    
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return 0;
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return 0;
        return bpf_ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return 0;
        return bpf_ntohs(udph->dest);
    }
    return 0;
}

static __always_inline void update_stats(__u8 action, __u32 bytes) {
    __u32 key = 0;
    struct firewall_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        stats->packets_processed++;
        stats->bytes_processed += bytes;
        if (action == 0) {
            stats->packets_dropped++;
            if (is_live_mode()) {
                stats->live_drops++;
            }
        } else {
            stats->packets_allowed++;
            if (is_live_mode()) {
                stats->live_allows++;
            }
        }
    }
}

static __always_inline __u8 check_blacklist(__u32 ip) {
    __u64 key = (__u64)ip << 32;
    __u8 *value = bpf_map_lookup_elem(&blacklist, &key);
    return value ? *value : 0;
}

static __always_inline __u8 check_whitelist(__u32 ip) {
    __u64 key = (__u64)ip << 32;
    __u8 *value = bpf_map_lookup_elem(&whitelist, &key);
    return value ? *value : 0;
}

static __always_inline __u8 check_session(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol) {
    __u64 key = ((__u64)src_ip << 32) | dst_ip;
    struct session_entry *session = bpf_map_lookup_elem(&session_table, &key);
    if (session && session->protocol == protocol && 
        session->src_port == src_port && session->dst_port == dst_port) {
        return session->state;
    }
    return 0;
}

static __always_inline void update_session(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol) {
    __u64 key = ((__u64)src_ip << 32) | dst_ip;
    struct session_entry session = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
        .timestamp = bpf_ktime_get_ns() / 1000000,
        .state = 1,
        .live_verified = is_live_mode() ? 1 : 0
    };
    bpf_map_update_elem(&session_table, &key, &session, BPF_ANY);
}

static __always_inline __u8 evaluate_rules(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol) {
    __u8 action = 1; // Default: allow
    __u8 live_mode = is_live_mode();
    
    // Check blacklist first
    if (check_blacklist(src_ip) || check_blacklist(dst_ip)) {
        return 0; // Drop
    }
    
    // Check whitelist
    if (check_whitelist(src_ip) || check_whitelist(dst_ip)) {
        return 1; // Allow
    }
    
    // Rate limiting in live mode
    if (live_mode && !check_rate_limit(src_ip)) {
        return 0; // Rate limited
    }
    
    // Check session cache
    if (check_session(src_ip, dst_ip, src_port, dst_port, protocol)) {
        return 1; // Allow established sessions
    }
    
    // Evaluate firewall rules (manual iteration for compatibility)
    __u32 rule_id = 0;
    struct firewall_rule *rule;
    
    // Try first few rules (simplified for compatibility)
    for (int i = 0; i < 10; i++) {
        rule = bpf_map_lookup_elem(&firewall_rules, &rule_id);
        if (!rule) {
            rule_id++;
            continue;
        }
        
        if (!rule->enabled) {
            rule_id++;
            continue;
        }
        
        // In live mode, only apply safe rules
        if (live_mode && !rule->live_safe) {
            rule_id++;
            continue;
        }
            
        // Protocol match
        if (rule->protocol != 0 && rule->protocol != protocol) {
            rule_id++;
            continue;
        }
            
        // IP match
        if (rule->src_ip != 0 && rule->src_ip != src_ip) {
            rule_id++;
            continue;
        }
        if (rule->dst_ip != 0 && rule->dst_ip != dst_ip) {
            rule_id++;
            continue;
        }
            
        // Port match (for TCP/UDP)
        if ((protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)) {
            if (rule->src_port != 0 && rule->src_port != src_port) {
                rule_id++;
                continue;
            }
            if (rule->dst_port != 0 && rule->dst_port != dst_port) {
                rule_id++;
                continue;
            }
        }
        
        // Rule matched
        action = rule->action;
        rule->hit_count++;
        
        // Update session for allowed connections
        if (action == 1) {
            update_session(src_ip, dst_ip, src_port, dst_port, protocol);
        }
        
        break;
    }
    
    return action;
}

// Main XDP program
SEC("xdp")
int live_firewall_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Basic packet validation
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Extract packet information
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u8 protocol = iph->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        src_port = get_src_port(ctx);
        dst_port = get_dst_port(ctx);
    }

    // Evaluate firewall rules
    __u8 action = evaluate_rules(src_ip, dst_ip, src_port, dst_port, protocol);

    // Update statistics
    update_stats(action, data_end - data);
    
    // Update live mode statistics
    update_live_stats(action);

    // Return action
    if (action == 0) {
        return XDP_DROP;
    } else {
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "Apache-2.0"; 