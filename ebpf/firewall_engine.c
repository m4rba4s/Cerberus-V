// SPDX-License-Identifier: Apache-2.0
// Cerberus-V eBPF Firewall Engine
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
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end)
            return 0;
        return bpf_ntohs(tcp->source);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end)
            return 0;
        return bpf_ntohs(udp->source);
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
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end)
            return 0;
        return bpf_ntohs(tcp->dest);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end)
            return 0;
        return bpf_ntohs(udp->dest);
    }
    
    return 0;
}

static __always_inline void update_stats(__u32 action, __u32 packet_size) {
    __u32 key = 0;
    struct firewall_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats)
        return;
    
    stats->packets_processed++;
    stats->bytes_processed += packet_size;
    stats->rules_checked++;
    
    if (action == 0) {  // drop
        stats->packets_dropped++;
    } else {  // allow
        stats->packets_allowed++;
    }
}

static __always_inline __u8 check_blacklist(__u32 ip) {
    __u64 key = (__u64)ip << 32;
    __u8 *action = bpf_map_lookup_elem(&blacklist, &key);
    return action ? *action : 0;
}

static __always_inline __u8 check_whitelist(__u32 ip) {
    __u64 key = (__u64)ip << 32;
    __u8 *action = bpf_map_lookup_elem(&whitelist, &key);
    return action ? *action : 1;
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

static __always_inline void update_session(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol, __u8 state) {
    __u64 key = ((__u64)src_ip << 32) | dst_ip;
    struct session_entry session = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol,
        .timestamp = bpf_ktime_get_ns() / 1000000000,  // Convert to seconds
        .state = state
    };
    bpf_map_update_elem(&session_table, &key, &session, BPF_ANY);
}

static __always_inline __u8 evaluate_rules(__u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 protocol) {
    struct firewall_rule *rule;
    __u32 key = 0;
    
    // Check blacklist first (highest priority)
    if (check_blacklist(src_ip) || check_blacklist(dst_ip)) {
        return 0;  // drop
    }
    
    // Check whitelist
    if (check_whitelist(src_ip) && check_whitelist(dst_ip)) {
        return 1;  // allow
    }
    
    // Check session table for established connections
    __u8 session_state = check_session(src_ip, dst_ip, src_port, dst_port, protocol);
    if (session_state == 1) {  // established
        return 1;  // allow
    }
    
    // Evaluate firewall rules
    while (bpf_map_get_next_key(&firewall_rules, &key, &key) == 0) {
        rule = bpf_map_lookup_elem(&firewall_rules, &key);
        if (!rule || !rule->enabled)
            continue;
        
        // Check protocol
        if (rule->protocol != 0 && rule->protocol != protocol)
            continue;
        
        // Check IP addresses
        if (rule->src_ip != 0 && rule->src_ip != src_ip)
            continue;
        if (rule->dst_ip != 0 && rule->dst_ip != dst_ip)
            continue;
        
        // Check ports (only for TCP/UDP)
        if ((protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)) {
            if (rule->src_port != 0 && rule->src_port != src_port)
                continue;
            if (rule->dst_port != 0 && rule->dst_port != dst_port)
                continue;
        }
        
        // Rule matched
        rule->hit_count++;
        
        // Update session for TCP connections
        if (protocol == IPPROTO_TCP && rule->action == 1) {
            update_session(src_ip, dst_ip, src_port, dst_port, protocol, 1);
        }
        
        return rule->action;
    }
    
    // Default action: drop
    return 0;
}

SEC("xdp")
int firewall_filter(struct xdp_md *ctx) {
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
    
    // Return action
    if (action == 0) {
        return XDP_DROP;
    } else {
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "Apache-2.0"; 