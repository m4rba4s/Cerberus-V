// SPDX-License-Identifier: Apache-2.0
// Author: vppebpf  Date: 2024-12-19
// XDP firewall: ICMP drop, TCP redirect to AF_XDP, others pass

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

// XSK map for AF_XDP socket redirection
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);  // Support multiple queues
} xsk_map SEC(".maps");

// Stats map for monitoring
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4);  // PASS, DROP, REDIRECT, ERROR
} stats_map SEC(".maps");

enum stats_key {
    STAT_PASS = 0,
    STAT_DROP = 1,
    STAT_REDIRECT = 2,
    STAT_ERROR = 3,
};

static __always_inline void update_stats(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&stats_map, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

/*
 * This is the main XDP program. It is attached to the XDP hook and
 * will be executed for each incoming packet.
 */
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 queue_id = 0;  // Default queue

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stats(STAT_ERROR);
        return XDP_ABORTED;
    }

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        update_stats(STAT_PASS);
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        update_stats(STAT_ERROR);
        return XDP_ABORTED;
    }

    // Drop ICMP packets (DDoS protection)
    if (ip->protocol == IPPROTO_ICMP) {
        update_stats(STAT_DROP);
        return XDP_DROP;
    }

    // Redirect TCP packets to userspace via AF_XDP
    if (ip->protocol == IPPROTO_TCP) {
        update_stats(STAT_REDIRECT);
        return bpf_redirect_map(&xsk_map, queue_id, 0);
    }

    // Pass all other traffic (UDP, etc.)
    update_stats(STAT_PASS);
    return XDP_PASS;
} 