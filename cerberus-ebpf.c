/*
 * Cerberus-V2: eBPF XDP Program
 * Elite APT-Grade Packet Filtering
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

// Configuration
#define MAX_RULES 1024
#define RING_SIZE (1 << 16)
#define RATE_LIMIT 1000
#define RATE_WINDOW 1000000  // 1 second in microseconds

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // source IP
    __type(value, __u64); // timestamp
} rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);   // destination IP
    __type(value, __u8);  // action (0=drop, 1=allow)
} rules SEC(".maps");

// Event structure
struct event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;
    __u64 timestamp;
};

// XDP Program
SEC("xdp")
int cerberus_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Basic packet validation
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return XDP_PASS;
    
    if (iph->version != 4)
        return XDP_PASS;
    
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u64 now = bpf_ktime_get_ns();
    
    // Rate limiting
    __u64 *last_seen = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (last_seen) {
        if (now - *last_seen < RATE_WINDOW * 1000ULL) {
            return XDP_DROP;
        }
    }
    bpf_map_update_elem(&rate_limit, &src_ip, &now, BPF_ANY);
    
    // Rule lookup
    __u8 *action = bpf_map_lookup_elem(&rules, &dst_ip);
    if (action && *action == 0) {
        return XDP_DROP;
    }
    
    // Scan detection
    if (iph->protocol == IPPROTO_TCP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
            
        struct tcphdr *tcp = data + sizeof(*eth) + (iph->ihl << 2);
        
        // SYN scan detection
        if (tcp->syn && !tcp->ack) {
            struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (evt) {
                evt->src_ip = src_ip;
                evt->dst_ip = dst_ip;
                evt->src_port = bpf_ntohs(tcp->source);
                evt->dst_port = bpf_ntohs(tcp->dest);
                evt->protocol = IPPROTO_TCP;
                evt->action = 0;
                evt->timestamp = now;
                bpf_ringbuf_submit(evt, 0);
            }
            return XDP_DROP;
        }
    }
    
    // ICMP scan detection
    if (iph->protocol == IPPROTO_ICMP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct icmphdr) > data_end)
            return XDP_PASS;
            
        struct icmphdr *icmp = data + sizeof(*eth) + (iph->ihl << 2);
        
        if (icmp->type == ICMP_ECHO) {
            struct event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (evt) {
                evt->src_ip = src_ip;
                evt->dst_ip = dst_ip;
                evt->src_port = 0;
                evt->dst_port = 0;
                evt->protocol = IPPROTO_ICMP;
                evt->action = 0;
                evt->timestamp = now;
                bpf_ringbuf_submit(evt, 0);
            }
            return XDP_DROP;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 