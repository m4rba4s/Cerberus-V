/*
 * Cerberus-V: TC-BPF Firewall Fallback
 * Elite APT-Grade Packet Filtering for Wi-Fi
 * Compatible with interfaces that don't support XDP
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
#include <linux/pkt_cls.h>

// Simplified maps for compatibility
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} rules SEC(".maps");

// TC Program (ingress filter)
SEC("tc")
int tc_firewall(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Basic packet validation
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_OK;
    
    if (iph->version != 4)
        return TC_ACT_OK;
    
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u64 now = bpf_ktime_get_ns();
    
    // Rate limiting (1 packet per second per IP)
    __u64 *last_seen = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (last_seen) {
        if (now - *last_seen < 1000000000ULL) { // 1 second in nanoseconds
            return TC_ACT_SHOT;
        }
    }
    bpf_map_update_elem(&rate_limit, &src_ip, &now, BPF_ANY);
    
    // Rule lookup
    __u8 *action = bpf_map_lookup_elem(&rules, &dst_ip);
    if (action && *action == 0) {
        return TC_ACT_SHOT;
    }
    
    // TCP scan detection
    if (iph->protocol == IPPROTO_TCP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct tcphdr) > data_end)
            return TC_ACT_OK;
            
        struct tcphdr *tcp = data + sizeof(*eth) + (iph->ihl << 2);
        
        // SYN scan detection
        if (tcp->syn && !tcp->ack) {
            return TC_ACT_SHOT;
        }
        
        // NULL scan detection
        if (!tcp->syn && !tcp->ack && !tcp->rst && !tcp->fin && !tcp->psh && !tcp->urg) {
            return TC_ACT_SHOT;
        }
    }
    
    // ICMP scan detection
    if (iph->protocol == IPPROTO_ICMP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct icmphdr) > data_end)
            return TC_ACT_OK;
            
        struct icmphdr *icmp = data + sizeof(*eth) + (iph->ihl << 2);
        
        // ICMP echo (ping) detection
        if (icmp->type == ICMP_ECHO) {
            return TC_ACT_SHOT;
        }
    }
    
    // UDP scan detection
    if (iph->protocol == IPPROTO_UDP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct udphdr) > data_end)
            return TC_ACT_OK;
            
        struct udphdr *udp = data + sizeof(*eth) + (iph->ihl << 2);
        
        // Common UDP scan ports
        __u16 dst_port = bpf_ntohs(udp->dest);
        if (dst_port == 53 || dst_port == 161 || dst_port == 123 || dst_port == 137) {
            return TC_ACT_SHOT;
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL"; 