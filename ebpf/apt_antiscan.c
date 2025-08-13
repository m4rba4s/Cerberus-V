// SPDX-License-Identifier: GPL-2.0
// APT-Shield: Anti-Reconnaissance eBPF/XDP Engine
// Elite-Mode APT-Grade Network Defense
// Critical Infrastructure Protection Module

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

// Ring-buffer для логирования сканирований (1% RAM max)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1M entries max
} scan_log SEC(".maps");

// LRU hash для rate limiting (защита от flood)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // source IP
    __type(value, __u64); // timestamp + count
} rate_limiter SEC(".maps");

// Per-CPU array для статистики (lock-free)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} apt_stats SEC(".maps");

// Структура для логирования сканирования
struct scan_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 scan_type;
    __u64 timestamp;
};

// Структура для rate limiting
struct rate_data {
    __u64 timestamp;
    __u32 count;
};

SEC("xdp")
int apt_antiscan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Проверка минимального размера пакета
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return XDP_PASS;
    
    // Проверка IP версии
    if (iph->version != 4)
        return XDP_PASS;
    
    // Rate limiting check
    __u32 src_ip = iph->saddr;
    __u64 current_time = bpf_ktime_get_ns();
    
    struct rate_data *rate_data = bpf_map_lookup_elem(&rate_limiter, &src_ip);
    if (rate_data) {
        // Если больше 100 пакетов в секунду - блокируем
        if (current_time - rate_data->timestamp < 1000000000ULL) { // 1 second
            if (rate_data->count > 100) {
                return XDP_DROP;
            }
            rate_data->count++;
        } else {
            rate_data->timestamp = current_time;
            rate_data->count = 1;
        }
    } else {
        struct rate_data new_rate = {current_time, 1};
        bpf_map_update_elem(&rate_limiter, &src_ip, &new_rate, BPF_ANY);
    }
    
    // TCP SYN scan detection
    if (iph->protocol == IPPROTO_TCP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
            
        struct tcphdr *tcp = data + sizeof(*eth) + (iph->ihl << 2);
        
        // SYN scan detection (SYN without ACK)
        if (tcp->syn && !tcp->ack) {
            struct scan_event *event = bpf_ringbuf_reserve(&scan_log, sizeof(*event), 0);
            if (event) {
                event->src_ip = src_ip;
                event->dst_ip = iph->daddr;
                event->src_port = bpf_ntohs(tcp->source);
                event->dst_port = bpf_ntohs(tcp->dest);
                event->protocol = IPPROTO_TCP;
                event->scan_type = 1; // SYN scan
                event->timestamp = current_time;
                bpf_ringbuf_submit(event, 0);
            }
            
            // Drop SYN scan packets
            return XDP_DROP;
        }
    }
    
    // UDP scan detection
    if (iph->protocol == IPPROTO_UDP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
            
        struct udphdr *udp = data + sizeof(*eth) + (iph->ihl << 2);
        
        // Common UDP scan ports
        __u16 dst_port = bpf_ntohs(udp->dest);
        if (dst_port == 53 || dst_port == 161 || dst_port == 123 || 
            dst_port == 137 || dst_port == 138 || dst_port == 1434) {
            
            struct scan_event *event = bpf_ringbuf_reserve(&scan_log, sizeof(*event), 0);
            if (event) {
                event->src_ip = src_ip;
                event->dst_ip = iph->daddr;
                event->src_port = bpf_ntohs(udp->source);
                event->dst_port = dst_port;
                event->protocol = IPPROTO_UDP;
                event->scan_type = 2; // UDP scan
                event->timestamp = current_time;
                bpf_ringbuf_submit(event, 0);
            }
            
            return XDP_DROP;
        }
    }
    
    // ICMP scan detection
    if (iph->protocol == IPPROTO_ICMP) {
        if (data + sizeof(*eth) + (iph->ihl << 2) + sizeof(struct icmphdr) > data_end)
            return XDP_PASS;
            
        struct icmphdr *icmp = data + sizeof(*eth) + (iph->ihl << 2);
        
        // ICMP echo request (ping scan)
        if (icmp->type == ICMP_ECHO) {
            struct scan_event *event = bpf_ringbuf_reserve(&scan_log, sizeof(*event), 0);
            if (event) {
                event->src_ip = src_ip;
                event->dst_ip = iph->daddr;
                event->src_port = 0;
                event->dst_port = 0;
                event->protocol = IPPROTO_ICMP;
                event->scan_type = 3; // ICMP scan
                event->timestamp = current_time;
                bpf_ringbuf_submit(event, 0);
            }
            
            return XDP_DROP;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL"; 