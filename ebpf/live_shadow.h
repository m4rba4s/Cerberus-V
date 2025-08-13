// SPDX-License-Identifier: Apache-2.0
// Cerberus-V LIVE Mode Shadow Maps
// Elite-Mode APT-Grade Two-Phase Commit

#ifndef __LIVE_SHADOW_H
#define __LIVE_SHADOW_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Shadow map configuration
#define SHADOW_MAP_SIZE 1048576  // 1M entries
#define MAX_RULES_PER_SEC 10
#define SHADOW_IDX 0
#define ACTIVE_IDX 1

// Live mode state
struct live_state {
    __u8 mode;              // 0=simulation, 1=live
    __u64 last_commit;      // timestamp of last commit
    __u32 rule_count;       // current rule count
    __u32 drop_count;       // packets dropped in live mode
    __u32 allow_count;      // packets allowed in live mode
    __u8 emergency_mode;    // emergency rollback flag
};

// Shadow map structure
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);        /* [0] = shadow, [1] = active */
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(int));
} live_shadow SEC(".maps");

// Live state map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct live_state);
} live_state_map SEC(".maps");

// Per-CPU drop histogram for live mode
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256); /* latency buckets */
    __type(key, __u32);
    __type(value, __u64);
} live_drops SEC(".maps");

// Rate limiter for live mode
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  // IP address
    __type(value, __u64); // timestamp
} rate_limiter SEC(".maps");

// Atomic swap function for shadow maps
static __always_inline void commit_live(void) {
    __u32 shadow = SHADOW_IDX, active = ACTIVE_IDX;
    bpf_map_update_elem(&live_shadow, &active, &shadow, BPF_ANY);
}

// Check if live mode is enabled
static __always_inline __u8 is_live_mode(void) {
    __u32 key = 0;
    struct live_state *state = bpf_map_lookup_elem(&live_state_map, &key);
    return state ? state->mode : 0;
}

// Update live mode statistics
static __always_inline void update_live_stats(__u8 action) {
    __u32 key = 0;
    struct live_state *state = bpf_map_lookup_elem(&live_state_map, &key);
    if (state) {
        if (action == 0) {
            state->drop_count++;
        } else {
            state->allow_count++;
        }
    }
}

// Rate limiting check
static __always_inline __u8 check_rate_limit(__u32 ip) {
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_time = bpf_map_lookup_elem(&rate_limiter, &ip);
    
    if (last_time) {
        if (now - *last_time < 100000000) { // 100ms
            return 0; // Rate limited
        }
    }
    
    bpf_map_update_elem(&rate_limiter, &ip, &now, BPF_ANY);
    return 1; // Allowed
}

// Emergency rollback trigger
static __always_inline void trigger_emergency_rollback(void) {
    __u32 key = 0;
    struct live_state *state = bpf_map_lookup_elem(&live_state_map, &key);
    if (state) {
        state->emergency_mode = 1;
        state->mode = 0; // Switch to simulation
    }
}

#endif /* __LIVE_SHADOW_H */ 