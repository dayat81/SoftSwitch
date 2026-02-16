/*
 * BlueWall XDP Simplified - Production Ready
 * 
 * Does: Blacklist, Rate Limiting, Basic Stats
 * Leaves: Pattern detection to userspace
 */

#define ETH_P_IP 0x0800

#include "vmlinux.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>

#ifndef XDP_PASS
#define XDP_PASS 2
#endif
#ifndef XDP_DROP
#define XDP_DROP 1
#endif

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} Map_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} Map_drop_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} Map_pass_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} Map_rate_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} Map_stats_traffic_normal SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} Map_stats_traffic_malicious SEC(".maps");

// Helper: check if IP is private (192.168.x.x, 10.x.x.x)
static __always_inline int is_private_ip(__u32 ip) {
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000)
        return 1;
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000)
        return 1;
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000)
        return 1;
    return 0;
}

static __always_inline void update_stats(__u32 ip, int dropped) {
    if (dropped) {
        __u64 *drops = bpf_map_lookup_elem(&Map_drop_stats, &ip);
        if (drops) {
            __sync_fetch_and_add(drops, 1);
        } else {
            __u64 init = 1;
            bpf_map_update_elem(&Map_drop_stats, &ip, &init, BPF_ANY);
        }
    } else {
        __u64 *passes = bpf_map_lookup_elem(&Map_pass_stats, &ip);
        if (passes) {
            __sync_fetch_and_add(passes, 1);
        } else {
            __u64 init = 1;
            bpf_map_update_elem(&Map_pass_stats, &ip, &init, BPF_ANY);
        }
    }
}

static __always_inline int check_rate_limit(__u32 ip) {
    __u64 *count = bpf_map_lookup_elem(&Map_rate_counters, &ip);
    if (!count) {
        __u64 init = 1;
        bpf_map_update_elem(&Map_rate_counters, &ip, &init, BPF_ANY);
        return 0;
    }
    
    __sync_fetch_and_add(count, 1);
    
    if (*count > 100000) {
        return 1;
    }
    return 0;
}

SEC("xdp")
int xdp_threat_detector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    
    // Determine traffic type
    int is_internal = is_private_ip(src_ip) && is_private_ip(dst_ip);
    
    // Stage 1: Blacklist check
    __u8 *blacklisted = bpf_map_lookup_elem(&Map_blacklist, &src_ip);
    if (blacklisted && *blacklisted == 1) {
        update_stats(src_ip, 1);
        return XDP_DROP;
    }
    
    // Stage 2: Rate limiting
    if (check_rate_limit(src_ip)) {
        __u8 one = 1;
        bpf_map_update_elem(&Map_blacklist, &src_ip, &one, BPF_ANY);
        update_stats(src_ip, 1);
        return XDP_DROP;
    }
    
    // Stage 3: Separate traffic into normal/malicious maps
    if (is_internal) {
        // Malicious/internal traffic
        __u64 *count = bpf_map_lookup_elem(&Map_stats_traffic_malicious, &src_ip);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 init = 1;
            bpf_map_update_elem(&Map_stats_traffic_malicious, &src_ip, &init, BPF_ANY);
        }
    } else {
        // Normal traffic
        __u64 *count = bpf_map_lookup_elem(&Map_stats_traffic_normal, &src_ip);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 init = 1;
            bpf_map_update_elem(&Map_stats_traffic_normal, &src_ip, &init, BPF_ANY);
        }
    }
    
    // Default: pass (pattern detection done in userspace)
    update_stats(src_ip, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
