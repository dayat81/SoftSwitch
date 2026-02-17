/*
 * BlueWall XDP Pattern Detector - Verifier Safe v3
 * Explicit bounds checking for every payload access
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
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u8);
} Map_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u64);
} Map_attack_count SEC(".maps");

// Helper: Add to blacklist
static __always_inline void blacklist_ip(__u32 ip) {
    __u8 one = 1;
    bpf_map_update_elem(&Map_blacklist, &ip, &one, BPF_ANY);
}

static __always_inline void count_attack(__u32 ip) {
    __u64 *c = bpf_map_lookup_elem(&Map_attack_count, &ip);
    if (c) {
        (*c)++;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&Map_attack_count, &ip, &init, BPF_ANY);
    }
}

SEC("xdp")
int xdp_pattern_detector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    
    // Check blacklist
    __u8 *bl = bpf_map_lookup_elem(&Map_blacklist, &src_ip);
    if (bl && *bl == 1)
        return XDP_DROP;
    
    // Only TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Get TCP header
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60)
        return XDP_PASS;
    
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > 60)
        return XDP_PASS;
    
    // Get payload
    char *payload = (char *)tcp + tcp_hdr_len;
    
    // CRITICAL: Explicit bounds check for payload access
    // We need at least 12 bytes for pattern matching
    if (payload + 12 > (char *)data_end)
        return XDP_PASS;
    
    // Now safe to access payload[0..11]
    // Check for "UNION SELECT"
    if (payload[0] == 'U' && payload[1] == 'N' && payload[2] == 'I' &&
        payload[3] == 'O' && payload[4] == 'N' && payload[5] == ' ' &&
        payload[6] == 'S' && payload[7] == 'E' && payload[8] == 'L' &&
        payload[9] == 'E' && payload[10] == 'C' && payload[11] == 'T') {
        count_attack(src_ip);
        blacklist_ip(src_ip);
        return XDP_DROP;
    }
    
    // Check for "<script>"
    if (payload[0] == '<' && payload[1] == 's' && payload[2] == 'c' &&
        payload[3] == 'r' && payload[4] == 'i' && payload[5] == 'p' &&
        payload[6] == 't' && payload[7] == '>') {
        count_attack(src_ip);
        blacklist_ip(src_ip);
        return XDP_DROP;
    }
    
    // Check for "; /bin/"
    if (payload[0] == ';' && payload[1] == ' ' && payload[2] == '/' &&
        payload[3] == 'b' && payload[4] == 'i' && payload[5] == 'n' &&
        payload[6] == '/') {
        count_attack(src_ip);
        blacklist_ip(src_ip);
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
