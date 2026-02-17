/*
 * BlueWall TC Pattern Detector - Fixed
 * Attaches to TC ingress hook - coexists with SoftSwitch XDP
 */

#define ETH_P_IP 0x0800

#include "vmlinux.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
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

// Helper functions
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

SEC("tc")
int tc_pattern_detector(struct __sk_buff *skb) {
    // Parse Ethernet header
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK;
    
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IP header
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0)
        return TC_ACT_OK;
    
    __u32 src_ip = ip.saddr;
    
    // Check blacklist
    __u8 *bl = bpf_map_lookup_elem(&Map_blacklist, &src_ip);
    if (bl && *bl == 1)
        return TC_ACT_SHOT;
    
    // Only check TCP
    if (ip.protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    int ip_hdr_len = ip.ihl * 4;
    int tcp_offset = sizeof(eth) + ip_hdr_len;
    
    // Parse TCP header
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, tcp_offset, &tcp, sizeof(tcp)) < 0)
        return TC_ACT_OK;
    
    int tcp_hdr_len = tcp.doff * 4;
    int payload_offset = tcp_offset + tcp_hdr_len;
    
    // Read payload
    char buf[16];
    if (bpf_skb_load_bytes(skb, payload_offset, buf, 16) < 0)
        return TC_ACT_OK;
    
    // Check patterns
    // Pattern: "UNION SELECT"
    if (buf[0] == 'U' && buf[1] == 'N' && buf[2] == 'I' &&
        buf[3] == 'O' && buf[4] == 'N' && buf[5] == ' ' &&
        buf[6] == 'S' && buf[7] == 'E' && buf[8] == 'L' &&
        buf[9] == 'E' && buf[10] == 'C' && buf[11] == 'T') {
        count_attack(src_ip);
        blacklist_ip(src_ip);
        return TC_ACT_SHOT;
    }
    
    // Pattern: "<script>"
    if (buf[0] == '<' && buf[1] == 's' && buf[2] == 'c' &&
        buf[3] == 'r' && buf[4] == 'i' && buf[5] == 'p' &&
        buf[6] == 't' && buf[7] == '>') {
        count_attack(src_ip);
        blacklist_ip(src_ip);
        return TC_ACT_SHOT;
    }
    
    // Pattern: "; /bin/"
    if (buf[0] == ';' && buf[1] == ' ' && buf[2] == '/' &&
        buf[3] == 'b' && buf[4] == 'i' && buf[5] == 'n' &&
        buf[6] == '/') {
        count_attack(src_ip);
        blacklist_ip(src_ip);
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
