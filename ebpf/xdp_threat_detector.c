/*
 * BlueWall XDP Threat Detector
 * 
 * High-performance kernel-space threat detection
 * Supports: OWASP Top 10, MITRE ATT&CK Framework
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Include threat framework headers
#include "threat_framework.h"
#include "owasp_signatures.h"
#include "mitre_signatures.h"

// ============================================================================
// eBPF Maps
// ============================================================================

// Blacklist map (IPs to drop immediately)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // IP address
    __type(value, __u8);     // 1 = blacklisted
} Map_blacklist SEC(".maps");

// Drop statistics per IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // IP address
    __type(value, __u64);    // Drop count
} Map_drop_stats SEC(".maps");

// Pass statistics per IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);      // IP address
    __type(value, __u64);    // Pass count
} Map_pass_stats SEC(".maps");

// Threat events (perf buffer for userspace)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} Map_threat_events SEC(".maps");

// Rate limiting per IP
struct rate_limit_key {
    __u32 ip;
    __u16 port;
    __u8  proto;
};

struct rate_limit_val {
    __u64 count;
    __u64 window_start;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct rate_limit_key);
    __type(value, struct rate_limit_val);
} Map_rate_limit SEC(".maps");

// Attack statistics (for dashboard)
struct attack_stats {
    __u64 count;
    __u64 last_seen;
    __u32 last_src_ip;
    __u8  severity;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);  // One per attack type
    __type(key, __u8);         // attack_type
    __type(value, struct attack_stats);
} Map_attack_stats SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

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

static __always_inline int check_rate_limit(__u32 ip, __u16 port, __u8 proto) {
    struct rate_limit_key key = {
        .ip = ip,
        .port = port,
        .proto = proto
    };
    
    __u64 now = bpf_ktime_get_ns();
    struct rate_limit_val *val = bpf_map_lookup_elem(&Map_rate_limit, &key);
    
    if (!val) {
        // New entry
        struct rate_limit_val new_val = {
            .count = 1,
            .window_start = now,
            .last_seen = now
        };
        bpf_map_update_elem(&Map_rate_limit, &key, &new_val, BPF_ANY);
        return 0;  // Allow
    }
    
    // Check if window expired (1 second)
    __u64 window_ns = 1000000000;  // 1 second
    if (now - val->window_start > window_ns) {
        val->count = 1;
        val->window_start = now;
        val->last_seen = now;
        return 0;  // Allow
    }
    
    // Increment counter
    val->count++;
    val->last_seen = now;
    
    // Check threshold (10000 pps)
    if (val->count > 10000) {
        return 1;  // Rate limited
    }
    
    return 0;  // Allow
}

static __always_inline void update_attack_stats(__u8 attack_type, __u32 src_ip, __u8 severity) {
    struct attack_stats *stats = bpf_map_lookup_elem(&Map_attack_stats, &attack_type);
    __u64 now = bpf_ktime_get_ns();
    
    if (stats) {
        stats->count++;
        stats->last_seen = now;
        stats->last_src_ip = src_ip;
        stats->severity = severity;
    } else {
        struct attack_stats new_stats = {
            .count = 1,
            .last_seen = now,
            .last_src_ip = src_ip,
            .severity = severity
        };
        bpf_map_update_elem(&Map_attack_stats, &attack_type, &new_stats, BPF_ANY);
    }
}

// ============================================================================
// Main XDP Program
// ============================================================================

SEC("xdp")
int xdp_threat_detector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;  // Malformed, pass to kernel
    
    // Check if IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;  // Not IPv4
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 proto = ip->protocol;
    
    __u16 src_port = 0;
    __u16 dst_port = 0;
    void *payload = NULL;
    int payload_len = 0;
    
    // Parse transport layer
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        src_port = __bpf_ntohs(tcp->source);
        dst_port = __bpf_ntohs(tcp->dest);
        
        // Get payload (after TCP header)
        int tcp_hdr_len = tcp->doff * 4;
        payload = (void *)tcp + tcp_hdr_len;
        if (payload < data_end)
            payload_len = data_end - payload;
        
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        src_port = __bpf_ntohs(udp->source);
        dst_port = __bpf_ntohs(udp->dest);
        
        payload = (void *)(udp + 1);
        if (payload < data_end)
            payload_len = data_end - payload;
    }
    
    // ===== STAGE 1: BLACKLIST CHECK (Fast path) =====
    __u8 *blacklisted = bpf_map_lookup_elem(&Map_blacklist, &src_ip);
    if (blacklisted && *blacklisted == 1) {
        update_stats(src_ip, 1);
        return XDP_DROP;
    }
    
    // ===== STAGE 2: RATE LIMITING =====
    if (check_rate_limit(src_ip, dst_port, proto)) {
        // Rate limit exceeded - add to blacklist temporarily
        __u8 one = 1;
        bpf_map_update_elem(&Map_blacklist, &src_ip, &one, BPF_ANY);
        
        // Log event
        struct threat_event evt = {
            .timestamp_ns = bpf_ktime_get_ns(),
            .src_ip = src_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = proto,
            .framework = FRAMEWORK_CUSTOM,
            .category_id = 0,
            .technique_id = 0,
            .action_taken = ACTION_DROP,
            .severity = SEVERITY_HIGH
        };
        bpf_perf_event_output(ctx, &Map_threat_events, BPF_F_CURRENT_CPU,
                             &evt, sizeof(evt));
        
        update_stats(src_ip, 1);
        return XDP_DROP;
    }
    
    // ===== STAGE 3: THREAT DETECTION (Payload inspection) =====
    if (payload_len > 0 && proto == IPPROTO_TCP) {
        struct threat_event evt = {0};
        int attack_detected = 0;
        __u8 severity = SEVERITY_MEDIUM;
        
        // Check OWASP signatures
        struct owasp_signature *owasp_sig = NULL;
        int owasp_attack = owasp_detect(payload, payload_len, &owasp_sig);
        
        if (owasp_attack > 0 && owasp_sig) {
            attack_detected = 1;
            severity = owasp_sig->severity;
            owasp_create_event(&evt, owasp_sig, src_ip, dst_ip, src_port, dst_port,
                              payload, payload_len);
            update_attack_stats(owasp_attack, src_ip, severity);
        }
        
        // Check MITRE signatures (if no OWASP match)
        if (!attack_detected) {
            struct mitre_signature *mitre_sig = NULL;
            int mitre_attack = mitre_detect_signature(payload, payload_len, &mitre_sig);
            
            if (mitre_attack > 0 && mitre_sig) {
                attack_detected = 1;
                severity = mitre_sig->severity;
                mitre_create_event(&evt, mitre_sig, src_ip, dst_ip, src_port, dst_port);
                update_attack_stats(mitre_attack, src_ip, severity);
            }
        }
        
        // If attack detected, decide action
        if (attack_detected) {
            // Send event to userspace
            bpf_perf_event_output(ctx, &Map_threat_events, BPF_F_CURRENT_CPU,
                                 &evt, sizeof(evt));
            
            // Action based on severity
            if (severity >= SEVERITY_HIGH) {
                // Add to blacklist for critical/high
                __u8 one = 1;
                bpf_map_update_elem(&Map_blacklist, &src_ip, &one, BPF_ANY);
                
                update_stats(src_ip, 1);
                return XDP_DROP;
            }
            // Medium/Low: Alert but allow (for monitoring)
        }
    }
    
    // ===== DEFAULT: PASS =====
    update_stats(src_ip, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
