#ifndef __THREAT_FRAMEWORK_H__
#define __THREAT_FRAMEWORK_H__

// ============================================================================
// OWASP TOP 10 2021 & MITRE ATT&CK v14.0 Framework Support
// ============================================================================

// Framework identifiers
#define FRAMEWORK_NONE      0
#define FRAMEWORK_OWASP     1
#define FRAMEWORK_MITRE     2
#define FRAMEWORK_CUSTOM    3

// Rule types
#define RULE_SIGNATURE      1
#define RULE_BEHAVIORAL     2
#define RULE_THRESHOLD      3
#define RULE_ANOMALY        4

// Actions
#define ACTION_PASS         0
#define ACTION_ALERT        1
#define ACTION_DROP         2
#define ACTION_BLACKLIST    3
#define ACTION_RATE_LIMIT   4

// Severity levels
#define SEVERITY_INFO       0
#define SEVERITY_LOW        1
#define SEVERITY_MEDIUM     2
#define SEVERITY_HIGH       3
#define SEVERITY_CRITICAL   4

// ============================================================================
// OWASP TOP 10 2021 Categories
// ============================================================================
#define OWASP_A01_BROKEN_ACCESS       0xA01
#define OWASP_A02_CRYPTO_FAILURES     0xA02
#define OWASP_A03_INJECTION           0xA03
#define OWASP_A04_INSECURE_DESIGN     0xA04
#define OWASP_A05_SECURITY_CONFIG     0xA05
#define OWASP_A06_VULNERABLE_COMPONENTS 0xA06
#define OWASP_A07_AUTH_FAILURES       0xA07
#define OWASP_A08_DATA_INTEGRITY      0xA08
#define OWASP_A09_LOGGING_FAILURES    0xA09
#define OWASP_A10_SSRF                0xA0A

// ============================================================================
// MITRE ATT&CK Tactics (TA)
// ============================================================================
#define MITRE_TA01_INITIAL_ACCESS     0xA101
#define MITRE_TA02_EXECUTION          0xA102
#define MITRE_TA03_PERSISTENCE        0xA103
#define MITRE_TA04_PRIV_ESC           0xA104
#define MITRE_TA05_DEFENSE_EVASION    0xA105
#define MITRE_TA06_CRED_ACCESS        0xA106
#define MITRE_TA07_DISCOVERY          0xA107
#define MITRE_TA08_LATERAL_MOVEMENT   0xA108
#define MITRE_TA09_COLLECTION         0xA109
#define MITRE_TA10_EXFILTRATION       0xA10A
#define MITRE_TA11_C2                 0xA10B
#define MITRE_TA12_IMPACT             0xA10C

// ============================================================================
// MITRE ATT&CK Techniques (Selected for Network Detection)
// ============================================================================

// Initial Access
#define MITRE_T1190_EXPLOIT_PUBLIC_APP  0x1190
#define MITRE_T1133_EXTERNAL_SERVICE    0x1133
#define MITRE_T1566_PHISHING            0x1566

// Execution
#define MITRE_T1059_CMD_SCRIPTING       0x1059
#define MITRE_T1059_001_POWERSHELL      0x10591
#define MITRE_T1059_003_CMD_SHELL       0x10593
#define MITRE_T1059_004_UNIX_SHELL      0x10594

// Persistence
#define MITRE_T1543_CREATE_SERVICE      0x1543
#define MITRE_T1136_CREATE_ACCOUNT      0x1136

// Privilege Escalation
#define MITRE_T1068_EXPLOITATION        0x1068

// Defense Evasion
#define MITRE_T1070_LOG_CLEAR           0x1070
#define MITRE_T1036_MASQUERADING        0x1036

// Credential Access
#define MITRE_T1110_BRUTE_FORCE         0x1110
#define MITRE_T1003_CRED_DUMPING        0x1003

// Discovery
#define MITRE_T1046_NETWORK_SCAN        0x1046
#define MITRE_T1083_FILE_DISCOVERY      0x1083
#define MITRE_T1018_REMOTE_SYSTEM       0x1018

// Lateral Movement
#define MITRE_T1021_REMOTE_SERVICE      0x1021
#define MITRE_T1210_EXPLOIT_REMOTE      0x1210

// Collection
#define MITRE_T1005_LOCAL_DATA          0x1005

// Exfiltration
#define MITRE_T1041_C2_EXFIL            0x1041
#define MITRE_T1567_WEB_EXFIL           0x1567

// Command and Control
#define MITRE_T1071_APP_LAYER_PROTO     0x1071
#define MITRE_T1572_PROTOCOL_TUNNEL     0x1572

// Impact
#define MITRE_T1498_DOS                 0x1498
#define MITRE_T1499_ENDPOINT_DOS        0x1499

// ============================================================================
// Rule Structure with Framework Support
// ============================================================================
struct threat_rule {
    __u32 rule_id;
    __u8  framework;      // FRAMEWORK_OWASP, FRAMEWORK_MITRE, etc.
    __u16 category_id;    // OWASP A01-A10 or MITRE TA
    __u32 technique_id;   // MITRE technique ID
    
    __u8  rule_type;      // signature, behavioral, threshold
    __u8  action;         // pass, alert, drop, blacklist
    __u8  severity;       // info, low, medium, high, critical
    
    // Pattern matching (for signature rules)
    char  pattern[64];
    __u8  pattern_len;
    
    // Threshold (for behavioral/threshold rules)
    __u32 threshold;
    __u32 window_sec;
    
    // Metadata
    char  name[48];
    char  description[96];
};

// ============================================================================
// Event Structure for Threat Logging
// ============================================================================
struct threat_event {
    __u64 timestamp_ns;
    
    // Network identifiers
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    
    // Detection info
    __u32 rule_id;
    __u8  framework;
    __u16 category_id;
    __u32 technique_id;
    
    // Action & severity
    __u8  action_taken;
    __u8  severity;
    
    // Context
    __u64 packet_count;
    __u64 byte_count;
    
    // Payload preview (first 32 bytes)
    char  payload_preview[32];
    __u8  payload_len;
};

// ============================================================================
// Attack Type Enumeration
// ============================================================================
#define ATTACK_TYPE_NONE        0
#define ATTACK_TYPE_SQLI        1
#define ATTACK_TYPE_XSS         2
#define ATTACK_TYPE_TRAVERSAL   3
#define ATTACK_TYPE_RCE         4
#define ATTACK_TYPE_LFI         5
#define ATTACK_TYPE_RFI         6
#define ATTACK_TYPE_CMD_INJ     7
#define ATTACK_TYPE_BRUTE_FORCE 8
#define ATTACK_TYPE_PORT_SCAN   9
#define ATTACK_TYPE_DOS         10
#define ATTACK_TYPE_C2          11
#define ATTACK_TYPE_DATA_EXFIL  12
#define ATTACK_TYPE_SUSPICIOUS  99

// ============================================================================
// Helper Functions
// ============================================================================

// Fast string matching (BPF verifier compatible)
static __always_inline int fast_pattern_match(const char *payload, int payload_len,
                                               const char *pattern, int pattern_len) {
    if (pattern_len <= 0 || pattern_len > payload_len)
        return 0;
    
    // Boyer-Moore-Horspool simplified for BPF
    #pragma unroll
    for (int i = 0; i < 256; i++) {  // Max search window
        if (i + pattern_len > payload_len)
            break;
        
        int match = 1;
        #pragma unroll
        for (int j = 0; j < 32; j++) {  // Max pattern length
            if (j >= pattern_len)
                break;
            if (payload[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

// Case-insensitive pattern match
static __always_inline int fast_pattern_match_ci(const char *payload, int payload_len,
                                                  const char *pattern, int pattern_len) {
    if (pattern_len <= 0 || pattern_len > payload_len)
        return 0;
    
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if (i + pattern_len > payload_len)
            break;
        
        int match = 1;
        #pragma unroll
        for (int j = 0; j < 32; j++) {
            if (j >= pattern_len)
                break;
            char p = payload[i + j];
            char m = pattern[j];
            // Convert to lowercase for comparison
            if (p >= 'A' && p <= 'Z') p = p + 32;
            if (m >= 'A' && m <= 'Z') m = m + 32;
            if (p != m) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

// Check if IP is in private range
static __always_inline int is_private_ip(__u32 ip) {
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000)
        return 1;
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000)
        return 1;
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000)
        return 1;
    // 127.0.0.0/8
    if ((ip & 0xFF000000) == 0x7F000000)
        return 1;
    return 0;
}

// Extract payload from TCP packet
static __always_inline void *tcp_payload(struct xdp_md *ctx, struct tcphdr *tcp, int *payload_len) {
    void *data_end = (void *)(long)ctx->data_end;
    void *payload = (void *)tcp + (tcp->doff * 4);
    
    if (payload > data_end)
        return NULL;
    
    *payload_len = data_end - payload;
    if (*payload_len < 0)
        *payload_len = 0;
    
    return payload;
}

#endif /* __THREAT_FRAMEWORK_H__ */
