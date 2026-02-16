#ifndef __OWASP_SIGNATURES_H__
#define __OWASP_SIGNATURES_H__

// ============================================================================
// OWASP TOP 10 Signature Database
// Pre-compiled patterns for eBPF kernel detection
// ============================================================================

#define MAX_OWASP_SIGNATURES 32

// Signature structure for static array
struct owasp_signature {
    __u32 sig_id;
    __u16 owasp_category;
    __u8  attack_type;
    __u8  severity;
    char  pattern[48];
    __u8  pattern_len;
    char  name[32];
};

// ============================================================================
// A03: Injection Signatures
// ============================================================================

// SQL Injection patterns
#define SIG_SQLI_UNION      0xA03001
#define SIG_SQLI_SLEEP      0xA03002
#define SIG_SQLI_DROP       0xA03003
#define SIG_SQLI_INSERT     0xA03004
#define SIG_SQLI_CMD        0xA03005
#define SIG_SQLI_COMMENT    0xA03006
#define SIG_SQLI_OR         0xA03007

// XSS patterns  
#define SIG_XSS_SCRIPT      0xA03010
#define SIG_XSS_ALERT       0xA03011
#define SIG_XSS_JAVASCRIPT  0xA03012
#define SIG_XSS_ONERROR     0xA03013
#define SIG_XSS_IMG         0xA03014

// Command Injection
#define SIG_CMD_SEMICOLON   0xA03020
#define SIG_CMD_PIPE        0xA03021
#define SIG_CMD_BACKTICK    0xA03022
#define SIG_CMD_DOLLAR      0xA03023

// Path Traversal
#define SIG_TRAV_DOTDOT     0xA03030
#define SIG_TRAV_ETC        0xA03031
#define SIG_TRAV_WIN        0xA03032

// Static signature database (embedded in BPF program)
// This avoids map lookups for common patterns

static const struct owasp_signature owasp_db[MAX_OWASP_SIGNATURES] = {
    // === SQL INJECTION (A03) ===
    {
        .sig_id = SIG_SQLI_UNION,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_SQLI,
        .severity = SEVERITY_CRITICAL,
        .pattern = "UNION SELECT",
        .pattern_len = 12,
        .name = "SQLi-UNION"
    },
    {
        .sig_id = SIG_SQLI_SLEEP,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_SQLI,
        .severity = SEVERITY_HIGH,
        .pattern = "SLEEP(",
        .pattern_len = 6,
        .name = "SQLi-SLEEP"
    },
    {
        .sig_id = SIG_SQLI_DROP,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_SQLI,
        .severity = SEVERITY_CRITICAL,
        .pattern = "DROP TABLE",
        .pattern_len = 10,
        .name = "SQLi-DROP"
    },
    {
        .sig_id = SIG_SQLI_INSERT,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_SQLI,
        .severity = SEVERITY_HIGH,
        .pattern = "INSERT INTO",
        .pattern_len = 11,
        .name = "SQLi-INSERT"
    },
    {
        .sig_id = SIG_SQLI_CMD,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_SQLI,
        .severity = SEVERITY_HIGH,
        .pattern = "xp_cmdshell",
        .pattern_len = 11,
        .name = "SQLi-CMD"
    },
    {
        .sig_id = SIG_SQLI_OR,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_SQLI,
        .severity = SEVERITY_MEDIUM,
        .pattern = "' OR '",
        .pattern_len = 6,
        .name = "SQLi-OR"
    },
    
    // === XSS (A03) ===
    {
        .sig_id = SIG_XSS_SCRIPT,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_XSS,
        .severity = SEVERITY_HIGH,
        .pattern = "<script>",
        .pattern_len = 8,
        .name = "XSS-SCRIPT"
    },
    {
        .sig_id = SIG_XSS_ALERT,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_XSS,
        .severity = SEVERITY_MEDIUM,
        .pattern = "alert(",
        .pattern_len = 6,
        .name = "XSS-ALERT"
    },
    {
        .sig_id = SIG_XSS_JAVASCRIPT,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_XSS,
        .severity = SEVERITY_HIGH,
        .pattern = "javascript:",
        .pattern_len = 11,
        .name = "XSS-JS"
    },
    {
        .sig_id = SIG_XSS_ONERROR,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_XSS,
        .severity = SEVERITY_HIGH,
        .pattern = "onerror=",
        .pattern_len = 8,
        .name = "XSS-ONERROR"
    },
    {
        .sig_id = SIG_XSS_IMG,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_XSS,
        .severity = SEVERITY_MEDIUM,
        .pattern = "<img src=",
        .pattern_len = 9,
        .name = "XSS-IMG"
    },
    
    // === COMMAND INJECTION (A03) ===
    {
        .sig_id = SIG_CMD_SEMICOLON,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "; /bin/",
        .pattern_len = 7,
        .name = "CMD-SEMICOLON"
    },
    {
        .sig_id = SIG_CMD_PIPE,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "| /bin/",
        .pattern_len = 7,
        .name = "CMD-PIPE"
    },
    {
        .sig_id = SIG_CMD_BACKTICK,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "`whoami`",
        .pattern_len = 8,
        .name = "CMD-BACKTICK"
    },
    {
        .sig_id = SIG_CMD_DOLLAR,
        .owasp_category = OWASP_A03_INJECTION,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "$(cat /",
        .pattern_len = 7,
        .name = "CMD-DOLLAR"
    },
    
    // === PATH TRAVERSAL (A01) ===
    {
        .sig_id = SIG_TRAV_DOTDOT,
        .owasp_category = OWASP_A01_BROKEN_ACCESS,
        .attack_type = ATTACK_TYPE_TRAVERSAL,
        .severity = SEVERITY_HIGH,
        .pattern = "../../../",
        .pattern_len = 9,
        .name = "TRAVERSAL-DOT"
    },
    {
        .sig_id = SIG_TRAV_ETC,
        .owasp_category = OWASP_A01_BROKEN_ACCESS,
        .attack_type = ATTACK_TYPE_TRAVERSAL,
        .severity = SEVERITY_HIGH,
        .pattern = "/etc/passwd",
        .pattern_len = 11,
        .name = "TRAVERSAL-ETC"
    },
    {
        .sig_id = SIG_TRAV_WIN,
        .owasp_category = OWASP_A01_BROKEN_ACCESS,
        .attack_type = ATTACK_TYPE_TRAVERSAL,
        .severity = SEVERITY_HIGH,
        .pattern = "..\\..\\",
        .pattern_len = 6,
        .name = "TRAVERSAL-WIN"
    },
    
    // === Terminator ===
    {
        .sig_id = 0,
        .owasp_category = 0,
        .attack_type = 0,
        .severity = 0,
        .pattern = "",
        .pattern_len = 0,
        .name = "END"
    }
};

// ============================================================================
// Detection Function
// ============================================================================

static __always_inline int owasp_detect(const char *payload, int payload_len,
                                         struct owasp_signature **matched_sig) {
    if (!payload || payload_len <= 0)
        return 0;
    
    // Limit payload length for safety
    if (payload_len > 1024)
        payload_len = 1024;
    
    #pragma unroll
    for (int i = 0; i < MAX_OWASP_SIGNATURES; i++) {
        const struct owasp_signature *sig = &owasp_db[i];
        
        // End of signatures
        if (sig->sig_id == 0)
            break;
        
        if (sig->pattern_len <= 0 || sig->pattern_len > payload_len)
            continue;
        
        // Simple string search
        #pragma unroll
        for (int j = 0; j < 256; j++) {
            if (j + sig->pattern_len > payload_len)
                break;
            
            int match = 1;
            #pragma unroll
            for (int k = 0; k < 32; k++) {
                if (k >= sig->pattern_len)
                    break;
                if (payload[j + k] != sig->pattern[k]) {
                    match = 0;
                    break;
                }
            }
            
            if (match) {
                *matched_sig = (struct owasp_signature *)sig;
                return sig->attack_type;
            }
        }
    }
    
    return 0;
}

// ============================================================================
// Helper to create threat event from OWASP detection
// ============================================================================

static __always_inline void owasp_create_event(struct threat_event *evt,
                                                const struct owasp_signature *sig,
                                                __u32 src_ip, __u32 dst_ip,
                                                __u16 src_port, __u16 dst_port,
                                                const char *payload, int payload_len) {
    evt->framework = FRAMEWORK_OWASP;
    evt->category_id = sig->owasp_category;
    evt->technique_id = sig->sig_id;
    evt->severity = sig->severity;
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->protocol = IPPROTO_TCP;
    
    // Copy payload preview
    int copy_len = payload_len > 32 ? 32 : payload_len;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i < copy_len)
            evt->payload_preview[i] = payload[i];
        else
            evt->payload_preview[i] = 0;
    }
    evt->payload_len = copy_len;
}

#endif /* __OWASP_SIGNATURES_H__ */
