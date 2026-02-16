#ifndef __MITRE_SIGNATURES_H__
#define __MITRE_SIGNATURES_H__

// ============================================================================
// MITRE ATT&CK Signature Database
// Technique-based detection for network traffic
// ============================================================================

#define MAX_MITRE_SIGNATURES 24

// MITRE signature structure
struct mitre_signature {
    __u32 sig_id;
    __u16 tactic_id;
    __u32 technique_id;
    __u8  attack_type;
    __u8  severity;
    char  pattern[48];
    __u8  pattern_len;
    char  name[48];
};

// ============================================================================
// MITRE ATT&CK Signatures
// ============================================================================

static const struct mitre_signature mitre_db[MAX_MITRE_SIGNATURES] = {
    // === TA0001: Initial Access ===
    // T1190: Exploit Public-Facing Application
    {
        .sig_id = 0xF001,
        .tactic_id = MITRE_TA01_INITIAL_ACCESS,
        .technique_id = MITRE_T1190_EXPLOIT_PUBLIC_APP,
        .attack_type = ATTACK_TYPE_RCE,
        .severity = SEVERITY_CRITICAL,
        .pattern = "eval(",
        .pattern_len = 5,
        .name = "MITRE-T1190-Eval"
    },
    {
        .sig_id = 0xF002,
        .tactic_id = MITRE_TA01_INITIAL_ACCESS,
        .technique_id = MITRE_T1190_EXPLOIT_PUBLIC_APP,
        .attack_type = ATTACK_TYPE_RCE,
        .severity = SEVERITY_CRITICAL,
        .pattern = "system(",
        .pattern_len = 7,
        .name = "MITRE-T1190-System"
    },
    
    // === TA0002: Execution ===
    // T1059.001: PowerShell
    {
        .sig_id = 0xF010,
        .tactic_id = MITRE_TA02_EXECUTION,
        .technique_id = MITRE_T1059_001_POWERSHELL,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "powershell -enc",
        .pattern_len = 15,
        .name = "MITRE-T1059.001-PS"
    },
    {
        .sig_id = 0xF011,
        .tactic_id = MITRE_TA02_EXECUTION,
        .technique_id = MITRE_T1059_001_POWERSHELL,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "IEX (New-Object",
        .pattern_len = 15,
        .name = "MITRE-T1059.001-IEX"
    },
    {
        .sig_id = 0xF012,
        .tactic_id = MITRE_TA02_EXECUTION,
        .technique_id = MITRE_T1059_001_POWERSHELL,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_HIGH,
        .pattern = "Invoke-Expression",
        .pattern_len = 17,
        .name = "MITRE-T1059.001-Invoke"
    },
    
    // T1059.003: Windows Command Shell
    {
        .sig_id = 0xF013,
        .tactic_id = MITRE_TA02_EXECUTION,
        .technique_id = MITRE_T1059_003_CMD_SHELL,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_HIGH,
        .pattern = "cmd.exe /c",
        .pattern_len = 10,
        .name = "MITRE-T1059.003-CMD"
    },
    
    // T1059.004: Unix Shell
    {
        .sig_id = 0xF014,
        .tactic_id = MITRE_TA02_EXECUTION,
        .technique_id = MITRE_T1059_004_UNIX_SHELL,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "/bin/bash -c",
        .pattern_len = 12,
        .name = "MITRE-T1059.004-Bash"
    },
    {
        .sig_id = 0xF015,
        .tactic_id = MITRE_TA02_EXECUTION,
        .technique_id = MITRE_T1059_004_UNIX_SHELL,
        .attack_type = ATTACK_TYPE_CMD_INJ,
        .severity = SEVERITY_CRITICAL,
        .pattern = "/bin/sh -i",
        .pattern_len = 10,
        .name = "MITRE-T1059.004-Sh-Interactive"
    },
    
    // === TA0006: Credential Access ===
    // T1110: Brute Force
    {
        .sig_id = 0xF020,
        .tactic_id = MITRE_TA06_CRED_ACCESS,
        .technique_id = MITRE_T1110_BRUTE_FORCE,
        .attack_type = ATTACK_TYPE_BRUTE_FORCE,
        .severity = SEVERITY_HIGH,
        .pattern = "",
        .pattern_len = 0,
        .name = "MITRE-T1110-BruteForce"
    },
    
    // === TA0007: Discovery ===
    // T1046: Network Service Scanning
    {
        .sig_id = 0xF030,
        .tactic_id = MITRE_TA07_DISCOVERY,
        .technique_id = MITRE_T1046_NETWORK_SCAN,
        .attack_type = ATTACK_TYPE_PORT_SCAN,
        .severity = SEVERITY_MEDIUM,
        .pattern = "",
        .pattern_len = 0,
        .name = "MITRE-T1046-PortScan"
    },
    
    // T1083: File and Directory Discovery
    {
        .sig_id = 0xF031,
        .tactic_id = MITRE_TA07_DISCOVERY,
        .technique_id = MITRE_T1083_FILE_DISCOVERY,
        .attack_type = ATTACK_TYPE_SUSPICIOUS,
        .severity = SEVERITY_MEDIUM,
        .pattern = "ls -la",
        .pattern_len = 6,
        .name = "MITRE-T1083-LS"
    },
    {
        .sig_id = 0xF032,
        .tactic_id = MITRE_TA07_DISCOVERY,
        .technique_id = MITRE_T1083_FILE_DISCOVERY,
        .attack_type = ATTACK_TYPE_SUSPICIOUS,
        .severity = SEVERITY_MEDIUM,
        .pattern = "find / -name",
        .pattern_len = 12,
        .name = "MITRE-T1083-Find"
    },
    
    // T1018: Remote System Discovery
    {
        .sig_id = 0xF033,
        .tactic_id = MITRE_TA07_DISCOVERY,
        .technique_id = MITRE_T1018_REMOTE_SYSTEM,
        .attack_type = ATTACK_TYPE_SUSPICIOUS,
        .severity = SEVERITY_MEDIUM,
        .pattern = "ping -c",
        .pattern_len = 7,
        .name = "MITRE-T1018-Ping"
    },
    
    // === TA0010: Exfiltration ===
    // T1041: Exfiltration Over C2 Channel
    {
        .sig_id = 0xF040,
        .tactic_id = MITRE_TA10_EXFILTRATION,
        .technique_id = MITRE_T1041_C2_EXFIL,
        .attack_type = ATTACK_TYPE_DATA_EXFIL,
        .severity = SEVERITY_HIGH,
        .pattern = "",
        .pattern_len = 0,
        .name = "MITRE-T1041-C2-Exfil"
    },
    
    // T1567: Exfiltration Over Web Service
    {
        .sig_id = 0xF041,
        .tactic_id = MITRE_TA10_EXFILTRATION,
        .technique_id = MITRE_T1567_WEB_EXFIL,
        .attack_type = ATTACK_TYPE_DATA_EXFIL,
        .severity = SEVERITY_HIGH,
        .pattern = "pastebin.com",
        .pattern_len = 12,
        .name = "MITRE-T1567-Pastebin"
    },
    {
        .sig_id = 0xF042,
        .tactic_id = MITRE_TA10_EXFILTRATION,
        .technique_id = MITRE_T1567_WEB_EXFIL,
        .attack_type = ATTACK_TYPE_DATA_EXFIL,
        .severity = SEVERITY_HIGH,
        .pattern = "transfer.sh",
        .pattern_len = 11,
        .name = "MITRE-T1567-Transfer"
    },
    
    // === TA0011: Command and Control ===
    // T1071: Application Layer Protocol
    {
        .sig_id = 0xF050,
        .tactic_id = MITRE_TA11_C2,
        .technique_id = MITRE_T1071_APP_LAYER_PROTO,
        .attack_type = ATTACK_TYPE_C2,
        .severity = SEVERITY_CRITICAL,
        .pattern = "",
        .pattern_len = 0,
        .name = "MITRE-T1071-C2"
    },
    
    // === TA0040: Impact ===
    // T1498: Network Denial of Service
    {
        .sig_id = 0xF060,
        .tactic_id = MITRE_TA12_IMPACT,
        .technique_id = MITRE_T1498_DOS,
        .attack_type = ATTACK_TYPE_DOS,
        .severity = SEVERITY_HIGH,
        .pattern = "",
        .pattern_len = 0,
        .name = "MITRE-T1498-DoS"
    },
    
    // === Terminator ===
    {
        .sig_id = 0,
        .tactic_id = 0,
        .technique_id = 0,
        .attack_type = 0,
        .severity = 0,
        .pattern = "",
        .pattern_len = 0,
        .name = "END"
    }
};

// ============================================================================
// Behavioral Detection State (for rate-based techniques)
// ============================================================================

struct mitre_behavior_state {
    __u64 last_seen_ns;
    __u32 connection_count;
    __u32 unique_ports[16];  // Track scanned ports
    __u8  port_count;
};

// ============================================================================
// Detection Functions
// ============================================================================

static __always_inline int mitre_detect_signature(const char *payload, int payload_len,
                                                   struct mitre_signature **matched_sig) {
    if (!payload || payload_len <= 0)
        return 0;
    
    if (payload_len > 1024)
        payload_len = 1024;
    
    #pragma unroll
    for (int i = 0; i < MAX_MITRE_SIGNATURES; i++) {
        const struct mitre_signature *sig = &mitre_db[i];
        
        if (sig->sig_id == 0)
            break;
        
        // Skip behavioral-only signatures (no pattern)
        if (sig->pattern_len <= 0)
            continue;
        
        if (sig->pattern_len > payload_len)
            continue;
        
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
                *matched_sig = (struct mitre_signature *)sig;
                return sig->attack_type;
            }
        }
    }
    
    return 0;
}

// Create event from MITRE detection
static __always_inline void mitre_create_event(struct threat_event *evt,
                                                const struct mitre_signature *sig,
                                                __u32 src_ip, __u32 dst_ip,
                                                __u16 src_port, __u16 dst_port) {
    evt->framework = FRAMEWORK_MITRE;
    evt->category_id = sig->tactic_id;
    evt->technique_id = sig->technique_id;
    evt->severity = sig->severity;
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->protocol = IPPROTO_TCP;
}

#endif /* __MITRE_SIGNATURES_H__ */
