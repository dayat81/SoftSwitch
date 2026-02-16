import re
import subprocess
import json
import time
import struct
import socket
import threading
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# --- Logic from monitor_ui.py ---
dns_cache = {}
dns_lock = threading.Lock()
blocked_services = set()
CUSTOM_SERVICE_MAP = {}  # IP -> Service Name

# Auto-classification patterns for reverse DNS
CLASSIFICATION_PATTERNS = [
    (r'.*akamai.*', 'Akamai-CDN'),
    (r'.*cloudflare.*', 'Cloudflare-CDN'),
    (r'.*fastly.*', 'Fastly-CDN'),
    (r'.*edgecast.*', 'Edgecast-CDN'),
    (r'.*linode.*', 'Linode-Cloud'),
    (r'.*digitalocean.*', 'DigitalOcean'),
    (r'.*aws.*', 'AWS-Cloud'),
    (r'.*amazon.*', 'Amazon-Cloud'),
    (r'.*google.*', 'Google-Cloud'),
    (r'.*azure.*', 'Microsoft-Azure'),
    (r'.*microsoft.*', 'Microsoft-Cloud'),
    (r'.*hetzner.*', 'Hetzner-Cloud'),
    (r'.*ovh.*', 'OVH-Cloud'),
    (r'.*tailscale.*', 'Tailscale-VPN'),
    (r'.*wireguard.*', 'WireGuard-VPN'),
    (r'.*openvpn.*', 'OpenVPN'),
    (r'.*_gateway.*', 'Local-Gateway'),
    (r'.*gateway.*', 'Local-Gateway'),
    (r'.*router.*', 'Local-Router'),
    (r'.*mdns.*', 'mDNS-Multicast'),
    (r'.*ssdp.*', 'SSDP-Multicast'),
    (r'.*dns.*', 'DNS-Service'),
    (r'.*ntp.*', 'NTP-Service'),
]


# IP range based classification for major services
IP_SERVICE_RANGES = [
    # Google
    ("8.8.8.0", "8.8.8.255", "Google"), ("8.8.4.0", "8.8.4.255", "Google"),
    ("142.250.0.0", "142.251.255.255", "Google"), ("172.217.0.0", "172.217.255.255", "Google"),
    ("74.125.0.0", "74.125.255.255", "Google"), ("209.85.128.0", "209.85.255.255", "Google"),
    ("35.184.0.0", "35.207.255.255", "Google-Cloud"),
    # Cloudflare
    ("104.16.0.0", "104.31.255.255", "Cloudflare"), ("172.64.0.0", "172.71.255.255", "Cloudflare"),
    # AWS
    ("52.0.0.0", "52.31.255.255", "AWS"), ("52.32.0.0", "52.63.255.255", "AWS"),
    ("52.64.0.0", "52.95.255.255", "AWS"), ("54.0.0.0", "54.255.255.255", "AWS"),
    ("13.32.0.0", "13.63.255.255", "AWS"), ("13.112.0.0", "13.127.255.255", "AWS"),
    ("13.208.0.0", "13.215.255.255", "AWS"), ("18.128.0.0", "18.255.255.255", "AWS"),
    # Microsoft
    ("13.64.0.0", "13.107.255.255", "Microsoft"), ("20.0.0.0", "20.255.255.255", "Microsoft-Azure"),
    # Meta
    ("31.13.24.0", "31.13.95.255", "Meta"), ("157.240.0.0", "157.240.255.255", "Meta"),
    # Akamai
    ("104.64.0.0", "104.127.255.255", "Akamai"), ("184.24.0.0", "184.31.255.255", "Akamai"),
    # Netflix
    ("23.246.0.0", "23.246.63.255", "Netflix"), ("45.57.0.0", "45.57.127.255", "Netflix"),
    # GitHub
    ("140.82.112.0", "140.82.127.255", "GitHub"), ("192.30.252.0", "192.30.255.255", "GitHub"),
    # Linode
    ("45.33.0.0", "45.79.255.255", "Linode"), ("172.104.0.0", "172.104.255.255", "Linode"),
    # Hetzner
    ("49.12.0.0", "49.13.255.255", "Hetzner"), ("116.202.0.0", "116.203.255.255", "Hetzner"),
    # Fastly
    ("151.101.0.0", "151.101.255.255", "Fastly"),
    # DigitalOcean
    ("104.131.0.0", "104.131.255.255", "DigitalOcean"),
]

def ip_to_int(ip):
    parts = [int(x) for x in ip.split(".")]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def classify_by_ip_range(ip):
    try:
        ip_int = ip_to_int(ip)
        for start, end, service in IP_SERVICE_RANGES:
            if ip_to_int(start) <= ip_int <= ip_to_int(end):
                return service
    except:
        pass
    return None

def is_local_ip(ip):
    """Check if IP is in private/local ranges"""
    if ip.startswith('192.168.') or ip.startswith('10.'):
        return True
    if ip.startswith('172.'):
        parts = ip.split('.')
        if len(parts) > 1 and parts[1].isdigit():
            if 16 <= int(parts[1]) <= 31:
                return True
    if ip.startswith('127.'):
        return True
    if ip.startswith('224.') or ip.startswith('239.'):  # Multicast
        return True
    return False

def classify_traffic(src_ip, dst_ip, hostname):
    """Classify traffic based on direction and IPs"""
    src_local = is_local_ip(src_ip)
    dst_local = is_local_ip(dst_ip)
    
    # Internal traffic (local -> local)
    if src_local and dst_local:
        return "Local-Network"
    
    # Outbound traffic (local -> external) - classify by destination
    if src_local and not dst_local:
        # Try IP range first
        ip_svc = classify_by_ip_range(dst_ip)
        if ip_svc:
            return ip_svc
        # Try reverse DNS on destination
        dst_svc = classify_by_reverse_dns(dst_ip)
        if dst_svc and dst_svc not in ["Local-Network", None]:
            return dst_svc
        # Try service map
        for suffix, svc in SERVICE_MAP.items():
            if hostname.endswith(suffix):
                return svc
        return "Unknown"
    
    # Inbound traffic (external -> local) - classify by source
    if not src_local and dst_local:
        ip_svc = classify_by_ip_range(src_ip)
        if ip_svc:
            return ip_svc
        dst_svc = classify_by_reverse_dns(src_ip)
        if dst_svc and dst_svc not in ["Local-Network", None]:
            return dst_svc
        return "Unknown"
    
    # Transit traffic (external -> external)
    return "Transit"

def classify_by_reverse_dns(ip):
    if ip.startswith('224.') or ip.startswith('239.') or ip.startswith('255.'):
        return None
    if ip.startswith('192.168.') or ip.startswith('10.'):
        return 'Local-Network'
    if ip.startswith('172.'):
        parts = ip.split('.')
        if len(parts) > 1 and parts[1].isdigit():
            if 16 <= int(parts[1]) <= 31:
                return 'Local-Network'
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        for pattern, service in CLASSIFICATION_PATTERNS:
            if re.match(pattern, hostname, re.IGNORECASE):
                return service
    except:
        pass
    return None



SERVICE_MAP = {
    ".google.com": "Google",
    ".gstatic.com": "Google",
    ".googlevideo.com": "YouTube",
    ".1e100.net": "Google",
    ".facebook.com": "Meta",
    ".fbcdn.net": "Meta",
    ".instagram.com": "Meta",
    ".whatsapp.net": "Meta",
    ".netflix.com": "Netflix",
    ".nflxvideo.net": "Netflix",
    ".nflxso.net": "Netflix",
    ".tiktok.com": "TikTok",
    ".byteoversea.com": "TikTok",
    ".microsoft.com": "Microsoft",
    ".windows.com": "Microsoft",
    ".azure.com": "Microsoft",
}

def get_service_name(ip_or_hostname):
    if ip_or_hostname in CUSTOM_SERVICE_MAP:
        return CUSTOM_SERVICE_MAP[ip_or_hostname]
    if ip_or_hostname == "0.0.0.0" or ":" in ip_or_hostname: return "Local/Unknown"
    for suffix, service in SERVICE_MAP.items():
        if ip_or_hostname.endswith(suffix):
            return service
    if re.match(r'^[\d\.]+$', ip_or_hostname):
        classified = classify_by_reverse_dns(ip_or_hostname)
        if classified:
            CUSTOM_SERVICE_MAP[ip_or_hostname] = classified
            return classified
    return "Unknown"

def resolve_dns(ip):
    if ip == "0.0.0.0" or ":" in ip: return ip
    with dns_lock:
        if ip in dns_cache:
            return dns_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = ip
    with dns_lock:
        dns_cache[ip] = hostname
    return hostname

def get_map_id(name_fragment):
    try:
        cmd = ["sudo", "bpftool", "map", "show", "-j"]
        output = subprocess.check_output(cmd)
        maps = json.loads(output)
        matching_ids = [m["id"] for m in maps if name_fragment in m.get("name", "")]
        if matching_ids:
            return max(matching_ids)  # Return highest ID (most recent)
    except Exception:
        return None
    return None

def ip_to_str(val_hex_list):
    return ".".join(str(int(x, 16)) for x in val_hex_list)

def parse_key(key_hex):
    src_ip = ip_to_str(key_hex[:4])
    dst_ip = ip_to_str(key_hex[4:8])
    vlan_bytes = bytes([int(x, 16) for x in key_hex[8:10]])
    vlan = struct.unpack("<H", vlan_bytes)[0]
    l2_proto_bytes = bytes([int(x, 16) for x in key_hex[10:12]])
    l2_proto = socket.ntohs(struct.unpack("<H", l2_proto_bytes)[0])
    return src_ip, dst_ip, vlan, l2_proto

def parse_val(val_list):
    total_pkts = 0
    total_bytes = 0
    for cpu_val in val_list:
        v_hex = cpu_val["value"]
        v_bytes = bytes([int(x, 16) for x in v_hex])
        rx_passed_b = struct.unpack("<Q", v_bytes[27:35])[0]
        rx_passed_p = struct.unpack("<Q", v_bytes[35:43])[0]
        rx_redir_b = struct.unpack("<Q", v_bytes[43:51])[0]
        rx_redir_p = struct.unpack("<Q", v_bytes[51:59])[0]
        total_bytes += (rx_passed_b + rx_redir_b)
        total_pkts += (rx_passed_p + rx_redir_p)
    return total_pkts, total_bytes

# --- API Endpoints ---
stream_stats = {}

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats_id = get_map_id("Map_stats_traff")
    blacklist_id = get_map_id("Map_blacklist")
    if not stats_id:
        return jsonify({"error": "Map_stats_traffic not found"}), 500

    # Get Blacklist
    blacklist_ips = set()
    if blacklist_id:
        try:
            bl_cmd = ["sudo", "bpftool", "map", "dump", "id", str(blacklist_id), "-j"]
            bl_data = json.loads(subprocess.check_output(bl_cmd))
            for entry in bl_data:
                blacklist_ips.add(ip_to_str(entry["key"]))
        except: pass

    # Get Stats
    cmd = ["sudo", "bpftool", "map", "dump", "id", str(stats_id), "-j"]
    data = json.loads(subprocess.check_output(cmd))
    
    now_wall = time.time()
    for entry in data:
        src_ip, dst_ip, vlan, l2_proto = parse_key(entry["key"])
        pkts, b = parse_val(entry["values"])
        if pkts == 0: continue
        
        # Async DNS resolution
        if l2_proto == 0x0800 and src_ip not in dns_cache:
            threading.Thread(target=resolve_dns, args=(src_ip,), daemon=True).start()
        
        key = f"{src_ip}-{dst_ip}-{vlan}-{l2_proto}"
        if key not in stream_stats:
            stream_stats[key] = {
                'src': src_ip, 'dst': dst_ip, 'vlan': vlan, 'proto': l2_proto,
                'pkts': pkts, 'bytes': b, 'last_seen': now_wall, 
                'pps': 0.0, 'bps': 0.0, 'last_update': now_wall
            }
        else:
            s = stream_stats[key]
            dt = now_wall - s['last_update']
            if dt >= 0.5:
                s['pps'] = (pkts - s['pkts']) / dt
                s['bps'] = (b - s['bytes']) / dt
                s['pkts'] = pkts
                s['bytes'] = b
                s['last_update'] = now_wall
            s['last_seen'] = now_wall

        # Auto-block services
        if l2_proto == 0x0800:
            hostname = dns_cache.get(src_ip)
            if hostname:
                service = get_service_name(hostname)
                if service in blocked_services and src_ip not in blacklist_ips:
                    try:
                        subprocess.run(["sudo", "bpftool", "map", "update", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in src_ip.split('.')], "value", "hex", "01"], capture_output=True)
                        blacklist_ips.add(src_ip)
                    except: pass

    # Pruning and Response Formatting
    PRUNE_TIMEOUT = 15
    result = []
    to_delete = []
    for k, v in stream_stats.items():
        if now_wall - v['last_seen'] > PRUNE_TIMEOUT:
            to_delete.append(k)
            continue
        
        hostname = dns_cache.get(v['src'], v['src'])
        proto_name = f"0x{v['proto']:04x}"
        if v['proto'] == 0x0800: proto_name = "IPv4"
        elif v['proto'] == 0x86dd: proto_name = "IPv6"
        elif v['proto'] == 0x0806: proto_name = "ARP"
        
        # Classify traffic based on direction (inbound/outbound/internal)
        if v['proto'] == 0x0800:
            service_name = classify_traffic(v['src'], v['dst'], hostname)
        else:
            service_name = "-"
        
        result.append({
            "status": "BLOCK" if v['dst'] in blacklist_ips else "PASS",
            "src": v['src'],
            "host": hostname,
            "service": service_name,
            "dst": v['dst'],
            "proto": proto_name,
            "vlan": v['vlan'],
            "pps": round(v['pps'], 1),
            "bps": round(v['bps'], 1),
            "pkts": v['pkts'],
            "bytes": v['bytes']
        })
    
    for k in to_delete: del stream_stats[k]
    
    # Group by service name with details
    grouped = {}
    for item in result:
        svc = item['service']
        if svc not in grouped:
            grouped[svc] = {
                'service': svc, 'pkts': 0, 'bytes': 0, 'bps': 0.0, 'pps': 0.0,
                'flows': 0, 'status': item['status'], 'details': []
            }
        grouped[svc]['pkts'] += item['pkts']
        grouped[svc]['bps'] += item['bps']
        grouped[svc]['pps'] += item['pps']
        grouped[svc]['flows'] += 1
        grouped[svc]['bytes'] += item['bytes']
        grouped[svc]['details'].append({
            'src': item['src'], 'dst': item['dst'], 'host': item['host'],
            'proto': item['proto'], 'vlan': item['vlan'], 'pkts': item['pkts'],
            'bytes': item['bytes'], 'pps': item['pps'], 'bps': item['bps'], 'status': item['status']
        })
    return jsonify(sorted(grouped.values(), key=lambda x: x['pkts'], reverse=True))

@app.route('/api/block', methods=['POST'])
def block_target():
    blacklist_id = get_map_id("Map_blacklist")
    target = request.json.get('target')
    service_name = request.json.get('service_name')
    if not target or not blacklist_id: return jsonify({"status": "error"}), 400
    
    if any(c.isalpha() for c in target): # Service (Legacy/Hardcoded)
        blocked_services.add(target)
        for ip, host in dns_cache.items():
            if get_service_name(host) == target:
                subprocess.run(["sudo", "bpftool", "map", "update", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in ip.split('.')], "value", "hex", "01"])
    else: # IP
        if service_name:
            CUSTOM_SERVICE_MAP[target] = service_name
        subprocess.run(["sudo", "bpftool", "map", "update", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in target.split('.')], "value", "hex", "01"])
    return jsonify({"status": "ok"})

@app.route('/api/unblock', methods=['POST'])
def unblock_target():
    blacklist_id = get_map_id("Map_blacklist")
    target = request.json.get('target')
    if not target or not blacklist_id: return jsonify({"status": "error"}), 400
    
    if any(c.isalpha() for c in target): # Service
        if target in blocked_services:
            blocked_services.remove(target)
            for ip, host in dns_cache.items():
                if get_service_name(host) == target:
                    subprocess.run(["sudo", "bpftool", "map", "delete", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in ip.split('.')]])
    else: # IP
        subprocess.run(["sudo", "bpftool", "map", "delete", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in target.split('.')]])
    return jsonify({"status": "ok"})

@app.route('/api/reset', methods=['POST'])
def reset_stats():
    stats_id = get_map_id("Map_stats_traff")
    if not stats_id:
        return jsonify({"status": "error", "message": "Map_stats_traffic not found"}), 500
    
    try:
        cmd_dump = ["sudo", "bpftool", "map", "dump", "id", str(stats_id), "-j"]
        data = json.loads(subprocess.check_output(cmd_dump))
        for entry in data:
            key_hex = entry["key"]
            subprocess.run(["sudo", "bpftool", "map", "delete", "id", str(stats_id), "key", "hex"] + key_hex, capture_output=True)
        
        stream_stats.clear()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/batch_label', methods=['POST'])
def batch_label():
    targets = request.json.get('targets', [])
    service_name = request.json.get('service_name')
    if not service_name: return jsonify({"status": "error", "message": "Service name required"}), 400
    
    for ip in targets:
        CUSTOM_SERVICE_MAP[ip] = service_name
        
    return jsonify({"status": "ok"})

@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    blacklist_id = get_map_id("Map_blacklist")
    ips = []
    if blacklist_id:
        try:
            bl_cmd = ["sudo", "bpftool", "map", "dump", "id", str(blacklist_id), "-j"]
            bl_data = json.loads(subprocess.check_output(bl_cmd))
            for entry in bl_data:
                ips.append(ip_to_str(entry["key"]))
        except: pass
    return jsonify({
        "ips": ips,
        "services": list(blocked_services),
        "custom_services": CUSTOM_SERVICE_MAP
    })



@app.route('/api/labels', methods=['GET'])
def get_all_labels():
    """Dump all service labels including auto-classified and custom mappings"""
    return jsonify({
        "custom_services": CUSTOM_SERVICE_MAP,
        "classification_patterns": [p[1] for p in CLASSIFICATION_PATTERNS],
        "total_labels": len(CUSTOM_SERVICE_MAP),
        "sources": {
            "manual": [ip for ip, svc in CUSTOM_SERVICE_MAP.items() if svc not in [p[1] for p in CLASSIFICATION_PATTERNS]],
            "auto_classified": [ip for ip, svc in CUSTOM_SERVICE_MAP.items() if svc in [p[1] for p in CLASSIFICATION_PATTERNS]]
        }
    })

@app.route('/api/clear_blacklist', methods=['POST'])
def clear_blacklist():
    blacklist_id = get_map_id("Map_blacklist")
    if not blacklist_id:
        return jsonify({"status": "error", "message": "Blacklist map not found"}), 500
    
    try:
        # Clear IPs from Map
        bl_cmd = ["sudo", "bpftool", "map", "dump", "id", str(blacklist_id), "-j"]
        bl_data = json.loads(subprocess.check_output(bl_cmd))
        for entry in bl_data:
            key_hex = entry["key"]
            subprocess.run(["sudo", "bpftool", "map", "delete", "id", str(blacklist_id), "key", "hex"] + key_hex, capture_output=True)
        
        # Clear Services
        blocked_services.clear()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, threaded=True)

# Add Flask debug and reload
app.config["DEBUG"] = False
app.config["TESTING"] = False
