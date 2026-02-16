import subprocess
import json
import time
import struct
import socket
import threading
import sys
import select
from datetime import datetime
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import termios
import tty

console = Console()

# Cache for DNS lookups
dns_cache = {}
dns_lock = threading.Lock()

# Service Mapping
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

def get_service_name(hostname):
    if hostname == "0.0.0.0" or ":" in hostname: return "Local/Unknown"
    for suffix, service in SERVICE_MAP.items():
        if hostname.endswith(suffix):
            return service
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
        for m in maps:
            if name_fragment in m.get("name", ""):
                return m["id"]
    except Exception:
        return None
    return None

def ip_to_str(val_hex_list):
    # val_hex_list: ["c0", "a8", "00", "01"] (Network Byte Order)
    return ".".join(str(int(x, 16)) for x in val_hex_list)

def parse_key(key_hex):
    # key_hex is a list of 16 bytes (16B key size)
    # struct traffic_key { u32 src_ip; u32 dst_ip; u16 vlan; u16 proto_l2; u16 proto_l3; u16 target_if; }
    # 0-4 src, 4-8 dst, 8-10 vlan, 10-12 proto_l2, 12-14 proto_l3, 14-16 target
    src_ip = ip_to_str(key_hex[:4])
    dst_ip = ip_to_str(key_hex[4:8])
    vlan_bytes = bytes([int(x, 16) for x in key_hex[8:10]])
    vlan = struct.unpack("<H", vlan_bytes)[0]
    l2_proto_bytes = bytes([int(x, 16) for x in key_hex[10:12]])
    l2_proto = socket.ntohs(struct.unpack("<H", l2_proto_bytes)[0])
    return src_ip, dst_ip, vlan, l2_proto

def parse_val(val_list):
    # struct traffic_stats { u64 ts; u8 tagged; u16 size; u64 rx_dropped_b; u64 rx_dropped_p; ... }
    # rx_passed_b is at offset 27..35
    total_pkts = 0
    total_bytes = 0
    for cpu_val in val_list:
        v_hex = cpu_val["value"]
        v_bytes = bytes([int(x, 16) for x in v_hex])
        # offsets based on struct alignment
        rx_passed_b = struct.unpack("<Q", v_bytes[27:35])[0]
        rx_passed_p = struct.unpack("<Q", v_bytes[35:43])[0]
        rx_redir_b = struct.unpack("<Q", v_bytes[43:51])[0]
        rx_redir_p = struct.unpack("<Q", v_bytes[51:59])[0]
        total_bytes += (rx_passed_b + rx_redir_b)
        total_pkts += (rx_passed_p + rx_redir_p)
    return total_pkts, total_bytes

def generate_table(stats, blacklist_ips, sorted_keys=None):
    table = Table(title=f"SoftSwitch Monitor - {datetime.now().strftime('%H:%M:%S')}\n[yellow]Tracking all L2 traffic. Press 'b' to block IP, 'u' to unblock, 'q' to quit[/yellow]", show_header=True, header_style="bold magenta")
    table.add_column("Status", width=8)
    table.add_column("Source IP / Host", style="cyan")
    table.add_column("Service", style="yellow")
    table.add_column("Dest IP", style="cyan")
    table.add_column("Proto", style="magenta")
    table.add_column("VLAN", justify="right")
    table.add_column("PPS", justify="right", style="green")
    table.add_column("BPS", justify="right", style="green")
    table.add_column("Total Pkts")
    
    if sorted_keys is None:
        sorted_keys = sorted(stats.keys(), key=lambda k: stats[k]['pkts'], reverse=True)
    
    for key in sorted_keys:
        s = stats[key]
        src_ip, dst_ip, vlan, l2_proto = key
        hostname = dns_cache.get(src_ip, src_ip)
        
        status = "[green]PASS[/green]"
        if src_ip in blacklist_ips:
            status = "[bold red]BLOCK[/bold red]"
            
        proto_name = f"0x{l2_proto:04x}"
        if l2_proto == 0x0800: proto_name = "IPv4"
        elif l2_proto == 0x86dd: proto_name = "IPv6"
        elif l2_proto == 0x0806: proto_name = "ARP"
        elif l2_proto <= 1500: proto_name = "L2/STP"

        table.add_row(
            status,
            f"{src_ip}\n({hostname})" if l2_proto == 0x0800 else src_ip, 
            get_service_name(hostname) if l2_proto == 0x0800 else "-",
            dst_ip, 
            proto_name,
            str(vlan), 
            f"{s['pps']:.1f}", 
            f"{s['bps']:.1f}", 
            str(s['pkts'])
        )
    return table

def main():
    stats_id = get_map_id("Map_stats_traff")
    blacklist_id = get_map_id("Map_blacklist")
    
    if not stats_id:
        console.print("[red]Error: Could not find Map_stats_traffic map.[/red]")
        return

    stream_stats = {}
    PRUNE_TIMEOUT = 15 
    last_sort_time = 0
    cached_sorted_keys = []
    blocked_services = set()
    
    wizard_type = None # 'block', 'unblock'
    wizard_buffer = ""
    
    # Save old terminal settings
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    
    try:
        # Set raw mode
        tty.setraw(fd)
        
        with Live(Panel("Initializing Monitor...", title="SoftSwitch"), refresh_per_second=4, screen=True) as live:
            while True:
                try:
                    blacklist_ips = set()
                    if blacklist_id:
                        try:
                            bl_cmd = ["sudo", "bpftool", "map", "dump", "id", str(blacklist_id), "-j"]
                            bl_data = json.loads(subprocess.check_output(bl_cmd))
                            for entry in bl_data:
                                blacklist_ips.add(ip_to_str(entry["key"]))
                        except: pass
    
                    cmd = ["sudo", "bpftool", "map", "dump", "id", str(stats_id), "-j"]
                    data = json.loads(subprocess.check_output(cmd))
                    
                    now_wall = time.time()
                    current_keys = set()
                    for entry in data:
                        src_ip, dst_ip, vlan, l2_proto = parse_key(entry["key"])
                        pkts, b = parse_val(entry["values"])
                        
                        if pkts == 0: continue
                        
                        if l2_proto == 0x0800 and src_ip not in dns_cache:
                            threading.Thread(target=resolve_dns, args=(src_ip,), daemon=True).start()
                        
                        key = (src_ip, dst_ip, vlan, l2_proto)
                        current_keys.add(key)
                        if key not in stream_stats:
                            stream_stats[key] = {'pkts': pkts, 'bytes': b, 'last_seen': now_wall, 'pps': 0.0, 'bps': 0.0, 'last_update': now_wall}
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
    
                        # Auto-blocking for services
                        if l2_proto == 0x0800:
                            hostname = dns_cache.get(src_ip)
                            if hostname:
                                service = get_service_name(hostname)
                                if service in blocked_services and src_ip not in blacklist_ips:
                                    try:
                                        subprocess.run(["sudo", "bpftool", "map", "update", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in src_ip.split('.')], "value", "hex", "01"], capture_output=True)
                                        blacklist_ips.add(src_ip)
                                    except: pass
    
                    to_delete = [k for k, v in stream_stats.items() if now_wall - v['last_seen'] > PRUNE_TIMEOUT]
                    for k in to_delete: del stream_stats[k]
                    
                    active_stats = {k: v for k, v in stream_stats.items() if v['pkts'] > 0}
                    if not active_stats:
                        live.update(Panel("Waiting for traffic... (STP/VLAN/IP)", title="SoftSwitch - Idle"))
                    else:
                        if time.time() - last_sort_time > 2.0 or not cached_sorted_keys:
                            cached_sorted_keys = sorted(active_stats.keys(), key=lambda k: active_stats[k]['pkts'], reverse=True)
                            last_sort_time = time.time()
                        
                        # Ensure we only try to display keys that still exist in active_stats
                        display_keys = [k for k in cached_sorted_keys if k in active_stats]
                        # Append any new keys that aren't in cached_sorted_keys yet at the bottom
                        new_keys = [k for k in active_stats if k not in display_keys]
                        display_keys.extend(new_keys)
    
                        # Build UI with Wizard on top
                        table = generate_table(active_stats, blacklist_ips, display_keys)
                        
                        if wizard_type:
                            title = "BLOCK" if wizard_type == 'block' else "UNBLOCK"
                            color = "red" if wizard_type == 'block' else "green"
                            wizard_panel = Panel(
                                Text(f"Target: {wizard_buffer}_", style="bold white"),
                                title=f"[bold {color}]{title} WIZARD[/bold {color}]",
                                subtitle="Press ESC to cancel, ENTER to confirm",
                                border_style=color
                            )
                        else:
                            wizard_panel = Panel(
                                Text("Press 'b' to BLOCK, 'u' to UNBLOCK, 'q' to QUIT", style="dim"),
                                title="[bold blue]SOFT SWITCH MONITOR[/bold blue]",
                                border_style="blue"
                            )
                        
                        from rich.console import Group
                        live.update(Group(wizard_panel, table))
                    
                    if select.select([sys.stdin], [], [], 0)[0]:
                        char = sys.stdin.read(1)
                        if wizard_type:
                            if char == '\r' or char == '\n':
                                target = wizard_buffer.strip()
                                if target:
                                    if wizard_type == 'block':
                                        if any(c.isalpha() for c in target):
                                            blocked_services.add(target)
                                            for ip, host in dns_cache.items():
                                                if get_service_name(host) == target:
                                                    subprocess.run(["sudo", "bpftool", "map", "update", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in ip.split('.')], "value", "hex", "01"], capture_output=True)
                                        else:
                                            subprocess.run(["sudo", "bpftool", "map", "update", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in target.split('.')], "value", "hex", "01"], capture_output=True)
                                    else: # unblock
                                        if any(c.isalpha() for c in target):
                                            if target in blocked_services:
                                                blocked_services.remove(target)
                                                for ip, host in dns_cache.items():
                                                    if get_service_name(host) == target:
                                                        subprocess.run(["sudo", "bpftool", "map", "delete", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in ip.split('.')]], capture_output=True)
                                        else:
                                            subprocess.run(["sudo", "bpftool", "map", "delete", "id", str(blacklist_id), "key", "hex", *[f"{int(x):02x}" for x in target.split('.')]], capture_output=True)
                                wizard_type = None
                                wizard_buffer = ""
                            elif char == '\x1b': # ESC
                                wizard_type = None
                                wizard_buffer = ""
                            elif char == '\x7f' or char == '\b': # Backspace
                                wizard_buffer = wizard_buffer[:-1]
                            else:
                                if char.isprintable():
                                    wizard_buffer += char
                        else:
                            if char.lower() == 'q': break
                            elif char.lower() == 'b':
                                wizard_type = 'block'
                                wizard_buffer = ""
                            elif char.lower() == 'u':
                                wizard_type = 'unblock'
                                wizard_buffer = ""
    
                    time.sleep(0.5)
                    
                except KeyboardInterrupt: break
                except Exception as e:
                    live.update(Panel(f"Error: {e}", title="SoftSwitch Error", border_style="red"))
                    time.sleep(1)
    finally:
        # Restore terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

if __name__ == "__main__":
    main()
