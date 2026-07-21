import socket
import uuid
import sys
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

OUI_VENDOR_MAP = {}

MAC_VENDOR_CACHE = {}

def lookup_mac_vendor_online(mac):
    """
    Optional online fallback for MAC OUI lookup via lightweight public API (macvendors).
    Uses caching and short timeout (1s) so it never blocks or fails offline scans.
    """
    if not mac or len(mac) < 8:
        return None
    mac_prefix = mac[:8].upper()
    if mac_prefix in MAC_VENDOR_CACHE:
        return MAC_VENDOR_CACHE[mac_prefix]

    try:
        url = f"https://api.macvendors.com/{urllib.parse.quote(mac)}"
        req = urllib.request.Request(url, headers={"User-Agent": "CamMiner/1.0"})
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            if resp.status == 200:
                raw_name = resp.read().decode('utf-8', errors='ignore').strip()
                if raw_name and "error" not in raw_name.lower():
                    vendor = raw_name
                    v_low = raw_name.lower()
                    if "hikvision" in v_low: vendor = "Hikvision"
                    elif "dahua" in v_low: vendor = "Dahua"
                    elif "tp-link" in v_low: vendor = "TP-Link"
                    elif "intelbras" in v_low: vendor = "Intelbras"
                    elif "reolink" in v_low: vendor = "Reolink"
                    elif "axis" in v_low: vendor = "Axis"
                    elif "tuya" in v_low: vendor = "Tuya"
                    elif "bilian" in v_low: vendor = "Bilian"
                    MAC_VENDOR_CACHE[mac_prefix] = vendor
                    return vendor
    except Exception:
        pass
    return None

def load_mac_vendor_map(file_path="config/mac.cfg"):
    """
    Loads MAC address OUI vendor mappings from a user-editable configuration file (e.g. config/mac.cfg).
    Merges user entries into OUI_VENDOR_MAP.
    """
    if not file_path or not os.path.exists(file_path):
        return OUI_VENDOR_MAP

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            count = 0
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    parts = line.split("=", 1)
                    mac_prefix = parts[0].strip().upper().replace("-", ":")
                    vendor_name = parts[1].strip()
                    if mac_prefix and vendor_name:
                        if len(mac_prefix) == 8:
                            OUI_VENDOR_MAP[mac_prefix] = vendor_name
                            count += 1
                        elif len(mac_prefix) == 6:
                            formatted = f"{mac_prefix[0:2]}:{mac_prefix[2:4]}:{mac_prefix[4:6]}"
                            OUI_VENDOR_MAP[formatted] = vendor_name
                            count += 1
        print(f"[+] Loaded {count} MAC OUI vendor mapping(s) from: {file_path}")
    except Exception as e:
        print(f"[-] Warning: Failed to load MAC config file {file_path}: {e}", file=sys.stderr)

    return OUI_VENDOR_MAP

# Load default config/mac.cfg if present at module import time
load_mac_vendor_map()

def lookup_mac_vendor(mac):
    """
    Looks up vendor name based on MAC address OUI prefix.
    First checks expanded offline OUI table, then falls back to fast online query if unlisted.
    """
    if not mac or len(mac) < 8:
        return None
    oui = mac[:8].upper()
    vendor = OUI_VENDOR_MAP.get(oui)
    if vendor:
        return vendor
        
    return lookup_mac_vendor_online(mac)

def get_mac_address(ip):
    """
    Retrieves the MAC address of a target IP from system ARP table cross-platform.
    Returns MAC string in format 'XX:XX:XX:XX:XX:XX' or None.
    """
    if os.name != 'nt':
        # 1. Try reading /proc/net/arp on Linux
        if os.path.exists('/proc/net/arp'):
            try:
                with open('/proc/net/arp', 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            candidate = parts[3].upper().replace('-', ':')
                            if candidate != '00:00:00:00:00:00':
                                return candidate
            except Exception:
                pass
        
        # 2. Fallback to arp -an or ip neighbor on Linux/macOS
        try:
            res = subprocess.run(['arp', '-an', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore', timeout=2.0)
            match = re.search(r'([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}', res.stdout)
            if match:
                mac_raw = match.group(0).upper().replace('-', ':')
                parts = [p.zfill(2) for p in mac_raw.split(':')]
                return ':'.join(parts)
        except Exception:
            pass
    else:
        # Windows arp -a
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            res = subprocess.run(['arp', '-a', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore', timeout=2.0, startupinfo=startupinfo)
            for line in res.stdout.splitlines():
                if ip in line:
                    match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                    if match:
                        return match.group(0).upper().replace('-', ':')
        except Exception:
            pass
            
    return None

def ssdp_discover(timeout=2.0):
    """
    Performs SSDP (UPnP) multicast discovery by sending M-SEARCH to 239.255.255.250:1900.
    """
    print("[*] Initiating SSDP/UPnP discovery for network cameras...")
    ssdp_req = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 2\r\n'
        'ST: ssdp:all\r\n\r\n'
    )
    discovered = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    
    try:
        sock.sendto(ssdp_req.encode('utf-8'), ('239.255.255.250', 1900))
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                resp_text = data.decode('utf-8', errors='ignore').lower()
                camera_keywords = ['camera', 'onvif', 'rtsp', 'hikvision', 'dahua', 'axis', 'foscam', 'reolink', 'intelbras', 'vigi', 'nvt', 'media']
                if any(kw in resp_text for kw in camera_keywords) or 'st: urn:schemas-upnp-org:device:mediaserver' in resp_text:
                    if ip not in discovered:
                        discovered.append(ip)
                        print(f"  [+] Discovered UPnP/SSDP Camera at {ip}")
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] SSDP discovery error: {e}", file=sys.stderr)
    finally:
        sock.close()
        
    return discovered

def ws_discover(timeout=2.0):
    """
    Performs ONVIF WS-Discovery by sending a SOAP Probe request
    via UDP multicast to 239.255.255.250:3702.
    """
    print("[*] Initiating ONVIF WS-Discovery to find local IP cameras...")
    probe_xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Envelope xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl" '
        'xmlns="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        '<Header>'
        f'<wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>'
        '<wsa:To>urn:schemas-xmlsoap-org:ws:2004:08:addressing:subject</wsa:To>'
        '<wsa:Action>http://schemas.xmlsoap.org/ws/2004/08/discovery/Probe</wsa:Action>'
        '</Header>'
        '<Body>'
        '<Probe xmlns="http://schemas.xmlsoap.org/ws/2004/08/discovery">'
        '<Types>tds:Device</Types>'
        '</Probe>'
        '</Body>'
        '</Envelope>'
    )
    
    discovered = []
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    
    try:
        sock.sendto(probe_xml.encode('utf-8'), ('239.255.255.250', 3702))
        
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                if ip not in discovered:
                    discovered.append(ip)
                    xml_str = data.decode('utf-8', errors='ignore')
                    endpoint = ""
                    if "XAddrs" in xml_str:
                        start_idx = xml_str.find("XAddrs>") + 7
                        end_idx = xml_str.find("</", start_idx)
                        if start_idx > 6 and end_idx > start_idx:
                            endpoint = xml_str[start_idx:end_idx].split()[0]
                    print(f"  [+] Discovered ONVIF Camera at {ip} (Endpoint: {endpoint if endpoint else 'Unknown'})")
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] WS-Discovery probe error: {e}", file=sys.stderr)
    finally:
        sock.close()
        
    return discovered

def scan_port(ip, port, timeout=1.0):
    """
    Tries to connect to a specific port on an IP address.
    Returns (port, True) if open, (port, False) otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port, True
    except Exception:
        pass
    finally:
        sock.close()
    return port, False

def scan_hosts(targets, ports, threads=20, timeout=1.0):
    """
    Scans a list of target IPs for a list of ports in parallel.
    Returns a dictionary: { ip: [open_ports] }
    """
    print(f"[*] Scanning {len(targets)} host(s) for open camera ports {ports}...")
    results = {}
    
    jobs = []
    for ip in targets:
        for port in ports:
            jobs.append((ip, port))
            
    total_jobs = len(jobs)
    completed_jobs = 0
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_job = {executor.submit(scan_port, ip, port, timeout): (ip, port) for ip, port in jobs}
        
        for future in as_completed(future_to_job):
            ip, port = future_to_job[future]
            try:
                port, is_open = future.result()
                if is_open:
                    if ip not in results:
                        results[ip] = []
                    results[ip].append(port)
            except Exception:
                pass
                
            completed_jobs += 1
            if completed_jobs % max(1, total_jobs // 10) == 0 or completed_jobs == total_jobs:
                percent = (completed_jobs / total_jobs) * 100
                sys.stdout.write(f"\r[*] Port scanning progress: {percent:.1f}% ({completed_jobs}/{total_jobs} tasks)")
                sys.stdout.flush()
                
    sys.stdout.write("\n")
    print(f"[+] Scan completed. Found {len(results)} hosts with open camera ports.")
    for ip, open_ports in results.items():
        print(f"  - {ip}: Open Ports -> {open_ports}")
    return results
