import socket
import uuid
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

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
                # Log XML metadata info to check for ONVIF profiles if needed,
                # but for discovery, finding the IP is the primary goal
                if ip not in discovered:
                    discovered.append(ip)
                    # Attempt to extract ONVIF service endpoint from XML response
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
    
    # Flatten scan jobs: (ip, port)
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
            except Exception as e:
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
