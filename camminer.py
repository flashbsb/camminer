#!/usr/bin/env python3
import os
import sys
import socket
from datetime import datetime

# Set global default socket timeout to prevent indefinite urllib or socket hangs
socket.setdefaulttimeout(4.0)

# Add core path to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.scanner import ws_discover, scan_hosts
from core.prober import probe_cameras
from core.performance import run_performance_suite
from core.exporter import format_terminal_table, export_csv, export_html, export_json

__version__ = "1.2.2"

def main():
    banner = f"""
    ██████╗ ███████╗████████╗██████╗  ██████╗  ██████╗  ██████╗ ███████╗██████╗ 
   ██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗
   ██║  ███╗███████╗   ██║   ██████╔╝██║   ██║██║  ███╗██║  ███╗█████╗  ██████╔╝
   ██║   ██║╚════██║   ██║   ██╔══██╗██║   ██║██║   ██║██║   ██║██╔══╝  ██╔══██╗
   ╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║  ██║
    ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
             IP Camera Discovery & Analysis Utility
                                 Version: {__version__}
    """
    print(banner)
    print("="*80)
    
    # Initialize Configuration
    config = Config()
    config.parse_args()
    
    if not config.run_scan:
        print("[*] Scan disabled via --no-scan flag. Exiting.")
        return
        
    # Step 1: Perform ONVIF WS-Discovery (multicast UDP) unless target override is present
    if not config.targets_overridden:
        discovered_ips = ws_discover()
        
        # Merge discovered IPs into scan targets
        original_targets_count = len(config.targets)
        for ip in discovered_ips:
            if ip not in config.targets:
                config.targets.append(ip)
                
        added_count = len(config.targets) - original_targets_count
        if added_count > 0:
            print(f"[+] Added {added_count} discovered ONVIF camera IP(s) to targets list.")
    else:
        print("[*] WS-Discovery disabled when active targets are explicitly specified via command line.")
        
    if not config.targets:
        print("[-] No scan targets specified in scan.cfg and none discovered via WS-Discovery. Exiting.")
        return
        
    # Step 2: Concurrently scan open RTSP & ONVIF ports
    scan_results = scan_hosts(
        targets=config.targets,
        ports=config.scan_ports,
        threads=config.threads,
        timeout=config.timeout
    )
    
    if not scan_results:
        print("[-] No active hosts with open camera ports (RTSP/HTTP/ONVIF) were found. Exiting.")
        return
        
    # Step 3: Detailed protocol probing (ONVIF profiles / RTSP credentials brute force / ffprobe parameters)
    camera_reports = probe_cameras(
        scan_results=scan_results,
        credentials=config.credentials,
        settings=config
    )
    
    if not camera_reports:
        print("[-] Failed to retrieve details from any active cameras. Exiting.")
        return
        
    # Step 4: Run Performance Tests if requested
    perf_reports = None
    if config.run_perf:
        perf_reports = run_performance_suite(
            camera_reports=camera_reports,
            ping_count=config.perf_ping_count,
            stream_duration=config.perf_stream_duration,
            timeout=5.0
        )
        
    # Step 5: Exporting & Outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(config.output_dir, exist_ok=True)
    
    # Export Terminal Output
    if "terminal" in config.export_formats:
        table_output = format_terminal_table(camera_reports, perf_reports)
        print(table_output)
        
    # Export CSV File
    if "csv" in config.export_formats:
        csv_filename = f"scan_report_{timestamp}.csv"
        csv_path = os.path.join(config.output_dir, csv_filename)
        export_csv(csv_path, camera_reports, perf_reports)
        
    # Export JSON File (always required if HTML is requested for index page summaries)
    if "json" in config.export_formats or "html" in config.export_formats:
        json_filename = f"scan_report_{timestamp}.json"
        json_path = os.path.join(config.output_dir, json_filename)
        export_json(json_path, camera_reports, perf_reports)
        
    # Export HTML File
    if "html" in config.export_formats:
        html_filename = f"scan_report_{timestamp}.html"
        html_path = os.path.join(config.output_dir, html_filename)
        export_html(html_path, camera_reports, perf_reports)
        
    print("\n[+] Antigravity CamMiner analysis finished.")
    print(f"    Reports saved to directory: {os.path.abspath(config.output_dir)}")
    print("="*80 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scan cancelled by user. Exiting.")
        sys.exit(1)
