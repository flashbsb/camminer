#!/usr/bin/env python3
import os
import sys
import socket
import shutil
from datetime import datetime

# Set global default socket timeout to prevent indefinite urllib or socket hangs
socket.setdefaulttimeout(4.0)

# Add core path to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.scanner import ws_discover, scan_hosts
from core.prober import probe_cameras
from core.performance import run_performance_suite
from core.media import generate_media_assets
from core.exporter import format_terminal_table, export_csv, export_html, export_json

__version__ = "1.4.0"

def check_dependencies():
    """
    Validates Python runtime version, standard library modules, and required system binaries.
    If any dependency is missing, displays detailed terminal instructions and exits.
    """
    missing_deps = []
    
    # 1. Python version check
    if sys.version_info < (3, 8):
        current_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        missing_deps.append(f"Python 3.8+ required (Current version: {current_ver})")
        
    # 2. Standard library modules check
    required_modules = [
        "socket", "urllib.request", "xml.etree.ElementTree",
        "concurrent.futures", "ipaddress", "subprocess",
        "argparse", "json", "csv", "shutil"
    ]
    for mod in required_modules:
        try:
            __import__(mod)
        except ImportError:
            missing_deps.append(f"Python module '{mod}'")
            
    # 3. System binaries check
    required_binaries = ["ffmpeg", "ffprobe", "ping"]
    for binary in required_binaries:
        if shutil.which(binary) is None:
            missing_deps.append(f"System binary '{binary}' (Not found in PATH)")
            
    if missing_deps:
        print("\n" + "="*80)
        print("[-] ERROR: Unmet dependencies detected!")
        print("="*80)
        print("The following required dependencies were not found:\n")
        for dep in missing_deps:
            print(f"  - {dep}")
        print("\n" + "="*80)
        print("INSTALLATION PROCEDURES (Refer to requirements.txt):")
        print("="*80)
        print("""
1. Linux (Debian / Ubuntu):
   sudo apt update
   sudo apt install -y ffmpeg iputils-ping python3

2. macOS (Homebrew):
   brew install ffmpeg

3. Arch Linux:
   sudo pacman -S ffmpeg iputils python

4. Windows:
   - Download FFmpeg & FFprobe binaries from https://ffmpeg.org/download.html
   - Add the FFmpeg bin directory to system PATH.
   - Install Python 3.8+ from https://python.org

For complete dependency details, see requirements.txt in the project root.
""" + "="*80 + "\n")
        sys.exit(1)

def main():
    check_dependencies()
    banner = f"""
             IP Camera Discovery & Analysis Utility
                                 Version: {__version__}
    """
    print(banner)
    print("="*80)
    
    # Initialize Configuration
    config = Config()
    config.parse_args()
    
    # Apply global socket timeout from settings.json
    socket.setdefaulttimeout(config.socket_timeout)
    
    if not config.run_scan:
        print("[*] Scan disabled via --no-scan flag. Exiting.")
        return
        
    # Step 1: Perform ONVIF WS-Discovery (multicast UDP) unless target override is present
    if not config.targets_overridden:
        discovered_ips = ws_discover(timeout=config.ws_discovery_timeout)
        
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
        timeout=config.port_scan_timeout
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
            timeout=config.timeout,
            ffmpeg_socket_timeout=config.ffmpeg_socket_timeout
        )
        
    # Step 5: Exporting & Outputs
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(config.output_dir, exist_ok=True)

    # Step 4.5: Generate Media Assets (Snapshot Images & Video Clips)
    if config.run_image or config.run_video:
        generate_media_assets(
            camera_reports=camera_reports,
            output_dir=config.output_dir,
            credentials_list=config.credentials,
            timestamp=timestamp,
            run_image=config.run_image,
            run_video=config.run_video,
            duration=config.perf_stream_duration,
            max_workers=config.media_max_threads,
            jpeg_quality=config.snapshot_jpeg_quality,
            ffmpeg_socket_timeout=config.ffmpeg_socket_timeout
        )
    
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
        
    print("\n[+] CamMiner analysis finished.")
    print(f"    Reports saved to directory: {os.path.abspath(config.output_dir)}")
    print("="*80 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scan cancelled by user. Exiting.")
        sys.exit(1)
