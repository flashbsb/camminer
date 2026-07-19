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
from core.logger import Logger, Colors
from core.scanner import ws_discover, scan_hosts
from core.prober import probe_cameras
from core.performance import run_performance_suite
from core.media import generate_media_assets
from core.exporter import format_terminal_table, export_csv, export_html, export_json, update_index_html

__version__ = "1.5.0"

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
        print(f"{Colors.RED}[!] ERROR: Unmet dependencies detected!{Colors.RESET}")
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
    
    # Initialize Configuration
    config = Config()
    config.parse_args()
    
    # Apply global socket timeout from settings.json
    socket.setdefaulttimeout(config.socket_timeout)

    # Prepare timestamped execution subfolder
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(config.output_dir, f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    # Initialize Logger
    log_file_path = os.path.join(run_dir, f"camminer_{timestamp}.log") if config.log_to_file else None
    log = Logger(verbose=config.verbose, log_to_file=config.log_to_file, log_filepath=log_file_path)

    banner = f"""
{Colors.CYAN}{Colors.BOLD}             camminer IP Camera Discovery & Analysis Utility{Colors.RESET}
                                  {Colors.YELLOW}Version: {__version__}{Colors.RESET}
    """
    print(banner)
    print("="*80)
    
    if config.log_to_file:
        log.info(f"Execution log enabled: {os.path.abspath(log_file_path)}")
    if config.verbose:
        log.info("Verbose mode active (detailed debug output enabled)")

    if not config.run_scan:
        log.info("Scan disabled via --no-scan flag. Exiting.")
        return
        
    # STAGE 1: Network & WS-Discovery
    log.stage(1, 5, "Network Discovery & Target Port Scanning")
    if not config.targets_overridden:
        discovered_ips = ws_discover(timeout=config.ws_discovery_timeout)
        
        # Merge discovered IPs into scan targets
        original_targets_count = len(config.targets)
        for ip in discovered_ips:
            if ip not in config.targets:
                config.targets.append(ip)
                
        added_count = len(config.targets) - original_targets_count
        if added_count > 0:
            log.success(f"Added {added_count} discovered ONVIF camera IP(s) to targets list.")
    else:
        log.info("WS-Discovery disabled when active targets are explicitly specified via command line.")
        
    if not config.targets:
        log.warning("No scan targets specified in scan.cfg and none discovered via WS-Discovery. Exiting.")
        return
        
    scan_results = scan_hosts(
        targets=config.targets,
        ports=config.scan_ports,
        threads=config.threads,
        timeout=config.port_scan_timeout
    )
    
    if not scan_results:
        log.warning("No active hosts with open camera ports (RTSP/HTTP/ONVIF) were found. Exiting.")
        return
        
    # STAGE 2: Camera Protocol & Stream Probing
    log.stage(2, 5, "Camera Protocol & Stream Specification Probing")
    camera_reports = probe_cameras(
        scan_results=scan_results,
        credentials=config.credentials,
        settings=config
    )
    
    if not camera_reports:
        log.warning("Failed to retrieve details from any active cameras. Exiting.")
        return
        
    # STAGE 3: Performance Testing
    perf_reports = None
    if config.run_perf:
        log.stage(3, 5, "Performance & Network Latency Testing")
        perf_reports = run_performance_suite(
            camera_reports=camera_reports,
            ping_count=config.perf_ping_count,
            stream_duration=config.perf_stream_duration,
            timeout=config.timeout,
            ffmpeg_socket_timeout=config.ffmpeg_socket_timeout
        )
    else:
        log.info("Performance suite skipped via --no-perf flag.")
        
    # STAGE 4: Media Asset Generation
    if config.run_image or config.run_video:
        log.stage(4, 5, "Media Asset Capture (Snapshots & Clips)")
        generate_media_assets(
            camera_reports=camera_reports,
            output_dir=run_dir,
            credentials_list=config.credentials,
            timestamp=timestamp,
            run_image=config.run_image,
            run_video=config.run_video,
            duration=config.perf_stream_duration,
            max_workers=config.media_max_threads,
            jpeg_quality=config.snapshot_jpeg_quality,
            ffmpeg_socket_timeout=config.ffmpeg_socket_timeout
        )
    else:
        log.info("Media asset generation skipped via flags.")
    
    # STAGE 5: Report Exporting & Indexing
    log.stage(5, 5, "Report Generation & Archive Indexing")
    
    if "terminal" in config.export_formats:
        table_output = format_terminal_table(camera_reports, perf_reports)
        print(table_output)
        
    if "csv" in config.export_formats:
        csv_filename = f"scan_report_{timestamp}.csv"
        csv_path = os.path.join(run_dir, csv_filename)
        export_csv(csv_path, camera_reports, perf_reports)
        log.success(f"CSV report exported to: {csv_path}")
        
    if "json" in config.export_formats or "html" in config.export_formats:
        json_filename = f"scan_report_{timestamp}.json"
        json_path = os.path.join(run_dir, json_filename)
        export_json(json_path, camera_reports, perf_reports)
        log.success(f"JSON report exported to: {json_path}")
        
    if "html" in config.export_formats:
        html_filename = f"scan_report_{timestamp}.html"
        html_path = os.path.join(run_dir, html_filename)
        export_html(html_path, camera_reports, perf_reports)
        log.success(f"HTML report exported to: {html_path}")
        
    # Rebuild top-level index.html linking all run subfolders
    update_index_html(config.output_dir)
        
    print("\n" + "="*80)
    log.success("CamMiner analysis finished successfully.")
    print(f"    Run Directory:  {Colors.BOLD}{os.path.abspath(run_dir)}{Colors.RESET}")
    print(f"    Master Archive: {Colors.BOLD}{os.path.abspath(os.path.join(config.output_dir, 'index.html'))}{Colors.RESET}")
    print("="*80)
    print(f"{Colors.DIM}Repository & Updates: https://github.com/flashbsb/camminer{Colors.RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Scan cancelled by user. Exiting.")
        sys.exit(1)
