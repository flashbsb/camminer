import os
import json
import argparse
import ipaddress
import sys

class Config:
    def __init__(self):
        self.settings_path = "config/settings.json"
        self.scan_cfg_path = "config/scan.cfg"
        self.user_cfg_path = "config/user.cfg"
        self.output_dir = "infos"
        
        self.timeout = 3.0
        self.threads = 20
        self.scan_ports = [554, 8554, 80, 8080, 8888, 5000, 3702]
        self.common_rtsp_paths = []
        
        # Performance Suite settings
        self.perf_ping_count = 5
        self.perf_stream_duration = 5
        
        self.targets = []
        self.credentials = []
        
        self.run_scan = True
        self.run_perf = False
        self.export_formats = ["terminal", "csv", "html"]

    def parse_args(self):
        parser = argparse.ArgumentParser(
            description="Antigravity CamMiner - Multi-vendor IP Camera Scanning & Analysis Utility"
        )
        parser.add_argument(
            "-s", "--settings",
            default=self.settings_path,
            help=f"Path to settings.json (default: {self.settings_path})"
        )
        parser.add_argument(
            "-c", "--scan-cfg",
            default=self.scan_cfg_path,
            help=f"Path to scan.cfg (default: {self.scan_cfg_path})"
        )
        parser.add_argument(
            "-u", "--user-cfg",
            default=self.user_cfg_path,
            help=f"Path to user.cfg (default: {self.user_cfg_path})"
        )
        parser.add_argument(
            "-o", "--output-dir",
            default=None,
            help="Path to output directory (overrides settings.json config)"
        )
        parser.add_argument(
            "--no-scan",
            action="store_true",
            help="Disable network and camera scan module"
        )
        parser.add_argument(
            "--perf",
            action="store_true",
            help="Enable active camera stream and network performance testing"
        )
        parser.add_argument(
            "-f", "--format",
            default="terminal,csv,html",
            help="Output formats (comma-separated: terminal,csv,html,json. default: terminal,csv,html)"
        )

        args = parser.parse_args()
        
        # Override paths if provided
        self.settings_path = args.settings
        self.scan_cfg_path = args.scan_cfg
        self.user_cfg_path = args.user_cfg
        self.run_scan = not args.no_scan
        self.run_perf = args.perf
        self.export_formats = [fmt.strip().lower() for fmt in args.format.split(",")]
        
        # Load from files
        self.load_settings()
        
        # Command line output directory override
        if args.output_dir:
            self.output_dir = args.output_dir
            
        self.load_targets()
        self.load_credentials()

    def load_settings(self):
        # Prefer custom settings path, fallback to default or check environment
        paths_to_try = [self.settings_path, "config/settings.json"]
        settings_loaded = False
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.timeout = float(data.get("timeout", self.timeout))
                        self.threads = int(data.get("threads", self.threads))
                        self.scan_ports = list(data.get("scan_ports", self.scan_ports))
                        self.common_rtsp_paths = list(data.get("common_rtsp_paths", self.common_rtsp_paths))
                        self.output_dir = data.get("default_output_dir", self.output_dir)
                        self.perf_ping_count = int(data.get("perf_ping_count", self.perf_ping_count))
                        self.perf_stream_duration = int(data.get("perf_stream_duration", self.perf_stream_duration))
                        settings_loaded = True
                        break
                except Exception as e:
                    print(f"[-] Warning: Failed to load settings from {path}: {e}", file=sys.stderr)

        if not settings_loaded:
            print(f"[-] Warning: settings.json not found. Using default configurations.", file=sys.stderr)

    def load_targets(self):
        # We also check if there is a config in ../d-camminer/config/scan.cfg
        paths_to_try = [self.scan_cfg_path]
        # Check if parent d-camminer path exists
        parent_scan_cfg = os.path.join("..", "d-camminer", "config", "scan.cfg")
        if parent_scan_cfg not in paths_to_try:
            paths_to_try.append(parent_scan_cfg)
            
        scan_cfg_found = False
        
        for path in paths_to_try:
            if os.path.exists(path):
                self.targets = self._parse_ip_config(path)
                scan_cfg_found = True
                print(f"[+] Loaded targets from {path} ({len(self.targets)} target IP addresses)")
                break
                
        if not scan_cfg_found:
            print(f"[-] Warning: scan.cfg not found in searched paths {paths_to_try}.", file=sys.stderr)
            # Default to local subnet scan
            self.targets = self._generate_local_subnet_ips()
            print(f"[+] Defaulting to local subnet targets: {len(self.targets)} IPs")

    def _parse_ip_config(self, filepath):
        ips = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # Check if CIDR notation
                    if "/" in line:
                        try:
                            net = ipaddress.ip_network(line, strict=False)
                            for ip in net.hosts():
                                ips.append(str(ip))
                        except ValueError as ve:
                            print(f"[-] Invalid subnet notation in scan.cfg: {line} ({ve})", file=sys.stderr)
                    # Check if IP range
                    elif "-" in line:
                        try:
                            start_str, end_str = line.split("-")
                            start = ipaddress.IPv4Address(start_str.strip())
                            end = ipaddress.IPv4Address(end_str.strip())
                            if int(start) <= int(end):
                                for ip_int in range(int(start), int(end) + 1):
                                    ips.append(str(ipaddress.IPv4Address(ip_int)))
                            else:
                                print(f"[-] Invalid IP range in scan.cfg (start > end): {line}", file=sys.stderr)
                        except ValueError as ve:
                            print(f"[-] Invalid range notation in scan.cfg: {line} ({ve})", file=sys.stderr)
                    # Single IP
                    else:
                        try:
                            ip = ipaddress.IPv4Address(line)
                            ips.append(str(ip))
                        except ValueError:
                            print(f"[-] Invalid IP address in scan.cfg: {line}", file=sys.stderr)
        except Exception as e:
            print(f"[-] Error reading {filepath}: {e}", file=sys.stderr)
        return list(dict.fromkeys(ips)) # remove duplicates

    def _generate_local_subnet_ips(self):
        # Fallback to local subnet. Let's try to detect network or default to 192.168.0.0/24
        try:
            import socket
            # Create a connection to a dummy external address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Form subnet from local IP
            ip_parts = local_ip.split(".")
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            net = ipaddress.ip_network(subnet, strict=False)
            return [str(ip) for ip in net.hosts()]
        except Exception:
            # Absolute fallback
            net = ipaddress.ip_network("192.168.0.0/24", strict=False)
            return [str(ip) for ip in net.hosts()]

    def load_credentials(self):
        # We also check if there is a config in ../d-camminer/config/user.cfg
        paths_to_try = [self.user_cfg_path]
        parent_user_cfg = os.path.join("..", "d-camminer", "config", "user.cfg")
        if parent_user_cfg not in paths_to_try:
            paths_to_try.append(parent_user_cfg)
            
        credentials_loaded = False
        
        # Always allow unauthenticated access test (None, None) and (None, "")
        self.credentials = [(None, None), ("", "")]
        
        for path in paths_to_try:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split(":", 1)
                            user = parts[0].strip() if parts[0].strip() else ""
                            pwd = parts[1].strip() if len(parts) > 1 and parts[1].strip() else ""
                            
                            # Map special cases
                            if user == "" and pwd == "":
                                continue
                            
                            cred = (user, pwd)
                            if cred not in self.credentials:
                                self.credentials.append(cred)
                    credentials_loaded = True
                    # Subtracting the two empty test pairs
                    loaded_count = len(self.credentials) - 2
                    print(f"[+] Loaded credentials from {path} ({loaded_count} custom credential combinations)")
                    break
                except Exception as e:
                    print(f"[-] Error reading credentials from {path}: {e}", file=sys.stderr)

        if not credentials_loaded:
            print(f"[-] Warning: user.cfg not found in searched paths {paths_to_try}. Using minimal defaults.", file=sys.stderr)
            # Standard manufacturer fallback credentials
            fallbacks = [
                ("admin", "admin"),
                ("admin", "12345"),
                ("admin", "123456"),
                ("admin", "password"),
                ("admin", ""),
                ("Admin", ""),
            ]
            for f in fallbacks:
                if f not in self.credentials:
                    self.credentials.append(f)
