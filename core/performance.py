import subprocess
import re
import os
import sys
import time

class PerformanceTester:
    def __init__(self, ip, streams, ping_count=5, stream_duration=5, timeout=5.0, ffmpeg_socket_timeout=3.0):
        self.ip = ip
        self.streams = streams
        self.ping_count = ping_count
        self.stream_duration = stream_duration
        self.timeout = timeout
        self.ffmpeg_socket_timeout = ffmpeg_socket_timeout
        
        self.ping_loss = 100.0
        self.ping_avg_rtt = 0.0
        self.ping_jitter = 0.0
        
        self.stream_perf = {}  # stream_type -> {fps: 0, bitrate_kbps: 0, status: ""}

    def run_tests(self):
        """
        Executes network and stream performance tests.
        """
        print(f"\n[*] Running performance tests on {self.ip}...")
        self.test_network_ping()
        self.test_streams_performance()
        
        return {
            "ping_loss": self.ping_loss,
            "ping_avg_rtt": self.ping_avg_rtt,
            "ping_jitter": self.ping_jitter,
            "streams": self.stream_perf
        }

    def test_network_ping(self):
        """
        Runs ping test and parses statistics (packet loss, avg RTT, jitter).
        """
        print(f"  [*] Pinging host ({self.ping_count} packets)...")
        # Run ping command (using standard flags for Linux)
        cmd = ["ping", "-c", str(self.ping_count), "-W", "2", self.ip]
        
        try:
            startupinfo = None
            if os.name == 'nt':
                cmd = ["ping", "-n", str(self.ping_count), "-w", "2000", self.ip]
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12.0, startupinfo=startupinfo)
            out = res.stdout
            
            # Parse Linux ping output format:
            # "5 packets transmitted, 5 received, 0% packet loss, time 4005ms"
            # "rtt min/avg/max/mdev = 1.234/5.678/9.012/0.345 ms"
            loss_match = re.search(r'(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss', out, re.IGNORECASE)
            if loss_match:
                self.ping_loss = float(loss_match.group(1))
                
            rtt_match = re.search(r'(?:rtt|round-trip)\s*min/avg/max/(?:mdev|stddev)\s*=\s*[\d\.]+/([\d\.]+)/[\d\.]+/([\d\.]+)', out, re.IGNORECASE)
            if rtt_match:
                self.ping_avg_rtt = float(rtt_match.group(1))
                self.ping_jitter = float(rtt_match.group(2)) # standard deviation serves as a proxy for jitter
            else:
                # Windows ping parsing: "Average = 12ms"
                win_avg = re.search(r'Average\s*=\s*(\d+)ms', out, re.IGNORECASE)
                if win_avg:
                    times = [float(t) for t in re.findall(r'time[=<](\d+)ms', out, re.IGNORECASE)]
                    if times:
                        self.ping_avg_rtt = sum(times) / len(times)
                        self.ping_loss = 100.0 - (len(times) * 20.0)
                        
                        if len(times) > 1:
                            mean = self.ping_avg_rtt
                            self.ping_jitter = (sum((x - mean) ** 2 for x in times) / (len(times) - 1)) ** 0.5
                            
            if self.ping_loss < 100.0:
                print(f"    [+] Packet Loss: {self.ping_loss}% | Avg Latency: {self.ping_avg_rtt:.1f}ms | Jitter: {self.ping_jitter:.2f}ms")
            else:
                print("    [-] Host ping failed (no response or unreachable).")
                self.ping_loss = 100.0
        except Exception as e:
            print(f"    [-] Ping test error: {e}", file=sys.stderr)
            self.ping_loss = 100.0

    def test_streams_performance(self):
        """
        Runs short stream captures to measure frame rate consistency and network throughput.
        """
        if not self.streams:
            return
            
        for name, stream_info in self.streams.items():
            url = stream_info["url"]
            print(f"  [*] Testing {name.capitalize()} stream throughput & frame delivery ({self.stream_duration} seconds)...")
            
            # Use ffmpeg to record statistics about the stream
            # We copy codecs and dump to null. This reads raw frames without decoding CPU overhead.
            stimeout_us = str(int(self.ffmpeg_socket_timeout * 1000000))
            cmd = [
                "ffmpeg",
                "-rtsp_transport", "tcp",
                "-stimeout", stimeout_us,
                "-y",
                "-i", url,
                "-t", str(self.stream_duration),         # customizable test duration
                "-c", "copy",
                "-f", "null",
                "-"
            ]
            
            t_start = time.time()
            try:
                startupinfo = None
                if os.name == 'nt':
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.stream_duration + 5.0,  # timeout in case stream freezes
                    startupinfo=startupinfo
                )
                
                t_elapsed = time.time() - t_start
                stderr_output = res.stderr.decode('utf-8', errors='ignore')
                
                # Parse frames count and size from output
                # Ffmpeg progress line example:
                # frame=  125 fps= 25 q=-0.0 size=N/A time=00:00:05.00 bitrate=N/A speed=   1x
                # Or for stream copy:
                # frame=  125 fps=25 q=-0.0 Lsize=    4521kB time=00:00:05.00 bitrate= 7412.8kbits/s speed=   1x
                
                frames = 0
                bitrate_kbps = 0.0
                
                # Search for frame count in final summary (lines starting with 'frame=')
                frame_matches = re.findall(r"frame=\s*(\d+)", stderr_output)
                if frame_matches:
                    frames = int(frame_matches[-1])
                    
                # Search for bitrate in final summary
                bitrate_matches = re.findall(r"bitrate=\s*([\d\.]+)\s*kbits/s", stderr_output)
                if bitrate_matches:
                    bitrate_kbps = float(bitrate_matches[-1])
                else:
                    # Estimate based on size and elapsed time if size is parsed
                    # E.g. Lsize=    4521kB
                    size_kb = 0.0
                    size_matches = re.findall(r"Lsize=\s*(\d+)kB", stderr_output)
                    if size_matches:
                        size_kb = float(size_matches[-1])
                    else:
                        # Try to parse from video:XXXX units audio:YYYY units summary output
                        v_match = re.search(r"video:\s*([\d\.]+)\s*([a-zA-Z]+)", stderr_output)
                        a_match = re.search(r"audio:\s*([\d\.]+)\s*([a-zA-Z]+)", stderr_output)
                        
                        def parse_unit_to_kb(val_str, unit):
                            try:
                                val = float(val_str)
                                u = unit.lower()
                                if 'm' in u:
                                    return val * 1024.0
                                elif 'k' in u:
                                    return val
                                return val / 1024.0
                            except Exception:
                                return 0.0
                                
                        if v_match:
                            size_kb += parse_unit_to_kb(v_match.group(1), v_match.group(2))
                        if a_match:
                            size_kb += parse_unit_to_kb(a_match.group(1), a_match.group(2))
                            
                    if size_kb > 0 and t_elapsed > 0:
                        # Size in kbits = size_kb * 8
                        bitrate_kbps = (size_kb * 8) / t_elapsed
                
                avg_fps = round(frames / t_elapsed, 1) if t_elapsed > 0 else 0.0
                
                # Check for warnings or frame drops
                status = "Stable"
                if res.returncode != 0:
                    status = "Stream Interrupted"
                elif frames == 0:
                    status = "No Frames Received"
                elif avg_fps < 5.0:
                    status = "Critical Frame Drop"
                elif avg_fps < 12.0:
                    status = "Low Framerate"
                    
                self.stream_perf[name] = {
                    "fps": avg_fps,
                    "bitrate_kbps": round(bitrate_kbps, 1),
                    "status": status,
                    "frames_received": frames,
                    "duration": round(t_elapsed, 1)
                }
                
                print(f"    [+] FPS: {avg_fps} | Throughput: {bitrate_kbps:.1f} kbps | Status: {status}")
            except subprocess.TimeoutExpired:
                print("    [-] Test timed out. Stream connection is highly unstable or dead.")
                self.stream_perf[name] = {
                    "fps": 0.0,
                    "bitrate_kbps": 0.0,
                    "status": "Timeout / Dead Stream",
                    "frames_received": 0,
                    "duration": self.timeout
                }
            except Exception as e:
                print(f"    [-] Stream performance test error: {e}", file=sys.stderr)
                self.stream_perf[name] = {
                    "fps": 0.0,
                    "bitrate_kbps": 0.0,
                    "status": f"Error: {str(e)}",
                    "frames_received": 0,
                    "duration": 0
                }

def run_performance_suite(camera_reports, ping_count=5, stream_duration=5, timeout=5.0, ffmpeg_socket_timeout=3.0):
    """
    Runs the performance tester on each successfully probed camera.
    """
    print("\n" + "="*80)
    print("RUNNING CAMERA PERFORMANCE AND STABILITY SUITE")
    print("="*80)
    
    perf_reports = {}
    for report in camera_reports:
        ip = report["ip"]
        streams = report["streams"]
        
        # Only run tests if camera has working streams
        if streams:
            tester = PerformanceTester(
                ip, 
                streams, 
                ping_count=ping_count, 
                stream_duration=stream_duration, 
                timeout=timeout,
                ffmpeg_socket_timeout=ffmpeg_socket_timeout
            )
            perf_reports[ip] = tester.run_tests()
        else:
            print(f"\n[-] Skipping performance tests for {ip} (no active RTSP streams found).")
            
    return perf_reports
