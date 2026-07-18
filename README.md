# Antigravity CamMiner 🔍🎥

**Antigravity CamMiner** is a modular, high-performance Python utility designed to discover, probe, and assess IP cameras on your local network. It identifies stream protocols (RTSP), resolves video/audio profiles, captures camera snapshots, runs network diagnostic pings, measures live video throughput, and grades each device's suitability for NVR (e.g. Shinobi) or Home Assistant integration.

---

## Flowchart & Architecture

The scanner conducts discovery, authentication, probing, performance sweeps, and report consolidation through the following pipeline:

```mermaid
sequenceDiagram
    participant CLI as camminer.py
    participant C as Config (scan.cfg/settings.json)
    participant S as Scanner (TCP/ONVIF Discovery)
    participant P as Prober (ONVIF/RTSP)
    participant PF as Performance (Ping/FFmpeg)
    participant M as Media (Snapshot/Video Clips)
    participant E as Exporters (HTML/CSV/Index)
    
    CLI->>C: Load configurations, CLI flags & settings
    CLI->>S: Run TCP Port Scan & ONVIF Multicast
    S-->>CLI: Return active hosts list
    
    loop For each host in parallel (Thread Pool)
        CLI->>P: Probe camera details
        alt ONVIF detected
            P->>P: GetDeviceInformation & GetProfiles
            P->>P: GetStreamUri & GetSnapshotUri
            alt Stream URI requires auth
                P->>P: authenticate_rtsp_url (Basic/Digest checks)
            end
        else ONVIF failed / not present
            P->>P: Brute-force RTSP paths (Raw socket DESCRIBE)
        end
        P->>P: Run single-stream ffprobe / SDP parser
        P-->>CLI: Return camera details report
    end
    
    opt Performance Testing (default: enabled, bypass with --no-perf)
        loop For each camera with active streams
            CLI->>PF: Run Ping packet loss & Jitter checks
            CLI->>PF: Run FFmpeg stream copy throughput tests
            PF-->>CLI: Return performance report
        end
    end
    
    opt Media Asset Generation (default: enabled, bypass with --no-image / --no-video)
        loop For each camera in parallel (ThreadPoolExecutor)
            CLI->>M: Capture HTTP snapshot / FFmpeg single-frame grab
            CLI->>M: Record short MP4 video clip via FFmpeg
            M-->>CLI: Return media file relative paths
        end
    end
    
    CLI->>E: Export Terminal, CSV, JSON, and HTML reports
    CLI->>E: Update index.html consolidated archive
```

---

## Features

- **Concurrent Multi-Protocol Scanning**: Discover cameras concurrently using WS-Discovery (multicast UDP) and TCP port scanning (`ThreadPoolExecutor`).
- **Fast Raw Socket RTSP Probing**: Brute forces RTSP URLs using lightweight socket-level `DESCRIBE` requests in milliseconds, only running `ffprobe` on confirmed working streams.
- **RTSP Digest Authentication Support**: Custom challenge-response algorithm handles Basic/Digest RTSP challenges natively.
- **Open-ONVIF Credential Fallback**: If a camera has open ONVIF endpoints but locks the RTSP stream, the prober automatically brute-forces the RTSP stream using user credentials and embeds the working set.
- **ONVIF GetSnapshotUri Resolution**: Resolves and maps camera snapshot URLs (HTTP) and profile tokens.
- **Default Performance Suite (`--no-perf`)**: Ping statistics (latency, loss, jitter) and stream throughput testing are enabled by default.
- **Automated Media Captures (`--no-image` / `--no-video`)**: Automatically captures single-frame `.jpg` snapshots and records short `.mp4` video clips from active streams in parallel.
- **Responsive HTML Lightbox Modal**: Interactive snapshot image thumbnails and inline video previews in HTML dashboard reports expand to `90vw x 90vh` on click without cropping.
- **Target & Credentials Overrides (`--target`, `--user`, `--password`)**: Target single IPs or CIDR blocks (`192.168.0.0/24`) and test specific credentials directly from the command line.
- **Consolidated Archives (`index.html`)**: Automatically generates a historical database index linking all past scan reports.

---

## Prerequisites

- **Python 3.8+**
- **FFmpeg & FFprobe**: Ensure both binaries are installed and available in the system PATH.
  - Linux: `sudo apt install ffmpeg`
  - macOS: `brew install ffmpeg`

---

## Configuration

Configurations are stored inside the `config/` directory:

1. **`config/settings.json`**:
   - `timeout`: Network socket timeouts.
   - `threads`: Thread pool size for parallel probing.
   - `scan_ports`: Target TCP ports (e.g. `554`, `80`, `8080`, `3702`).
   - `perf_ping_count`: Count of ping packets sent per target during performance tests.
   - `perf_stream_duration`: Length of live ffmpeg stream copy tests and video clip recordings (in seconds).
   - `common_rtsp_paths`: Common RTSP paths list to check.
   
2. **`config/scan.cfg`**:
   - List of IP addresses, ranges (e.g., `192.168.0.10-192.168.0.50`), or subnets (e.g., `192.168.0.0/24`) to target.
   
3. **`config/user.cfg`**:
   - List of credentials (format `username:password`) tested for ONVIF and RTSP access.

---

## Usage

### Run a Standard Full Scan (Probing, Performance & Media Capture):
```bash
./camminer.py
```

### Scan Specific Targets (Bypassing `scan.cfg`):
```bash
./camminer.py --target 192.168.0.33 --target 192.168.0.128/25
```

### Test Specific Credentials (Bypassing `user.cfg`):
```bash
./camminer.py --user adminabc --password senhaabc
```

### Fast Scan Disabling Performance or Media Generation:
```bash
./camminer.py --no-perf --no-image --no-video
```

### Specify Custom Settings, Configuration, and Outputs:
```bash
./camminer.py \
  -c ../custom_scan.cfg \
  -u ../custom_user.cfg \
  -s ../custom_settings.json \
  -o ../output_reports_dir/
```

---

## Output Reports

Outputs are saved in the configured output directory (default: `infos/`):
- **`scan_report_*.csv`**: Flat sheet dataset containing resolved URLs, codecs, pings, media paths, and NVR ratings.
- **`scan_report_*.json`**: Serialized database of scanned metrics.
- **`scan_report_*.html`**: Interactive responsive dashboard showcasing summary distributions, chart graphics, filterable tables, copyable links, and lightbox media viewers.
- **`media/`**: Subdirectory containing snapshot images (`.jpg`) and video clips (`.mp4`).
- **`index.html`**: Consolidated historical log linking all past scans in chronological order.
