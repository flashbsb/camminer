# CamMiner 🔍🎥

**CamMiner** is a modular, high-performance Python utility designed to discover, probe, and assess IP cameras on your local network. It identifies stream protocols (RTSP), resolves video/audio profiles, captures camera snapshots, runs network diagnostic pings, measures live video throughput, and grades each device's suitability for NVR (e.g. Shinobi) or Home Assistant integration.

---

## Flowchart & Architecture

The scanner conducts discovery, authentication, probing, performance sweeps, and report consolidation through the following pipeline:

```mermaid
flowchart TD
    subgraph ST1["1. Initialization & Pre-Checks"]
        A["🚀 Launch camminer.py"] --> B["🔍 Check Runtime & Dependencies<br/><i>Python 3.8+, ffmpeg, ffprobe, ping</i>"]
        B --> C["⚙️ Load Configuration & CLI Flags<br/><i>scan.cfg, user.cfg, settings.json</i>"]
    end

    subgraph ST2["2. Discovery Phase"]
        C --> D["🌐 WS-Discovery Multicast UDP"]
        C --> E["🔌 Concurrent TCP Port Scanner<br/><i>RTSP 554, HTTP 80/8080, ONVIF 3702</i>"]
        D --> F["📋 Active IP Target Aggregator"]
        E --> F
    end

    subgraph ST3["3. Deep Camera Probing"]
        F --> G{"ONVIF Endpoint Detected?"}
        G -- Yes --> H["🔑 Query ONVIF Device Info & Profiles<br/><i>GetStreamUri & GetSnapshotUri</i>"]
        H --> I{"RTSP Requires Auth?"}
        I -- Yes --> J["🔓 Authenticate RTSP Credentials<br/><i>Basic & Digest Auth Sweep</i>"]
        I -- No --> K["🎥 Confirmed Active Stream URI"]
        J --> K
        G -- No --> L["⚡ Raw Socket RTSP Path Brute-Force<br/><i>DESCRIBE Request Sweeps</i>"]
        L --> K
        K --> M["📊 Extract Media Specifications<br/><i>ffprobe & SDP Attributes</i>"]
    end

    subgraph ST4["4. Performance & Media Generation"]
        M --> N{"Performance Suite Enabled?"}
        N -- Yes --> O["📡 Network Ping Diagnostics<br/><i>Latency, Packet Loss & Jitter</i>"]
        O --> P["📈 Live Stream Throughput & FPS<br/><i>FFmpeg Stream Copy Dump</i>"]
        N -- No --> Q{"Media Capture Enabled?"}
        P --> Q
        Q -- Yes --> R["📸 Frame Snapshots (.jpg) & Video Clips (.mp4)<br/><i>Multi-Threaded Worker Pool</i>"]
        Q -- No --> S["⚙️ Reports Consolidation"]
        R --> S
    end

    subgraph ST5["5. Output & Dashboard Reports"]
        S --> T["🖥️ Terminal Data Table"]
        S --> U["📊 CSV & JSON Datasets"]
        S --> V["🎨 Interactive HTML Lightbox Dashboard"]
        V --> W["📁 Update index.html History Index"]
    end

    style ST1 fill:#1e293b,stroke:#3b82f6,stroke-width:2px,color:#f8fafc
    style ST2 fill:#1e293b,stroke:#8b5cf6,stroke-width:2px,color:#f8fafc
    style ST3 fill:#1e293b,stroke:#ec4899,stroke-width:2px,color:#f8fafc
    style ST4 fill:#1e293b,stroke:#10b981,stroke-width:2px,color:#f8fafc
    style ST5 fill:#1e293b,stroke:#f59e0b,stroke-width:2px,color:#f8fafc
```

---

## Features

- **Automated Dependency Pre-Checks**: Validates Python 3.8+, required standard library modules, and system binaries (`ffmpeg`, `ffprobe`, `ping`) on startup, guiding users on missing dependencies.
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

## Prerequisites & Installation

- **Python 3.8+**
- **FFmpeg & FFprobe**: Ensure both binaries are installed and available in system PATH.
  - Linux (Debian/Ubuntu): `sudo apt update && sudo apt install -y ffmpeg iputils-ping python3`
  - macOS (Homebrew): `brew install ffmpeg`
  - Arch Linux: `sudo pacman -S ffmpeg iputils python`
- See [requirements.txt](file:///home/flashbsb/camminer/requirements.txt) for a complete list of required system binaries and standard Python modules.
- `camminer.py` automatically performs dependency checks upon launch and prints installation guidance if any required dependency is missing.

---

## Configuration

Configurations are stored inside the `config/` directory:

1. **`config/settings.json`**:
   - `timeout`: Default network socket timeout (seconds).
   - `socket_timeout`: Global default socket timeout for HTTP & urllib requests (seconds).
   - `port_scan_timeout`: TCP port scanning connection timeout per port (seconds).
   - `ws_discovery_timeout`: ONVIF WS-Discovery UDP multicast socket timeout (seconds).
   - `rtsp_socket_timeout`: RTSP stream connection timeout (seconds).
   - `ffmpeg_socket_timeout`: FFmpeg/FFprobe socket timeout for stream probing and media capture (seconds).
   - `threads`: Thread pool size for parallel network host scanning.
   - `media_max_threads`: Worker thread limit for parallel camera image snapshot and video clip generation.
   - `snapshot_jpeg_quality`: Quality scale factor for JPEG snapshot captures (`1` highest to `31` lowest).
   - `perf_ping_count`: Count of ping packets sent per target during performance tests.
   - `perf_stream_duration`: Length of live ffmpeg stream copy tests and video clip recordings (seconds).
   - `export_formats`: Default report output formats (`terminal`, `csv`, `html`, `json`).
   - `scan_ports`: Target TCP ports (e.g. `554`, `8554`, `80`, `8080`, `8888`, `5000`, `3702`).
   - `common_rtsp_paths`: Common RTSP paths list to check during stream brute forcing.
   
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
./camminer.py --user adminabc --password passwordabc
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
