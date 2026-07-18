# Changelog

All notable changes to the **Antigravity CamMiner** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] - 2026-07-17

### Added
- **Default Performance Suite (`--no-perf`)**: Replaced `--perf` CLI flag with `--no-perf`. Performance and throughput analysis suite is now active by default on all runs unless `--no-perf` is passed.
- **Automated Snapshot Image Capture (`--no-image`)**: Automatically grabs single-frame snapshot images (`.jpg`) via HTTP ONVIF endpoints or FFmpeg RTSP stream grab. Enabled by default, can be disabled using `--no-image`.
- **Automated Short Video Recording (`--no-video`)**: Automatically records short MP4 video clips (`.mp4`) from active RTSP streams for `perf_stream_duration` seconds. Enabled by default, can be disabled using `--no-video`.
- **Responsive HTML Lightbox Modal**: Embedded interactive snapshot image thumbnails and inline video previews in camera report cards. Clicking any snapshot or video opens a full-viewport modal overlay (`90vw x 90vh; object-fit: contain`) maintaining aspect ratio without cropping.
- **Parallel Media Extraction**: Multi-threaded worker pool executing snapshot and video clip generation concurrently across active cameras.

## [1.2.2] - 2026-07-16

### Added
- **Command Line IP Targets Override (`--target`)**: Bypasses `scan.cfg` and WS-Discovery automatically when targets are explicitly supplied, accepting single IP addresses or CIDR block networks.
- **Command Line Credentials Override (`--user` & `--password`)**: Enables testing a specific credentials pair on target cameras, bypassing `user.cfg` file queries.

## [1.2.1] - 2026-07-16

### Added
- **Non-Intrusive SDP Metadata Parsing**: Added raw Session Description Protocol (SDP) body parser mapping media stream attributes (codecs: `H264`/`H265`, nominal frame rate, audio attributes) directly from raw `DESCRIBE` responses.
- **SDP Fallback Verification on Wildcards**: Wildcard RTSP servers are now validated using SDP metadata filters (checking for presence of `m=video`/`a=rtpmap`), bypassing stream channel connection limit timeouts on active cameras streaming to NVRs/Shinobi.

### Fixed
- **Regex WWW-Authenticate Header Parser**: Replaced fragile string line-splitting matches with case-insensitive regex to capture WWW-Authenticate headers, solving digest credential sweeps on Xiongmai camera systems.
- **Robust Realm & Nonce Parser**: Enhanced challenge token extraction to handle unquoted realms/nonces returned by proprietary camera protocols.
- **HTML Toggle Filter Button Highlighting**: Fixed active CSS class toggling in the dashboard HTML dashboard code when filtering status rows.

## [1.2.0] - 2026-07-16

### Added
- **Consolidated Scan History (`index.html`)**: Automatically creates or updates an index archive page inside the output directory listing past scans, timestamps, camera totals, NVR scores, and quick-open buttons.
- **ONVIF Snapshot Support**: Resolves `GetSnapshotUri` via ONVIF media service, extracting snapshot URLs and rendering them as click-to-copy code blocks in the HTML report.
- **ONVIF Profile Tokens**: Displays resolved ONVIF tokens inside stream tables to help with Shinobi and NVR stream mapping.
- **Customizable Performance Suite**: Mapped ping packets count (`perf_ping_count`) and active ffmpeg stream capture duration (`perf_stream_duration`) to variables inside `config/settings.json`.
- **ASCII Startup Banner**: Stylish console art banner showing version and software title on execution start.
- **Changelog and README**: Project documentation including sequence flow diagrams.

### Fixed
- **Credentials Fallback on Open ONVIF**: Implemented a credential verification check (`authenticate_rtsp_url`) on resolved ONVIF stream paths. If ONVIF was open without auth but the RTSP endpoint is protected, it automatically brute-forces RTSP using `user.cfg` credentials and embeds the working set into the stream URL, resolving "Unknown" codec/FPS issues.
- **Bitrate Parsing in Copy-Mode**: Added a regex parser to read video and audio sizes from `ffmpeg` copy-mode stderr logs (resolving the issue where throughput/bitrate returned `0.0 kbps` due to `Lsize=N/A` on null-muxing dumps).
- **Socket Hang Prevention**: Configured a global socket timeout of `4.0` seconds to prevent indefinite blocks during urllib or SOAP service requests on slower cameras.

---

## [1.1.0] - 2026-07-16

### Added
- **Raw Socket RTSP `DESCRIBE` Probing**: Replaced heavy subprocess-based `ffprobe` sweeps with raw TCP socket exchanges to check stream paths and credentials in milliseconds.
- **RTSP Digest Authentication Decoder**: Native MD5 challenge parser for cameras requesting Digest authentication.
- **Wildcard RTSP Server Detection**: Probes dummy paths to identify cameras responding `200 OK` on every route, filtering duplicate streams and preventing infinite loops.
- **Concurrent Host Discovery**: Multi-threaded host pinging and WS-Discovery (multicast UDP).

---

## [1.0.0] - 2026-07-16

### Added
- **Modular Package Structure**: Separated scanning, config management, probing, performance, and exporting layers.
- **Multiple Exporter Formats**: Terminal ASCII table, CSV sheet export, and premium HTML dashboard reports with Chart.js visualization.
- **Settings configuration files**: Settings loaded from `settings.json`, target IPs from `scan.cfg`, and credentials from `user.cfg`.
