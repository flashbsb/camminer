import os
import csv
import json
import sys
from datetime import datetime

def format_terminal_table(camera_reports, perf_reports=None):
    """
    Renders a structured ASCII table of findings to print in the console.
    """
    lines = []
    lines.append("\n" + "="*112)
    lines.append(f"| {'CAMERA IP':<15} | {'MANUFACTURER':<14} | {'MODEL':<14} | {'NVR SCORE':<9} | {'MAIN STREAM':<15} | {'SUBSTREAM':<15} | {'STATUS':<20} |")
    lines.append("="*112)
    
    for cam in camera_reports:
        ip = cam["ip"]
        manufacturer = cam["manufacturer"][:14]
        model = cam["model"][:14]
        score = f"{cam['nvr_score']}%"
        
        main_info = "N/A"
        main_stream = cam["streams"].get("main")
        if main_stream:
            main_info = f"{main_stream['resolution']} ({main_stream['codec'].split()[0]})"
            
        sub_info = "N/A"
        sub_stream = cam["streams"].get("substream")
        if sub_stream:
            sub_info = f"{sub_stream['resolution']} ({sub_stream['codec'].split()[0]})"
            
        status = "No Streams Found"
        if cam["streams"]:
            status = "Ready" if cam["nvr_score"] >= 90 else "Warnings"
            if perf_reports and ip in perf_reports:
                m_perf = perf_reports[ip]["streams"].get("main")
                if m_perf:
                    status = f"{status} ({m_perf['status']})"
                    
        lines.append(f"| {ip:<15} | {manufacturer:<14} | {model:<14} | {score:<9} | {main_info:<15} | {sub_info:<15} | {status:<20} |")
        
    lines.append("="*112)
    return "\n".join(lines)

def export_csv(output_path, camera_reports, perf_reports=None):
    """
    Exports details to a flat CSV file.
    """
    fieldnames = [
        "ip", "manufacturer", "model", "firmware", "username", "password", "nvr_score",
        "main_url", "main_resolution", "main_codec", "main_fps",
        "sub_url", "sub_resolution", "sub_codec", "sub_fps",
        "ping_avg_rtt_ms", "ping_loss_percent", "ping_jitter_ms",
        "main_test_fps", "main_test_bitrate_kbps", "main_test_status",
        "sub_test_fps", "sub_test_bitrate_kbps", "sub_test_status",
        "recommendations"
    ]
    
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for cam in camera_reports:
                ip = cam["ip"]
                main_st = cam["streams"].get("main", {})
                sub_st = cam["streams"].get("substream", {})
                
                perf = perf_reports.get(ip, {}) if perf_reports else {}
                perf_streams = perf.get("streams", {})
                main_perf = perf_streams.get("main", {})
                sub_perf = perf_streams.get("substream", {})
                
                row = {
                    "ip": ip,
                    "manufacturer": cam["manufacturer"],
                    "model": cam["model"],
                    "firmware": cam["firmware"],
                    "username": cam["username"] or "",
                    "password": cam["password"] or "",
                    "nvr_score": cam["nvr_score"],
                    "main_url": main_st.get("url", ""),
                    "main_resolution": main_st.get("resolution", ""),
                    "main_codec": main_st.get("codec", ""),
                    "main_fps": main_st.get("fps", ""),
                    "sub_url": sub_st.get("url", ""),
                    "sub_resolution": sub_st.get("resolution", ""),
                    "sub_codec": sub_st.get("codec", ""),
                    "sub_fps": sub_st.get("fps", ""),
                    "ping_avg_rtt_ms": perf.get("ping_avg_rtt", ""),
                    "ping_loss_percent": perf.get("ping_loss", ""),
                    "ping_jitter_ms": perf.get("ping_jitter", ""),
                    "main_test_fps": main_perf.get("fps", ""),
                    "main_test_bitrate_kbps": main_perf.get("bitrate_kbps", ""),
                    "main_test_status": main_perf.get("status", ""),
                    "sub_test_fps": sub_perf.get("fps", ""),
                    "sub_test_bitrate_kbps": sub_perf.get("bitrate_kbps", ""),
                    "sub_test_status": sub_perf.get("status", ""),
                    "recommendations": "; ".join(cam["recommendations"])
                }
                writer.writerow(row)
        print(f"[+] CSV report exported successfully to: {output_path}")
        return True
    except Exception as e:
        print(f"[-] Failed to export CSV report: {e}", file=sys.stderr)
        return False

def export_json(output_path, camera_reports, perf_reports=None):
    """
    Exports findings to a structured JSON file.
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        data = {
            "scan_time": datetime.now().isoformat(),
            "cameras": camera_reports,
            "performance": perf_reports or {}
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON report exported successfully to: {output_path}")
        return True
    except Exception as e:
        print(f"[-] Failed to export JSON report: {e}", file=sys.stderr)
        return False

def export_html(output_path, camera_reports, perf_reports=None):
    """
    Generates a premium, responsive dark-themed HTML dashboard reporting scan findings.
    """
    # Count statistics for summary cards
    total_cams = len(camera_reports)
    avg_score = 0
    ready_count = 0
    warning_count = 0
    error_count = 0
    codecs_dict = {}
    resolutions_dict = {}
    
    if total_cams > 0:
        avg_score = round(sum(c["nvr_score"] for c in camera_reports) / total_cams)
        
    for c in camera_reports:
        score = c["nvr_score"]
        if score >= 90:
            ready_count += 1
        elif score >= 50:
            warning_count += 1
        else:
            error_count += 1
            
        main_stream = c["streams"].get("main")
        if main_stream:
            codec = main_stream["codec"].split()[0].upper()
            codecs_dict[codec] = codecs_dict.get(codec, 0) + 1
            
            res = main_stream["resolution"]
            resolutions_dict[res] = resolutions_dict.get(res, 0) + 1
        else:
            codecs_dict["NONE"] = codecs_dict.get("NONE", 0) + 1
            resolutions_dict["NONE"] = resolutions_dict.get("NONE", 0) + 1

    # Format data lists for Chart.js
    codec_labels = list(codecs_dict.keys())
    codec_data = list(codecs_dict.values())
    res_labels = list(resolutions_dict.keys())
    res_data = list(resolutions_dict.values())
    
    # HTML template structure
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CamMiner - Camera Assessment Report</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-color: #0d0f12;
            --surface-color: #161a22;
            --surface-hover: #1e2430;
            --primary: #4f46e5;
            --primary-light: #6366f1;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --text-main: #f3f4f6;
            --text-secondary: #9ca3af;
            --border-color: #2d3748;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }}

        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }}

        header h1 {{
            font-size: 2.2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #a5b4fc, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        header p {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-top: 0.25rem;
        }}

        .timestamp {{
            font-family: 'JetBrains Mono', monospace;
            background-color: var(--surface-color);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            font-size: 0.85rem;
            color: var(--primary-light);
        }}

        /* Summary Cards Grid */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .card {{
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}

        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background-color: var(--primary);
        }}

        .card.card-success::before {{ background-color: var(--success); }}
        .card.card-warning::before {{ background-color: var(--warning); }}
        .card.card-error::before {{ background-color: var(--error); }}

        .card-title {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}

        .card-value {{
            font-size: 2.2rem;
            font-weight: 700;
        }}

        /* Charts Layout */
        .charts-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .chart-card {{
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            min-height: 320px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}

        .chart-card h3 {{
            align-self: flex-start;
            margin-bottom: 1rem;
            font-size: 1.1rem;
            color: var(--text-secondary);
        }}

        .chart-wrapper {{
            width: 100%;
            max-width: 280px;
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        /* Filter Controls */
        .controls-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}

        .filter-buttons {{
            display: flex;
            gap: 0.5rem;
        }}

        .filter-btn {{
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            font-family: inherit;
            transition: all 0.2s ease;
        }}

        .filter-btn:hover, .filter-btn.active {{
            background-color: var(--primary);
            color: var(--text-main);
            border-color: var(--primary);
        }}

        /* Tables & Lists */
        .table-container {{
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 2.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th {{
            background-color: rgba(255, 255, 255, 0.02);
            border-bottom: 2px solid var(--border-color);
            padding: 1rem 1.25rem;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}

        td {{
            padding: 1.25rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.95rem;
            vertical-align: top;
        }}

        tr {{
            transition: background-color 0.15s ease;
        }}

        tr:hover {{
            background-color: var(--surface-hover);
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }}

        .badge-success {{ background-color: rgba(16, 185, 129, 0.15); color: var(--success); }}
        .badge-warning {{ background-color: rgba(245, 158, 11, 0.15); color: var(--warning); }}
        .badge-error {{ background-color: rgba(239, 68, 68, 0.15); color: var(--error); }}
        .badge-info {{ background-color: rgba(99, 102, 241, 0.15); color: var(--primary-light); }}

        /* Compatibility Bar */
        .score-bar-container {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .score-num {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
            width: 38px;
        }}

        .score-bar {{
            height: 6px;
            width: 80px;
            background-color: #2d3748;
            border-radius: 3px;
            overflow: hidden;
        }}

        .score-fill {{
            height: 100%;
            border-radius: 3px;
        }}

        /* Monospace lists */
        .mono-list {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            list-style: none;
            color: var(--text-secondary);
        }}

        .mono-list li {{
            margin-bottom: 0.25rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 320px;
        }}

        .url-code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            word-break: break-all;
            white-space: normal !important;
            user-select: all;
            cursor: pointer;
            background-color: rgba(255, 255, 255, 0.05);
            padding: 0.15rem 0.35rem;
            border-radius: 4px;
            display: inline-block;
            max-width: 100%;
            transition: color 0.15s ease, background-color 0.15s ease;
        }}

        .url-code:hover {{
            background-color: rgba(255, 255, 255, 0.12);
            color: var(--primary-light);
        }}

        /* Recommendation Section */
        .recs-container {{
            max-width: 450px;
        }}

        .recs-list {{
            list-style-type: none;
            font-size: 0.85rem;
        }}

        .recs-list li {{
            margin-bottom: 0.4rem;
            padding-left: 1.25rem;
            position: relative;
        }}

        .recs-list li::before {{
            content: '•';
            position: absolute;
            left: 0.25rem;
            color: var(--primary-light);
            font-weight: bold;
        }}

        /* Performance Metrics Details */
        .perf-details {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .perf-details .latency-pill {{
            display: inline-block;
            margin-right: 0.5rem;
            border-radius: 4px;
            padding: 0.1rem 0.3rem;
            background-color: rgba(255,255,255,0.05);
        }}

        .perf-table-row {{
            background-color: rgba(255, 255, 255, 0.01);
            border-top: 1px dashed rgba(255,255,255,0.05);
        }}

        /* Scrollbar */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            background: var(--bg-color);
        }}
        ::-webkit-scrollbar-thumb {{
            background: var(--border-color);
            border-radius: 4px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: #4a5568;
        }}
    </style>
</head>
<body>

    <header>
        <div>
            <h1>Antigravity CamMiner</h1>
            <p>IP Camera Network Assessment and NVR Compatibility Analysis Report</p>
        </div>
        <div class="timestamp">
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </header>

    <!-- Summary Statistics -->
    <div class="summary-grid">
        <div class="card">
            <div class="card-title">Total Cameras</div>
            <div class="card-value">{total_cams}</div>
        </div>
        <div class="card card-success">
            <div class="card-title">Ready (>=90%)</div>
            <div class="card-value">{ready_count}</div>
        </div>
        <div class="card card-warning">
            <div class="card-title">Warnings (50-89%)</div>
            <div class="card-value">{warning_count}</div>
        </div>
        <div class="card card-error">
            <div class="card-title">Suboptimal (<50%)</div>
            <div class="card-value">{error_count}</div>
        </div>
        <div class="card">
            <div class="card-title">Average Compatibility</div>
            <div class="card-value">{avg_score}%</div>
        </div>
    </div>

    <!-- Visual Charts -->
    <div class="charts-container">
        <div class="chart-card">
            <h3>Video Codecs (Main Stream)</h3>
            <div class="chart-wrapper">
                <canvas id="codecsChart"></canvas>
            </div>
        </div>
        <div class="chart-card">
            <h3>Resolutions Distribution</h3>
            <div class="chart-wrapper">
                <canvas id="resolutionsChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Controls -->
    <div class="controls-row">
        <h3>Camera Scan & Diagnostics Table</h3>
        <div class="filter-buttons">
            <button class="filter-btn active" onclick="filterTable('all')">All</button>
            <button class="filter-btn" onclick="filterTable('ready')">Ready</button>
            <button class="filter-btn" onclick="filterTable('warning')">Warnings</button>
            <button class="filter-btn" onclick="filterTable('error')">Suboptimal</button>
        </div>
    </div>

    <!-- Main Results Table -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Camera Network Details</th>
                    <th>Credentials Used</th>
                    <th>Main Stream Details</th>
                    <th>Substream Details</th>
                    <th>Performance Stats</th>
                    <th>NVR score</th>
                    <th>Recommendations & Diagnostics</th>
                </tr>
            </thead>
            <tbody id="camTableBody">
"""
    
    for c in camera_reports:
        ip = c["ip"]
        manufacturer = c["manufacturer"]
        model = c["model"]
        fw = c["firmware"]
        
        # User details
        user_desc = "None"
        if c["username"] or c["password"]:
            user_desc = f"<code>{c['username']}:{c['password']}</code>"
            
        badge_class = "badge-success"
        score_color = "var(--success)"
        filter_status = "ready"
        
        if c["nvr_score"] < 50:
            badge_class = "badge-error"
            score_color = "var(--error)"
            filter_status = "error"
        elif c["nvr_score"] < 90:
            badge_class = "badge-warning"
            score_color = "var(--warning)"
            filter_status = "warning"
            
        # Streams
        main_stream = c["streams"].get("main", {})
        sub_stream = c["streams"].get("substream", {})
        
        main_res = main_stream.get("resolution", "N/A")
        main_codec = main_stream.get("codec", "N/A")
        main_fps = main_stream.get("fps", "N/A")
        main_url = main_stream.get("url", "")
        main_snap = main_stream.get("snapshot_url", "None")
        main_snap_html = ""
        if main_snap and main_snap != "None":
            main_snap_html = f'<li style="white-space: normal !important; max-width: 320px; margin-top:0.25rem;">Snapshot: <code class="url-code" onclick="copyToClipboard(\'{main_snap}\', this)" title="Click to copy snapshot URL">{main_snap}</code></li>'
        
        sub_res = sub_stream.get("resolution", "N/A")
        sub_codec = sub_stream.get("codec", "N/A")
        sub_fps = sub_stream.get("fps", "N/A")
        sub_url = sub_stream.get("url", "")
        sub_snap = sub_stream.get("snapshot_url", "None")
        sub_snap_html = ""
        if sub_snap and sub_snap != "None":
            sub_snap_html = f'<li style="white-space: normal !important; max-width: 320px; margin-top:0.25rem;">Snapshot: <code class="url-code" onclick="copyToClipboard(\'{sub_snap}\', this)" title="Click to copy snapshot URL">{sub_snap}</code></li>'
        
        # Performance info
        perf_html = "<i>No Performance Test Run</i>"
        if perf_reports and ip in perf_reports:
            p = perf_reports[ip]
            m_perf = p["streams"].get("main", {})
            s_perf = p["streams"].get("substream", {})
            
            perf_html = f"""
            <div class="perf-details">
                <div>Ping RTT: <b>{p['ping_avg_rtt']:.1f}ms</b></div>
                <div>Loss: <b style="color: { 'var(--error)' if p['ping_loss'] > 0 else 'var(--text-main)' }">{p['ping_loss']}%</b></div>
                <div>Jitter: <b>{p['ping_jitter']:.2f}ms</b></div>
            """
            if m_perf:
                perf_html += f'<div style="margin-top:0.35rem">Main Stream: {m_perf.get("fps")} FPS | {m_perf.get("bitrate_kbps")} kbps</div>'
                perf_html += f'<div>Status: <span class="badge { "badge-success" if m_perf.get("status") == "Stable" else "badge-warning" }">{m_perf.get("status")}</span></div>'
            perf_html += "</div>"
            
        # Recommendations
        recs_list_html = ""
        for rec in c["recommendations"]:
            class_mod = ""
            if "[Security Alert]" in rec or "[Error]" in rec:
                class_mod = 'style="color:var(--error); font-weight:500;"'
            elif "[Security Warning]" in rec or "[Performance Warning]" in rec:
                class_mod = 'style="color:var(--warning); font-weight:500;"'
            elif "[Success]" in rec:
                class_mod = 'style="color:var(--success);"'
            recs_list_html += f"<li {class_mod}>{rec}</li>"
            
        html_content += f"""
                <tr data-status="{filter_status}">
                    <td>
                        <b style="font-size:1.05rem">{ip}</b><br>
                        <span style="color:var(--text-secondary); font-size:0.85rem">
                            Vendor: {manufacturer}<br>
                            Model: {model}<br>
                            FW: {fw}
                        </span>
                    </td>
                    <td style="font-size:0.85rem">
                        {user_desc}
                    </td>
                    <td>
                        <ul class="mono-list">
                            <li>Res: <b>{main_res}</b></li>
                            <li>Codec: {main_codec}</li>
                            <li>Nominal: {main_fps} FPS</li>
                            <li>Token: <span class="badge badge-info">{main_stream.get('token', 'N/A')}</span></li>
                            <li style="white-space: normal !important; max-width: 320px;">URL: <code class="url-code" onclick="copyToClipboard('{main_url}', this)" title="Click to copy full RTSP URL">{main_url}</code></li>
                            {main_snap_html}
                        </ul>
                    </td>
                    <td>
                        <ul class="mono-list">
                            <li>Res: <b>{sub_res}</b></li>
                            <li>Codec: {sub_codec}</li>
                            <li>Nominal: {sub_fps} FPS</li>
                            <li>Token: <span class="badge badge-info">{sub_stream.get('token', 'N/A')}</span></li>
                            <li style="white-space: normal !important; max-width: 320px;">URL: <code class="url-code" onclick="copyToClipboard('{sub_url}', this)" title="Click to copy full RTSP URL">{sub_url}</code></li>
                            {sub_snap_html}
                        </ul>
                    </td>
                    <td>
                        {perf_html}
                    </td>
                    <td>
                        <div class="score-bar-container">
                            <span class="score-num" style="color:{score_color}">{c['nvr_score']}%</span>
                            <div class="score-bar">
                                <div class="score-fill" style="width:{c['nvr_score']}%; background-color:{score_color}"></div>
                            </div>
                        </div>
                    </td>
                    <td>
                        <div class="recs-container">
                            <ul class="recs-list">
                                {recs_list_html}
                            </ul>
                        </div>
                    </td>
                </tr>
        """
        
    html_content += f"""
            </tbody>
        </table>
    </div>

    <script>
        function copyToClipboard(text, el) {{
            navigator.clipboard.writeText(text).then(() => {{
                const originalText = el.innerText;
                el.innerText = "Copied!";
                el.style.color = "#10b981"; // var(--success)
                setTimeout(() => {{
                    el.innerText = originalText;
                    el.style.color = "";
                }}, 1200);
            }}).catch(err => {{
                console.error("Failed to copy: ", err);
            }});
        }}

        // Filters the table displays
        function filterTable(status) {{
            const rows = document.querySelectorAll("#camTableBody tr");
            const buttons = document.querySelectorAll(".filter-btn");
            
            // Set active button
            buttons.forEach(btn => {{
                if (btn.innerText.toLowerCase() === status || (status === 'all' && btn.innerText.toLowerCase() === 'all')) {{
                    btn.classList.add("active");
                }} else {{
                    btn.classList.remove("active");
                }}
            }});
            
            rows.forEach(row => {{
                if (status === "all") {{
                    row.style.display = "";
                }} else {{
                    if (row.getAttribute("data-status") === status) {{
                        row.style.display = "";
                    }} else {{
                        row.style.display = "none";
                    }}
                }}
            }});
        }}

        // Codec Chart
        const codecsCtx = document.getElementById('codecsChart').getContext('2d');
        const codecsChart = new Chart(codecsCtx, {{
            type: 'pie',
            data: {{
                labels: {json.dumps(codec_labels)},
                datasets: [{{
                    data: {json.dumps(codec_data)},
                    backgroundColor: [
                        '#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#6b7280'
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{
                            color: '#9ca3af',
                            font: {{ family: 'Outfit' }}
                        }}
                    }}
                }}
            }}
        }});

        // Resolutions Chart
        const resCtx = document.getElementById('resolutionsChart').getContext('2d');
        const resChart = new Chart(resCtx, {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(res_labels)},
                datasets: [{{
                    data: {json.dumps(res_data)},
                    backgroundColor: [
                        '#6366f1', '#ec4899', '#14b8a6', '#f59e0b', '#6b7280'
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{
                            color: '#9ca3af',
                            font: {{ family: 'Outfit' }}
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML Dashboard report exported successfully to: {output_path}")
        
        # Rebuild index.html archive page in the same folder
        update_index_html(os.path.dirname(output_path))
        
        return True
    except Exception as e:
        print(f"[-] Failed to export HTML dashboard: {e}", file=sys.stderr)
        return False

def update_index_html(output_dir):
    """
    Scans output_dir for JSON and HTML reports, parses summaries, and builds/updates an index.html index file.
    """
    import glob
    print("[*] Rebuilding index.html archive page in output directory...")
    
    # 1. Load details from JSON reports
    search_pattern = os.path.join(output_dir, "scan_report_*.json")
    json_files = glob.glob(search_pattern)
    
    scans_history = []
    processed_html_files = set()
    
    for jpath in json_files:
        try:
            with open(jpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            scan_time_str = data.get("scan_time", "")
            try:
                dt = datetime.fromisoformat(scan_time_str)
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                base = os.path.basename(jpath)
                parts = base.split("_")
                if len(parts) >= 4:
                    date_part = parts[2]
                    time_part = parts[3].split(".")[0]
                    formatted_time = f"{date_part[0:4]}-{date_part[4:6]}-{date_part[6:8]} {time_part[0:2]}:{time_part[2:4]}:{time_part[4:6]}"
                else:
                    formatted_time = "Unknown"
                    
            cameras = data.get("cameras", [])
            total_cams = len(cameras)
            active_cams = sum(1 for c in cameras if c.get("streams"))
            
            avg_score = 0
            if total_cams > 0:
                avg_score = round(sum(c.get("nvr_score", 0) for c in cameras) / total_cams)
                
            ips = [c.get("ip") for c in cameras]
            ips_str = ", ".join(ips)
            
            base_name = os.path.basename(jpath).replace(".json", ".html")
            html_path = base_name
            
            if os.path.exists(os.path.join(output_dir, base_name)):
                scans_history.append({
                    "time": formatted_time,
                    "raw_time": scan_time_str,
                    "total": f"{total_cams}",
                    "active": f"{active_cams}",
                    "score": avg_score,
                    "ips": ips_str,
                    "link": html_path
                })
                processed_html_files.add(base_name)
        except Exception as e:
            print(f"[-] Warning: Failed to parse history from {jpath}: {e}", file=sys.stderr)
            
    # 2. Check for legacy HTML reports that don't have matching JSON files
    search_pattern_html = os.path.join(output_dir, "scan_report_*.html")
    html_files = glob.glob(search_pattern_html)
    
    for hpath in html_files:
        base_name = os.path.basename(hpath)
        if base_name not in processed_html_files:
            formatted_time = "Unknown"
            raw_time_fallback = base_name
            
            parts = base_name.split("_")
            if len(parts) >= 4:
                date_part = parts[2]
                time_part = parts[3].split(".")[0]
                formatted_time = f"{date_part[0:4]}-{date_part[4:6]}-{date_part[6:8]} {time_part[0:2]}:{time_part[2:4]}:{time_part[4:6]}"
                raw_time_fallback = f"{date_part[0:4]}-{date_part[4:6]}-{date_part[6:8]}T{time_part[0:2]}:{time_part[2:4]}:{time_part[4:6]}"
                
            scans_history.append({
                "time": formatted_time,
                "raw_time": raw_time_fallback,
                "total": "N/A",
                "active": "N/A",
                "score": "N/A",
                "ips": "Legacy Report (No JSON Metadata)",
                "link": base_name
            })
            
    scans_history.sort(key=lambda x: x.get("raw_time", ""), reverse=True)
    
    total_scans = len(scans_history)
    last_scan = scans_history[0]["time"] if total_scans > 0 else "N/A"
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CamMiner - Scan Reports Archive</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0d0f12;
            --surface-color: #161a22;
            --surface-hover: #1e2430;
            --primary: #4f46e5;
            --primary-light: #6366f1;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --text-main: #f3f4f6;
            --text-secondary: #9ca3af;
            --border-color: #2d3748;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem;
        }}

        header {{
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
        }}

        header h1 {{
            font-size: 2.2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #a5b4fc, #6366f1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        header p {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-top: 0.25rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .card {{
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background-color: var(--primary);
        }}

        .card-title {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}

        .card-value {{
            font-size: 2.2rem;
            font-weight: 700;
        }}

        .table-container {{
            background-color: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th {{
            background-color: rgba(255, 255, 255, 0.02);
            border-bottom: 2px solid var(--border-color);
            padding: 1rem 1.25rem;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}

        td {{
            padding: 1.25rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.95rem;
        }}

        tr {{
            transition: background-color 0.15s ease;
        }}

        tr:hover {{
            background-color: var(--surface-hover);
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }}

        .badge-success {{ background-color: rgba(16, 185, 129, 0.15); color: var(--success); }}
        .badge-warning {{ background-color: rgba(245, 158, 11, 0.15); color: var(--warning); }}
        .badge-error {{ background-color: rgba(239, 68, 68, 0.15); color: var(--error); }}

        .btn {{
            display: inline-block;
            background-color: var(--primary);
            color: var(--text-main);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: 500;
            transition: background-color 0.2s ease;
            border: 1px solid var(--primary);
            cursor: pointer;
        }}

        .btn:hover {{
            background-color: var(--primary-light);
            border-color: var(--primary-light);
        }}

        .mono-text {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>

    <header>
        <h1>CamMiner Reports Archive</h1>
        <p>Archive of compiled camera scan assessments and NVR readiness metrics</p>
    </header>

    <div class="summary-grid">
        <div class="card">
            <div class="card-title">Total Scans in History</div>
            <div class="card-value">{total_scans}</div>
        </div>
        <div class="card">
            <div class="card-title">Latest Run Time</div>
            <div class="card-value" style="font-size: 1.5rem; margin-top: 0.75rem;">{last_scan}</div>
        </div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Scan Timestamp</th>
                    <th>Cameras (Total / Active)</th>
                    <th>Avg Compatibility Score</th>
                    <th>Target IPs Scanned</th>
                    <th>Report Link</th>
                </tr>
            </thead>
            <tbody>
"""
    
    if not scans_history:
        html_content += """
                <tr>
                    <td colspan="5" style="text-align: center; color: var(--text-secondary); padding: 2rem;">
                        No previous scan reports found in this folder.
                    </td>
                </tr>
        """
    else:
        for scan in scans_history:
            score = scan["score"]
            badge_class = "badge-success"
            score_display = f"{score}%"
            if score == "N/A":
                badge_class = "badge-warning"
                score_display = "N/A"
            elif score < 50:
                badge_class = "badge-error"
            elif score < 90:
                badge_class = "badge-warning"
                
            html_content += f"""
                <tr>
                    <td><b>{scan['time']}</b></td>
                    <td class="mono-text">{scan['total']} total / {scan['active']} active</td>
                    <td>
                        <span class="badge {badge_class}">{score_display}</span>
                    </td>
                    <td class="mono-text" title="{scan['ips']}">{scan['ips'][:60]}{'...' if len(scan['ips']) > 60 else ''}</td>
                    <td>
                        <a href="{scan['link']}" class="btn" target="_blank">Open Report</a>
                    </td>
                </tr>
            """
            
    html_content += """
            </tbody>
        </table>
    </div>

</body>
</html>
"""
    
    try:
        index_path = os.path.join(output_dir, "index.html")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] Index archive page successfully updated: {index_path}")
        return True
    except Exception as e:
        print(f"[-] Failed to update index.html archive: {e}", file=sys.stderr)
        return False
