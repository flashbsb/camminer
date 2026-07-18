import os
import sys
import subprocess
import urllib.request
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def build_authenticated_url(url, user, pwd):
    if not url or not user or "@" in url:
        return url
    parts = url.split("://", 1)
    if len(parts) == 2:
        return f"{parts[0]}://{user}:{pwd}@{parts[1]}"
    return url

def capture_single_image(ip, stream_url, snapshot_url, media_dir, username=None, password=None, credentials_list=None, video_filepath=None, timestamp=None, timeout=5.0):
    """
    Captures a snapshot image for a camera stream.
    1. Tries HTTP download from snapshot_url using HTTP Basic & Digest authentication.
    2. Fallback: Extracts frame directly from recorded local video MP4 file if available (0 extra RTSP connections!).
    3. Fallback: Captures single frame via FFmpeg RTSP stream grab.
    Returns relative path to the image file (e.g. 'media/snapshot_192_168_0_22_20260717_192458.jpg') or None.
    """
    os.makedirs(media_dir, exist_ok=True)
    ts_suffix = f"_{timestamp}" if timestamp else ""
    filename = f"snapshot_{ip.replace('.', '_')}{ts_suffix}.jpg"
    filepath = os.path.join(media_dir, filename)
    rel_path = os.path.join("media", filename)

    # Prepare credentials candidate list: [(username, password), ...]
    creds_to_try = []
    if "@" in (stream_url or ""):
        creds_to_try.append((None, None))
    else:
        if username is not None:
            creds_to_try.append((username, password or ""))
        if credentials_list:
            for u, p in credentials_list[:3]:  # Top candidates
                if (u, p) not in creds_to_try:
                    creds_to_try.append((u, p or ""))
        if (None, None) not in creds_to_try:
            creds_to_try.insert(0, (None, None))

    # 1. First choice: Extract 1 frame from recorded local video MP4 file if available (instant 50ms, 0 extra network calls!)
    if video_filepath and os.path.exists(video_filepath) and os.path.getsize(video_filepath) > 1000:
        import time
        for _attempt in range(2):
            time.sleep(0.3)  # Ensure file handles flush completely
            cmd_extract = [
                "ffmpeg", "-y",
                "-i", video_filepath,
                "-frames:v", "1",
                "-update", "1",
                "-q:v", "2",
                filepath
            ]
            try:
                subprocess.run(cmd_extract, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5.0)
                if os.path.exists(filepath) and os.path.getsize(filepath) > 500:
                    return rel_path
            except Exception:
                pass

    # 2. Try HTTP snapshot URL if available
    if snapshot_url and snapshot_url.lower() != "none" and snapshot_url.startswith("http"):
        for u, p in creds_to_try:
            try:
                auth_url = build_authenticated_url(snapshot_url, u, p) if u else snapshot_url
                passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                if u and p:
                    passman.add_password(None, auth_url, u, p)
                    passman.add_password(None, snapshot_url, u, p)
                
                auth_handler = urllib.request.HTTPDigestAuthHandler(passman)
                basic_handler = urllib.request.HTTPBasicAuthHandler(passman)
                opener = urllib.request.build_opener(auth_handler, basic_handler)
                req = urllib.request.Request(auth_url, headers={"User-Agent": "Antigravity-CamMiner/1.0"})
                with opener.open(req, timeout=1.5) as resp:
                    data = resp.read()
                    if data and len(data) > 500:
                        with open(filepath, "wb") as f:
                            f.write(data)
                        return rel_path
            except Exception:
                pass

    # 3. Fallback: FFmpeg RTSP frame grab
    if stream_url and stream_url.lower().startswith("rtsp"):
        for u, p in creds_to_try:
            target_url = build_authenticated_url(stream_url, u, p) if u else stream_url
            cmd = [
                "ffmpeg", "-y",
                "-rtsp_transport", "tcp",
                "-timeout", "2000000",
                "-i", target_url,
                "-update", "1",
                "-q:v", "2",
                filepath
            ]
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6.0)
                if os.path.exists(filepath) and os.path.getsize(filepath) > 500:
                    return rel_path
            except Exception:
                pass

    return None

def capture_single_video(ip, stream_url, media_dir, username=None, password=None, credentials_list=None, timestamp=None, duration=5, timeout=8.0):
    """
    Records an MP4 video clip from the camera RTSP stream URL using ffmpeg.
    First attempts stream copy (-c copy). Fallback to ultrafast H.264 transcode if stream copy fails.
    Returns relative path to the video file (e.g. 'media/clip_192_168_0_22_20260717_192458.mp4') or None.
    """
    if not stream_url or not stream_url.lower().startswith("rtsp"):
        return None

    os.makedirs(media_dir, exist_ok=True)
    ts_suffix = f"_{timestamp}" if timestamp else ""
    filename = f"clip_{ip.replace('.', '_')}{ts_suffix}.mp4"
    filepath = os.path.join(media_dir, filename)
    rel_path = os.path.join("media", filename)

    exec_timeout = float(duration) + 4.0

    creds_to_try = []
    if "@" in stream_url:
        creds_to_try.append((None, None))
    else:
        if username is not None:
            creds_to_try.append((username, password or ""))
        if credentials_list:
            for u, p in credentials_list[:3]:
                if (u, p) not in creds_to_try:
                    creds_to_try.append((u, p or ""))
        if (None, None) not in creds_to_try:
            creds_to_try.insert(0, (None, None))

    for u, p in creds_to_try:
        target_url = build_authenticated_url(stream_url, u, p) if u else stream_url

        # 1. Try stream copy into MP4
        cmd_copy = [
            "ffmpeg", "-y",
            "-rtsp_transport", "tcp",
            "-timeout", "2000000",
            "-i", target_url,
            "-t", str(duration),
            "-c", "copy",
            "-an",
            filepath
        ]
        try:
            subprocess.run(cmd_copy, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=exec_timeout)
            if os.path.exists(filepath) and os.path.getsize(filepath) > 1000:
                return rel_path
        except Exception:
            pass

        # 2. Fallback to ultrafast transcode
        cmd_transcode = [
            "ffmpeg", "-y",
            "-rtsp_transport", "tcp",
            "-timeout", "2000000",
            "-i", target_url,
            "-t", str(duration),
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-pix_fmt", "yuv420p",
            "-an",
            filepath
        ]
        try:
            subprocess.run(cmd_transcode, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=exec_timeout + 3.0)
            if os.path.exists(filepath) and os.path.getsize(filepath) > 1000:
                return rel_path
        except Exception:
            pass

    return None

def process_camera_media(ip, camera_data, output_dir, credentials_list=None, timestamp=None, run_image=True, run_video=True, duration=5):
    """
    Processes image snapshot and video clip for a single camera report entry.
    Returns (ip, image_rel_path, video_rel_path).
    """
    media_dir = os.path.join(output_dir, "media")
    
    main_stream = camera_data.get("streams", {}).get("main", {})
    sub_stream = camera_data.get("streams", {}).get("substream", {})
    
    stream_url = main_stream.get("url") or sub_stream.get("url")
    snapshot_url = main_stream.get("snapshot_url") or sub_stream.get("snapshot_url")
    username = camera_data.get("username")
    password = camera_data.get("password")

    image_rel_path = None
    video_rel_path = None
    video_abs_path = None

    # First, record video clip if enabled
    if run_video:
        video_rel_path = capture_single_video(
            ip, stream_url, media_dir, 
            username=username, password=password, 
            credentials_list=credentials_list, 
            timestamp=timestamp, duration=duration
        )
        if video_rel_path:
            video_abs_path = os.path.join(output_dir, video_rel_path)

    # Next, capture snapshot (uses HTTP auth -> local MP4 frame extraction -> RTSP grab fallback)
    if run_image:
        image_rel_path = capture_single_image(
            ip, stream_url, snapshot_url, media_dir, 
            username=username, password=password, 
            credentials_list=credentials_list,
            video_filepath=video_abs_path, 
            timestamp=timestamp
        )

    return ip, image_rel_path, video_rel_path

def generate_media_assets(camera_reports, output_dir, credentials_list=None, timestamp=None, run_image=True, run_video=True, duration=5):
    """
    Concurrently captures images and videos for all active discovered cameras.
    Modifies camera_reports in-place adding 'image_file' and 'video_file'.
    """
    if not run_image and not run_video:
        return

    print("\n" + "="*80)
    print("RUNNING CAMERA MEDIA CAPTURE SUITE (SNAPSHOTS & CLIPS)")
    print("="*80)

    active_cameras = [cam for cam in camera_reports if cam.get("streams")]
    if not active_cameras:
        print("[-] No active camera streams available for media capture.")
        return

    with ThreadPoolExecutor(max_workers=min(10, len(active_cameras))) as executor:
        futures = {}
        for cam in active_cameras:
            ip = cam["ip"]
            print(f"[*] Dispatching media capture tasks for {ip}...")
            f = executor.submit(process_camera_media, ip, cam, output_dir, credentials_list, timestamp, run_image, run_video, duration)
            futures[f] = cam

        for future in as_completed(futures):
            cam = futures[future]
            ip = cam["ip"]
            try:
                cam_ip, image_file, video_file = future.result()
                cam["image_file"] = image_file
                cam["video_file"] = video_file
                
                img_desc = image_file if image_file else "Failed/Disabled"
                vid_desc = video_file if video_file else "Failed/Disabled"
                print(f"  [+] Media for {ip} -> Image: {img_desc} | Video: {vid_desc}")
            except Exception as e:
                print(f"  [-] Error capturing media for {ip}: {e}", file=sys.stderr)
