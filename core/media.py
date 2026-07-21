import os
import sys
import subprocess
import urllib.request
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

def _get_sp_kwargs():
    kwargs = {}
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs['startupinfo'] = startupinfo
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    return kwargs

def build_authenticated_url(url, user, pwd):
    if not url or not user or "@" in url:
        return url
    parts = url.split("://", 1)
    if len(parts) == 2:
        return f"{parts[0]}://{user}:{pwd}@{parts[1]}"
    return url

def capture_single_image(ip, stream_url, snapshot_url, media_dir, username=None, password=None, credentials_list=None, video_filepath=None, timestamp=None, timeout=5.0, jpeg_quality=2, ffmpeg_socket_timeout=3.0):
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
    sp_kwargs = _get_sp_kwargs()

    # Prepare credentials candidate list: [(username, password), ...]
    creds_to_try = []
    if username is not None or password is not None:
        creds_to_try.append((username, password or ""))
    if credentials_list:
        for u, p in credentials_list:
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
                "-q:v", str(jpeg_quality),
                filepath
            ]
            try:
                subprocess.run(cmd_extract, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5.0, **sp_kwargs)
                if os.path.exists(filepath) and os.path.getsize(filepath) > 500:
                    return rel_path
            except Exception:
                pass

    # 2. Try HTTP snapshot URL if available
    if snapshot_url and snapshot_url.lower() != "none" and snapshot_url.startswith("http"):
        import base64
        for u, p in creds_to_try:
            try:
                auth_url = build_authenticated_url(snapshot_url, u, p) if u else snapshot_url
                headers = {"User-Agent": "CamMiner/1.0"}
                if u is not None and p is not None:
                    auth_str = base64.b64encode(f"{u}:{p}".encode('utf-8')).decode('utf-8')
                    headers["Authorization"] = f"Basic {auth_str}"
                
                req = urllib.request.Request(auth_url, headers=headers)
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    data = resp.read()
                    if data and len(data) > 500:
                        with open(filepath, "wb") as f:
                            f.write(data)
                        return rel_path
            except Exception:
                try:
                    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                    if u and p:
                        passman.add_password(None, snapshot_url, u, p)
                    auth_handler = urllib.request.HTTPDigestAuthHandler(passman)
                    basic_handler = urllib.request.HTTPBasicAuthHandler(passman)
                    opener = urllib.request.build_opener(auth_handler, basic_handler)
                    req = urllib.request.Request(snapshot_url, headers={"User-Agent": "CamMiner/1.0"})
                    with opener.open(req, timeout=3.0) as resp:
                        data = resp.read()
                        if data and len(data) > 500:
                            with open(filepath, "wb") as f:
                                f.write(data)
                            return rel_path
                except Exception:
                    pass

    # 3. Fallback: FFmpeg RTSP frame grab
    if stream_url and stream_url.lower().startswith("rtsp"):
        stimeout_us = str(int(ffmpeg_socket_timeout * 1000000))
        for u, p in creds_to_try:
            target_url = build_authenticated_url(stream_url, u, p) if u else stream_url
            cmd = [
                "ffmpeg", "-y",
                "-rtsp_transport", "tcp",
                "-stimeout", stimeout_us,
                "-i", target_url,
                "-frames:v", "1",
                "-update", "1",
                "-q:v", str(jpeg_quality),
                filepath
            ]
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=6.0, **sp_kwargs)
                if os.path.exists(filepath) and os.path.getsize(filepath) > 500:
                    return rel_path
            except Exception:
                pass

    return None

def capture_single_video(ip, stream_url, media_dir, username=None, password=None, credentials_list=None, timestamp=None, duration=5, timeout=8.0, ffmpeg_socket_timeout=3.0):
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
    sp_kwargs = _get_sp_kwargs()

    exec_timeout = float(duration) + 5.0
    stimeout_us = str(int(ffmpeg_socket_timeout * 1000000))

    creds_to_try = []
    if username is not None or password is not None:
        creds_to_try.append((username, password or ""))
    if credentials_list:
        for u, p in credentials_list:
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
            "-stimeout", stimeout_us,
            "-i", target_url,
            "-t", str(duration),
            "-c", "copy",
            "-an",
            filepath
        ]
        try:
            subprocess.run(cmd_copy, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=exec_timeout, **sp_kwargs)
            if os.path.exists(filepath) and os.path.getsize(filepath) > 1000:
                return rel_path
        except Exception:
            pass

        # 2. Fallback to ultrafast transcode
        cmd_transcode = [
            "ffmpeg", "-y",
            "-rtsp_transport", "tcp",
            "-stimeout", stimeout_us,
            "-i", target_url,
            "-t", str(duration),
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-pix_fmt", "yuv420p",
            "-an",
            filepath
        ]
        try:
            subprocess.run(cmd_transcode, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=exec_timeout + 3.0, **sp_kwargs)
            if os.path.exists(filepath) and os.path.getsize(filepath) > 1000:
                return rel_path
        except Exception:
            pass

    return None

def process_camera_media(ip, camera_data, output_dir, credentials_list=None, timestamp=None, run_image=True, run_video=True, duration=5, jpeg_quality=2, ffmpeg_socket_timeout=3.0):
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
            timestamp=timestamp, duration=duration,
            ffmpeg_socket_timeout=ffmpeg_socket_timeout
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
            timestamp=timestamp,
            jpeg_quality=jpeg_quality,
            ffmpeg_socket_timeout=ffmpeg_socket_timeout
        )

    return ip, image_rel_path, video_rel_path

def generate_media_assets(camera_reports, output_dir, credentials_list=None, timestamp=None, run_image=True, run_video=True, duration=5, max_workers=10, jpeg_quality=2, ffmpeg_socket_timeout=3.0):
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

    worker_count = min(max_workers, len(active_cameras)) if max_workers > 0 else len(active_cameras)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {}
        for cam in active_cameras:
            ip = cam["ip"]
            print(f"[*] Dispatching media capture tasks for {ip}...")
            f = executor.submit(process_camera_media, ip, cam, output_dir, credentials_list, timestamp, run_image, run_video, duration, jpeg_quality, ffmpeg_socket_timeout)
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
