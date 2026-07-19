import os
import sys
import json
import subprocess
import socket
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
import base64
import hashlib
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set global default socket timeout to prevent indefinite urllib or socket hangs
socket.setdefaulttimeout(4.0)

def get_ws_security_header(username, password):
    """
    Generates a WS-Security header using Digest authentication.
    """
    if not username:
        return ""
    
    nonce_bytes = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode('utf-8')
    created = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
    sha = hashlib.sha1()
    sha.update(nonce_bytes)
    sha.update(created.encode('utf-8'))
    sha.update(password.encode('utf-8'))
    digest = base64.b64encode(sha.digest()).decode('utf-8')
    
    return f"""
    <wsse:Security s:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
    """

def find_xml_elements(root, tag_name):
    """
    Helper to search XML elements ignoring namespaces.
    """
    results = []
    for elem in root.iter():
        local_name = elem.tag.split('}')[-1]
        if local_name == tag_name:
            results.append(elem)
    return results

def send_soap_request(url, xml_payload, timeout=3.0):
    """
    Sends a SOAP XML request to the specified ONVIF endpoint.
    """
    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "User-Agent": "CamMiner/1.0"
    }
    req = urllib.request.Request(url, data=xml_payload.encode('utf-8'), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read()
            if body and b"envelope" in body.lower():
                return body
            return None
    except Exception:
        # Fallback to text/xml for SOAP 1.1 if application/soap+xml fails
        headers["Content-Type"] = "text/xml; charset=utf-8"
        req = urllib.request.Request(url, data=xml_payload.encode('utf-8'), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read()
                if body and b"envelope" in body.lower():
                    return body
                return None
        except Exception:
            return None

def verify_rtsp_url_raw(rtsp_url, timeout=1.5):
    """
    Verifies an RTSP URL using raw sockets and RTSP DESCRIBE.
    Returns a tuple: (status, auth_header_required, response_headers)
    Where status is one of: "valid", "unauthorized", "not_found", "error"
    """
    try:
        parsed = urlparse(rtsp_url)
        host = parsed.hostname
        port = parsed.port or 554
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Check if URL has credentials embedded for Basic auth
        auth_header = ""
        if parsed.username:
            userpass = f"{parsed.username}:{parsed.password or ''}"
            auth_b64 = base64.b64encode(userpass.encode('utf-8')).decode('utf-8')
            auth_header = f"Authorization: Basic {auth_b64}\r\n"
            
        req = (
            f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: CamMiner/1.0\r\n"
            f"{auth_header}"
            f"Accept: application/sdp\r\n\r\n"
        )
        
        sock.sendall(req.encode('utf-8'))
        response = sock.recv(2048).decode('utf-8', errors='ignore')
        sock.close()
        
        if "RTSP/1.0 200" in response:
            return "valid", None, response
        elif "RTSP/1.0 401" in response:
            return "unauthorized", True, response
        elif "RTSP/1.0 404" in response:
            return "not_found", None, response
        else:
            return "invalid", None, response
    except Exception:
        return "error", None, None

def check_digest_auth(rtsp_url, username, password, www_auth_header, timeout=1.5):
    """
    Attempts Digest authentication using parameters from the WWW-Authenticate header.
    Returns (success, response_body)
    """
    try:
        parsed = urlparse(rtsp_url)
        host = parsed.hostname
        port = parsed.port or 554
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query
            
        method = "DESCRIBE"
        uri = f"rtsp://{host}:{port}{path}"
        
        realm = ""
        nonce = ""
        realm_match = re.search(r'realm="?([^",\s]+)"?', www_auth_header, re.IGNORECASE)
        if realm_match:
            realm = realm_match.group(1)
        nonce_match = re.search(r'nonce="?([^",\s]+)"?', www_auth_header, re.IGNORECASE)
        if nonce_match:
            nonce = nonce_match.group(1)
            
        if not realm or not nonce:
            return False, None
            
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode('utf-8')).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode('utf-8')).hexdigest()
        response_digest = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode('utf-8')).hexdigest()
        
        auth_str = (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{response_digest}"'
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        req = (
            f"DESCRIBE {uri} RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"User-Agent: CamMiner/1.0\r\n"
            f"Authorization: {auth_str}\r\n"
            f"Accept: application/sdp\r\n\r\n"
        )
        
        sock.sendall(req.encode('utf-8'))
        response = sock.recv(2048).decode('utf-8', errors='ignore')
        sock.close()
        
        success = "RTSP/1.0 200" in response
        return success, response
    except Exception:
        return False, None

def is_valid_sdp(sdp_text):
    """
    Checks if the response contains valid SDP configuration elements (e.g. video media payload metadata).
    """
    if not sdp_text:
        return False
    lower_text = sdp_text.lower()
    return "m=video" in lower_text or "a=rtpmap" in lower_text

def parse_sdp_metadata(sdp_text):
    """
    Parses video codec, framerate, and audio codec from an SDP body.
    Returns (codec, fps, audio)
    """
    codec = "Unknown"
    fps = "Unknown"
    audio = "Unknown"
    
    if not sdp_text:
        return codec, fps, audio
        
    lines = sdp_text.split("\n")
    current_media = None # "video" or "audio"
    
    for line in lines:
        line = line.strip()
        if line.startswith("m="):
            parts = line.split()
            if len(parts) > 0:
                current_media = parts[0][2:] # e.g. "video" or "audio"
                
        elif line.startswith("a=rtpmap:"):
            # e.g., a=rtpmap:96 H264/90000 or a=rtpmap:8 PCMA/8000
            parts = line[9:].split()
            if len(parts) >= 2:
                payload_type = parts[0]
                codec_part = parts[1].split("/")[0].upper()
                if current_media == "video":
                    codec = codec_part
                elif current_media == "audio":
                    audio = codec_part
                    
        elif line.startswith("a=framerate:"):
            # e.g., a=framerate:25 or a=framerate:15.0
            val_part = line[12:].strip()
            try:
                fps = int(float(val_part))
            except Exception:
                pass
                
        elif line.startswith("m=audio") and audio == "Unknown":
            # Check static payload types
            # RTP AVP 8 is PCMA, 0 is PCMU
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "RTP/AVP":
                pt = parts[3]
                if pt == "8":
                    audio = "PCMA"
                elif pt == "0":
                    audio = "PCMU"
                    
    return codec, fps, audio

def authenticate_rtsp_url(rtsp_url, credentials, timeout=1.5):
    """
    Tries different credentials on an RTSP URL. Returns the verified URL, working credentials, and SDP body,
    or (None, None, None) if none of the credentials work.
    """
    # 1. First check if it works without credentials
    status, auth_header, response = verify_rtsp_url_raw(rtsp_url, timeout=timeout)
    if status == "valid":
        return rtsp_url, ("", ""), response
        
    if status != "unauthorized" or not response:
        # If it's a 404 or connection error, no credentials can fix it
        return None, None, None
        
    parsed = urlparse(rtsp_url)
    host = parsed.hostname
    port = parsed.port or 554
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
        
    # Extract WWW-Authenticate header
    www_auth_match = re.search(r'WWW-Authenticate:\s*(.*)', response, re.IGNORECASE)
    www_auth = www_auth_match.group(0) if www_auth_match else ""
            
    # Try each credential pair
    for user, pwd in credentials:
        # 1. Try Basic Auth
        userpass = f"{user}:{pwd}"
        auth_b64 = base64.b64encode(userpass.encode('utf-8')).decode('utf-8')
        auth_header = f"Authorization: Basic {auth_b64}\r\n"
        
        req = (
            f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"User-Agent: CamMiner/1.0\r\n"
            f"{auth_header}"
            f"Accept: application/sdp\r\n\r\n"
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(req.encode('utf-8'))
            resp = sock.recv(2048).decode('utf-8', errors='ignore')
            sock.close()
            if "RTSP/1.0 200" in resp:
                # Basic Auth succeeded! Return URL with credentials embedded
                return f"rtsp://{user}:{pwd}@{host}:{port}{path}", (user, pwd), resp
        except Exception:
            pass
            
        # 2. Try Digest Auth if challenge present
        if www_auth and "digest" in www_auth.lower():
            success, resp_body = check_digest_auth(rtsp_url, user, pwd, www_auth, timeout=timeout)
            if success:
                # Digest Auth succeeded! Return URL with credentials embedded
                return f"rtsp://{user}:{pwd}@{host}:{port}{path}", (user, pwd), resp_body
                
    return None, None, None

class CameraProber:
    def __init__(self, ip, open_ports, credentials, settings):
        self.ip = ip
        self.open_ports = open_ports
        self.credentials = credentials
        self.settings = settings
        self.timeout = settings.timeout
        self.rtsp_socket_timeout = getattr(settings, "rtsp_socket_timeout", 1.5)
        self.ffmpeg_socket_timeout = getattr(settings, "ffmpeg_socket_timeout", 3.0)
        if hasattr(settings, "socket_timeout"):
            socket.setdefaulttimeout(settings.socket_timeout)
        
        # Discovered information
        self.manufacturer = "Unknown"
        self.model = "Generic IP Camera"
        self.firmware = "Unknown"
        self.auth_success = None  # (username, password)
        self.onvif_endpoint = None
        self.streams = {}  # type -> {url: "", resolution: "", codec: "", fps: 0, etc.}

    def probe(self):
        """
        Runs the discovery and probing pipeline for the camera.
        """
        print(f"[*] Probing camera at {self.ip}...")
        
        # Step 1: Detect ONVIF endpoint
        self.detect_onvif_service()
        
        # Step 2: Attempt ONVIF detailed probe if service exists
        onvif_success = False
        if self.onvif_endpoint:
            onvif_success = self.probe_onvif()
            
        # Step 3: Fallback to RTSP direct brute force if ONVIF failed or is not available
        if not onvif_success or not self.streams:
            self.brute_force_rtsp()
            
        # Step 4: Perform detailed stream analysis (ffprobe)
        self.analyze_discovered_streams()
        
        return self.get_summary()

    def detect_onvif_service(self):
        """
        Attempts to detect ONVIF HTTP endpoints on open ports concurrently.
        """
        http_ports = [p for p in self.open_ports if p in [80, 8080, 8888, 5000]]
        if not http_ports and 80 not in self.open_ports:
            http_ports = [80]
            
        urls = []
        for port in http_ports:
            urls.append(f"http://{self.ip}:{port}/onvif/device_service")
            urls.append(f"http://{self.ip}:{port}/device_service")
            
        soap = """
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
            <tds:GetDeviceInformation/>
          </s:Body>
        </s:Envelope>
        """
        
        def test_url(url):
            res = send_soap_request(url, soap, timeout=self.timeout)
            return url if res is not None else None
            
        with ThreadPoolExecutor(max_workers=len(urls) if urls else 1) as executor:
            futures = [executor.submit(test_url, url) for url in urls]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.onvif_endpoint = result
                        port = urlparse(result).port or 80
                        print(f"  [+] Found ONVIF service endpoint: {result}")
                        return
                except Exception:
                    pass

    def probe_onvif(self):
        """
        Probes the ONVIF service, tests credentials, extracts metadata and RTSP streams.
        """
        success = False
        media_service_url = None
        
        # Test credentials list against GetDeviceInformation
        for user, pwd in self.credentials:
            sec_header = get_ws_security_header(user, pwd)
            soap = f"""
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
              <s:Header>{sec_header}</s:Header>
              <s:Body xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                <tds:GetDeviceInformation/>
              </s:Body>
            </s:Envelope>
            """
            res = send_soap_request(self.onvif_endpoint, soap, timeout=self.timeout)
            if res is not None:
                try:
                    root = ET.fromstring(res)
                    # Check for Fault
                    faults = find_xml_elements(root, "Fault")
                    if faults:
                        continue
                    
                    self.auth_success = (user, pwd)
                    success = True
                    
                    manufacturer_elems = find_xml_elements(root, "Manufacturer")
                    model_elems = find_xml_elements(root, "Model")
                    fw_elems = find_xml_elements(root, "FirmwareVersion")
                    
                    if manufacturer_elems: self.manufacturer = manufacturer_elems[0].text
                    if model_elems: self.model = model_elems[0].text
                    if fw_elems: self.firmware = fw_elems[0].text
                    
                    cred_desc = f"'{user}:{pwd}'" if user is not None else "No Authentication"
                    print(f"  [+] ONVIF Auth successful using {cred_desc}")
                    print(f"  [+] Info: {self.manufacturer} | {self.model} | FW: {self.firmware}")
                    break
                except Exception as e:
                    print(f"  [-] XML Parse Error on ONVIF discovery response: {e}", file=sys.stderr)
                    
        if not success:
            print("  [-] ONVIF Auth failed for all credentials.")
            return False

        # Get capabilities to retrieve Media service URL
        sec_header = get_ws_security_header(self.auth_success[0], self.auth_success[1])
        soap = f"""
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Header>{sec_header}</s:Header>
          <s:Body xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
            <tds:GetCapabilities>
              <tds:Category>Media</tds:Category>
            </tds:GetCapabilities>
          </s:Body>
        </s:Envelope>
        """
        res = send_soap_request(self.onvif_endpoint, soap, timeout=self.timeout)
        if res is not None:
            try:
                root = ET.fromstring(res)
                media_elems = find_xml_elements(root, "XAddr")
                if media_elems:
                    media_service_url = media_elems[0].text
            except Exception:
                pass
                
        if not media_service_url:
            # Try GetServices request
            soap = f"""
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
              <s:Header>{sec_header}</s:Header>
              <s:Body xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
                <tds:GetServices>
                  <tds:IncludeCapability>false</tds:IncludeCapability>
                </tds:GetServices>
              </s:Body>
            </s:Envelope>
            """
            res = send_soap_request(self.onvif_endpoint, soap, timeout=self.timeout)
            if res is not None:
                try:
                    root = ET.fromstring(res)
                    services = find_xml_elements(root, "Service")
                    for srv in services:
                        namespace = find_xml_elements(srv, "Namespace")
                        xaddr = find_xml_elements(srv, "XAddr")
                        if namespace and xaddr and "media" in namespace[0].text.lower():
                            media_service_url = xaddr[0].text
                            break
                except Exception:
                    pass

        if not media_service_url:
            print("  [-] Could not resolve ONVIF Media Service URL.")
            return False

        # Get Media Profiles
        soap = f"""
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Header>{sec_header}</s:Header>
          <s:Body xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
            <trt:GetProfiles />
          </s:Body>
        </s:Envelope>
        """
        res = send_soap_request(media_service_url, soap, timeout=self.timeout)
        if res is not None:
            try:
                root = ET.fromstring(res)
                profiles = find_xml_elements(root, "Profiles")
                
                print(f"  [+] Found {len(profiles)} ONVIF Media Profile(s)")
                
                # Fetch stream URIs for each profile
                for i, profile in enumerate(profiles):
                    token = profile.attrib.get("token")
                    name = find_xml_elements(profile, "Name")
                    name_str = name[0].text if name else f"Profile_{token}"
                    
                    # Request Stream URI
                    soap_uri = f"""
                    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tt="http://www.onvif.org/ver10/schema">
                      <s:Header>{sec_header}</s:Header>
                      <s:Body xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
                        <trt:GetStreamUri>
                          <trt:StreamSetup>
                            <tt:Stream>RTP-Unicast</tt:Stream>
                            <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>
                          </trt:StreamSetup>
                          <trt:ProfileToken>{token}</trt:ProfileToken>
                        </trt:GetStreamUri>
                      </s:Body>
                    </s:Envelope>
                    """
                    res_uri = send_soap_request(media_service_url, soap_uri, timeout=self.timeout)
                    if res_uri is not None:
                        root_uri = ET.fromstring(res_uri)
                        uri_elems = find_xml_elements(root_uri, "Uri")
                        if uri_elems:
                            rtsp_url = uri_elems[0].text
                            
                            # Embed credentials into the RTSP URL
                            rtsp_cred_user = self.auth_success[0] if (self.auth_success and self.auth_success[0]) else None
                            rtsp_cred_pwd = self.auth_success[1] if (self.auth_success and self.auth_success[1]) else None
                            
                            # Try ONVIF credentials first if they exist
                            if rtsp_cred_user and "@" not in rtsp_url:
                                parts = rtsp_url.split("://", 1)
                                if len(parts) == 2:
                                    test_url = f"{parts[0]}://{rtsp_cred_user}:{rtsp_cred_pwd}@{parts[1]}"
                                    status, _, _ = verify_rtsp_url_raw(test_url, timeout=1.0)
                                    if status == "valid":
                                        rtsp_url = test_url
                                        
                            # If still unauthenticated or anonymous check fails, try all passwords from user.cfg
                            status, _, sdp_body = verify_rtsp_url_raw(rtsp_url, timeout=1.0)
                            if status != "valid":
                                verified_url, working_cred, sdp_body = authenticate_rtsp_url(rtsp_url, self.credentials)
                                if verified_url:
                                    rtsp_url = verified_url
                                    self.auth_success = working_cred
                                    
                            # Request Snapshot URI
                            soap_snapshot = f"""
                            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
                              <s:Header>{sec_header}</s:Header>
                              <s:Body xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
                                <trt:GetSnapshotUri>
                                  <trt:ProfileToken>{token}</trt:ProfileToken>
                                </trt:GetSnapshotUri>
                              </s:Body>
                            </s:Envelope>
                            """
                            res_snap = send_soap_request(media_service_url, soap_snapshot, timeout=self.timeout)
                            snapshot_url = "None"
                            if res_snap is not None:
                                try:
                                    root_snap = ET.fromstring(res_snap)
                                    snap_elems = find_xml_elements(root_snap, "Uri")
                                    if snap_elems:
                                        snapshot_url = snap_elems[0].text
                                        # Embed credentials into the Snapshot HTTP URL if needed
                                        snap_cred_user = self.auth_success[0] if (self.auth_success and self.auth_success[0]) else None
                                        snap_cred_pwd = self.auth_success[1] if (self.auth_success and self.auth_success[1]) else None
                                        if snap_cred_user and "@" not in snapshot_url and "http" in snapshot_url:
                                            parts = snapshot_url.split("://", 1)
                                            if len(parts) == 2:
                                                snapshot_url = f"{parts[0]}://{snap_cred_user}:{snap_cred_pwd}@{parts[1]}"
                                except Exception:
                                    pass

                            # Classify stream types dynamically
                            # Check resolution details if present in the profile XML
                            width = ""
                            height = ""
                            w_elems = find_xml_elements(profile, "Width")
                            h_elems = find_xml_elements(profile, "Height")
                            if w_elems: width = w_elems[0].text
                            if h_elems: height = h_elems[0].text
                            
                            # Parse fallback codec, fps, audio details from ONVIF profile configurations
                            codec = "Unknown"
                            fps = "Unknown"
                            audio = "Unknown"
                            
                            video_conf = find_xml_elements(profile, "VideoEncoderConfiguration")
                            if video_conf:
                                v_enc = find_xml_elements(video_conf[0], "Encoding")
                                if v_enc:
                                    codec = v_enc[0].text.upper()
                                v_fps = find_xml_elements(video_conf[0], "FrameRateLimit")
                                if v_fps:
                                    try:
                                        fps = int(float(v_fps[0].text))
                                    except Exception:
                                        pass
                                        
                            audio_conf = find_xml_elements(profile, "AudioEncoderConfiguration")
                            if audio_conf:
                                a_enc = find_xml_elements(audio_conf[0], "Encoding")
                                if a_enc:
                                    audio = a_enc[0].text.upper()
                                    
                            # Fallback to parsing from SDP headers if still Unknown
                            if sdp_body:
                                sdp_codec, sdp_fps, sdp_audio = parse_sdp_metadata(sdp_body)
                                if codec == "Unknown" and sdp_codec != "Unknown":
                                    codec = sdp_codec
                                if fps == "Unknown" and sdp_fps != "Unknown":
                                    fps = sdp_fps
                                if audio == "Unknown" and sdp_audio != "Unknown":
                                    audio = sdp_audio
                                        
                            stream_type = "main" if i == 0 else "substream"
                            if i > 1:
                                stream_type = f"substream_{i}"
                                
                            self.streams[stream_type] = {
                                "url": rtsp_url,
                                "name": name_str,
                                "token": token,
                                "resolution": f"{width}x{height}" if width and height else "Unknown",
                                "codec": codec,
                                "fps": fps,
                                "audio": audio,
                                "snapshot_url": snapshot_url
                            }
                            print(f"    - {stream_type.capitalize()} stream URL resolved: {rtsp_url}")
                            if snapshot_url != "None":
                                print(f"    - {stream_type.capitalize()} snapshot URL resolved: {snapshot_url}")
                return True
            except Exception as e:
                print(f"  [-] Error parsing profiles: {e}", file=sys.stderr)
        
        return False
 
    def add_brute_forced_stream(self, rtsp_url, credentials, sdp_text=None):
        self.auth_success = credentials
        stype = "main" if len(self.streams) == 0 else f"substream_{len(self.streams)}"
        if len(self.streams) == 1:
            stype = "substream"
            
        codec, fps, audio = parse_sdp_metadata(sdp_text)
            
        self.streams[stype] = {
            "url": rtsp_url,
            "name": f"BruteForce_{stype}",
            "token": "None",
            "resolution": "Unknown",
            "codec": codec,
            "fps": fps,
            "audio": audio,
            "snapshot_url": "None"
        }
        user, pwd = credentials
        cred_desc = f"'{user}:{pwd}'" if user else "No Authentication"
        print(f"    [+] Found working RTSP stream at: {rtsp_url} using {cred_desc}")

    def verify_rtsp_url_ffprobe(self, rtsp_url, timeout=2.0):
        """
        Checks if an RTSP URL is actually streamable using ffprobe.
        """
        cmd = [
            "ffprobe",
            "-rtsp_transport", "tcp",
            "-timeout", str(int(timeout * 1000000)),
            "-v", "error",
            "-show_entries", "format=format_name",
            "-of", "json",
            rtsp_url
        ]
        try:
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 1.0, startupinfo=startupinfo)
            return res.returncode == 0
        except Exception:
            return False

    def is_wildcard_server(self, port, user=None, pwd=None):
        """
        Checks if the camera responds with 200 OK to a dummy non-existent path.
        """
        cred_prefix = f"{user}:{pwd}@" if user else ""
        dummy_url = f"rtsp://{cred_prefix}{self.ip}:{port}/non_existent_dummy_path_12345"
        status, _, _ = verify_rtsp_url_raw(dummy_url, timeout=1.0)
        return status == "valid"

    def brute_force_rtsp(self):
        """
        Brute forces RTSP URLs using optimized candidate flows and wildcard server checks.
        """
        print("  [*] Running direct RTSP brute force discovery...")
        rtsp_ports = [p for p in self.open_ports if p in [554, 8554]]
        if not rtsp_ports:
            rtsp_ports = [554]
            
        for port in rtsp_ports:
            # Check wildcard status without auth
            is_unauth_wildcard = self.is_wildcard_server(port)
            
            # Step A: Find candidate paths by probing
            candidate_paths = []  # list of (path_template, www_auth_header)
            
            for path_template in self.settings.common_rtsp_paths:
                # If the path has credential placeholders, test directly with credentials
                if "{username}" in path_template or "{password}" in path_template:
                    # Test if the path template accepts dummy credentials (credential wildcard path)
                    dummy_path = path_template.format(username="dummy_user_999", password="dummy_pwd_999")
                    dummy_url = f"rtsp://{self.ip}:{port}{dummy_path}"
                    dummy_status, _, _ = verify_rtsp_url_raw(dummy_url, timeout=1.0)
                    is_cred_wildcard = (dummy_status == "valid")
                    
                    for user, pwd in self.credentials:
                        if user is None or (user == "" and pwd == ""):
                            continue
                        path = path_template.format(username=user, password=pwd)
                        rtsp_url = f"rtsp://{self.ip}:{port}{path}"
                        status, auth_req, response = verify_rtsp_url_raw(rtsp_url, timeout=1.0)
                        if status == "valid":
                            if is_unauth_wildcard or is_cred_wildcard:
                                if self.verify_rtsp_url_ffprobe(rtsp_url, timeout=1.5) or is_valid_sdp(response):
                                    self.add_brute_forced_stream(rtsp_url, (user, pwd), response)
                                    break
                            else:
                                self.add_brute_forced_stream(rtsp_url, (user, pwd), response)
                                if len(self.streams) >= 2:
                                    return
                    continue
                
                # Standard path sweep (no credential placeholders)
                rtsp_url = f"rtsp://{self.ip}:{port}{path_template}"
                status, auth_req, response = verify_rtsp_url_raw(rtsp_url, timeout=1.0)
                
                if status == "valid":
                    if is_unauth_wildcard:
                        # Verify with ffprobe to make sure it's a real stream
                        if self.verify_rtsp_url_ffprobe(rtsp_url, timeout=1.5) or is_valid_sdp(response):
                            self.add_brute_forced_stream(rtsp_url, (None, None), response)
                            break # stop at first stream for wildcard to avoid duplicates
                    else:
                        self.add_brute_forced_stream(rtsp_url, (None, None), response)
                        if len(self.streams) >= 2:
                            return
                elif status == "unauthorized":
                    www_auth_match = re.search(r'WWW-Authenticate:\s*(.*)', response, re.IGNORECASE)
                    www_auth = www_auth_match.group(0) if www_auth_match else ""
                    candidate_paths.append((path_template, www_auth))
                    
            if len(self.streams) >= 2:
                return
                
            # Step B: Find credentials first using the first candidate path
            if not candidate_paths:
                continue
                
            first_path_template, www_auth = candidate_paths[0]
            working_creds = []
            
            for user, pwd in self.credentials:
                if user is None or (user == "" and pwd == ""):
                    continue
                path = first_path_template
                if "{username}" in path or "{password}" in path:
                    path = path.format(username=user, password=pwd)
                rtsp_url = f"rtsp://{self.ip}:{port}{path}"
                rtsp_url_with_cred = f"rtsp://{user}:{pwd}@{self.ip}:{port}{path}"
                
                status, auth_req, response = verify_rtsp_url_raw(rtsp_url_with_cred, timeout=1.0)
                success = (status == "valid")
                if not success and www_auth and "digest" in www_auth.lower():
                    success, response = check_digest_auth(rtsp_url, user, pwd, www_auth, timeout=1.0)
                    
                if success:
                    working_creds.append((user, pwd))
                    
            # For each working credential, find the streams
            for user, pwd in working_creds:
                is_wildcard = self.is_wildcard_server(port, user, pwd)
                
                for path_template, www_auth in candidate_paths:
                    path = path_template
                    if "{username}" in path or "{password}" in path:
                        path = path.format(username=user, password=pwd)
                        
                    rtsp_url = f"rtsp://{self.ip}:{port}{path}"
                    rtsp_url_with_cred = f"rtsp://{user}:{pwd}@{self.ip}:{port}{path}"
                    
                    if is_wildcard:
                        status, _, resp_sdp = verify_rtsp_url_raw(rtsp_url_with_cred, timeout=1.0)
                        if self.verify_rtsp_url_ffprobe(rtsp_url_with_cred, timeout=1.5) or is_valid_sdp(resp_sdp):
                            self.add_brute_forced_stream(rtsp_url_with_cred, (user, pwd), resp_sdp)
                            break # stop at first stream for wildcard to avoid duplicates
                    else:
                        status, auth_req, response = verify_rtsp_url_raw(rtsp_url_with_cred, timeout=1.0)
                        success = (status == "valid")
                        if not success and www_auth and "digest" in www_auth.lower():
                            success, response = check_digest_auth(rtsp_url, user, pwd, www_auth, timeout=1.0)
                            
                        if success:
                            self.add_brute_forced_stream(rtsp_url_with_cred, (user, pwd), response)
                            if len(self.streams) >= 2:
                                return

    def analyze_discovered_streams(self):
        """
        Executes ffprobe on discovered streams to parse parameters in parallel.
        """
        if not self.streams:
            return
            
        print("  [*] Fetching stream details using ffprobe...")
        with ThreadPoolExecutor(max_workers=len(self.streams)) as executor:
            futures = {executor.submit(self.analyze_single_stream, name): name for name in self.streams.keys()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"    [-] Stream analysis error for {name}: {e}", file=sys.stderr)

    def analyze_single_stream(self, name):
        """
        Executes ffprobe on a single stream.
        """
        stream_info = self.streams[name]
        url = stream_info["url"]
        stimeout_us = str(int(self.ffmpeg_socket_timeout * 1000000))
        cmd = [
            "ffprobe",
            "-rtsp_transport", "tcp",
            "-stimeout", stimeout_us,
            "-v", "error",
            "-show_format",
            "-show_streams",
            "-of", "json",
            url
        ]
        try:
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5.0,
                startupinfo=startupinfo
            )
            if res.returncode == 0:
                data = json.loads(res.stdout.decode('utf-8', errors='ignore'))
                
                video_stream = None
                audio_stream = None
                
                for stream in data.get("streams", []):
                    codec_type = stream.get("codec_type")
                    if codec_type == "video" and not video_stream:
                        video_stream = stream
                    elif codec_type == "audio" and not audio_stream:
                        audio_stream = stream
                        
                if video_stream:
                    w = video_stream.get("width", "Unknown")
                    h = video_stream.get("height", "Unknown")
                    codec = video_stream.get("codec_name", "Unknown").upper()
                    profile = video_stream.get("profile", "")
                    if profile:
                        codec = f"{codec} ({profile})"
                        
                    r_fps = video_stream.get("r_frame_rate", "0/0")
                    fps = 0
                    if "/" in r_fps:
                        parts = r_fps.split("/")
                        if len(parts) == 2 and float(parts[1]) > 0:
                            fps = round(float(parts[0]) / float(parts[1]), 1)
                    if fps == 0:
                        avg_fps = video_stream.get("avg_frame_rate", "0/0")
                        if "/" in avg_fps:
                            parts = avg_fps.split("/")
                            if len(parts) == 2 and float(parts[1]) > 0:
                                fps = round(float(parts[0]) / float(parts[1]), 1)
                                
                    stream_info["resolution"] = f"{w}x{h}"
                    stream_info["codec"] = codec
                    stream_info["fps"] = fps if fps > 0 else "Unknown"
                    
                if audio_stream:
                    acodec = audio_stream.get("codec_name", "Unknown").upper()
                    ach = audio_stream.get("channels", 1)
                    stream_info["audio"] = f"{acodec} ({ach}ch)"
                else:
                    stream_info["audio"] = "None"
                    
                print(f"    - {name.capitalize()} stream: {stream_info['resolution']} | Codec: {stream_info['codec']} | FPS: {stream_info['fps']} | Audio: {stream_info['audio']}")
            else:
                print(f"    [-] ffprobe analysis failed for {name} stream (camera might be offline or stream dropped).")
        except Exception as e:
            print(f"    [-] ffprobe execution timeout/error for {name} stream: {e}", file=sys.stderr)

    def calculate_nvr_compatibility(self):
        """
        Evaluates the camera details and returns a compatibility score (0-100) and recommendations list.
        """
        score = 100
        recommendations = []
        
        if not self.streams:
            return 0, ["No working RTSP streams detected. Camera cannot be added to NVR."]
            
        # Check authentication status
        if self.auth_success:
            user, pwd = self.auth_success
            if not user and not pwd:
                score -= 20
                recommendations.append("[Security Alert] Camera has NO authentication enabled. Enable credentials immediately.")
            elif pwd in ["admin", "12345", "123456", "password"]:
                score -= 15
                recommendations.append("[Security Warning] Camera uses a weak/default password. Update credential configurations.")
        else:
            score -= 10
            recommendations.append("[Security Warning] Authentication status is unclear.")

        # Check stream resolutions and substreams
        main_stream = self.streams.get("main")
        sub_stream = self.streams.get("substream")
        
        if not main_stream:
            score -= 30
            recommendations.append("[Error] Main stream not identified.")
        else:
            # Check video codec
            vcodec = main_stream["codec"].lower()
            if "h265" in vcodec or "hevc" in vcodec:
                # Home Assistant compatibility warning
                recommendations.append("[Compatibility Note] Main stream uses H.265. Safe for NVR recording, but may not stream in all web browsers without transcoding (e.g., in Home Assistant UI).")
            elif "h264" not in vcodec and "mjpeg" not in vcodec:
                score -= 10
                recommendations.append(f"[Compatibility Warning] Video codec '{vcodec}' might have limited NVR support.")

        if not sub_stream:
            score -= 25
            recommendations.append("[Performance Warning] Substream (low-resolution profile) is missing. Using main stream for motion detection will increase NVR CPU load significantly.")
        else:
            # Substream should preferably be H.264 for widest browser compatibility (Home Assistant dashboard)
            sub_codec = sub_stream["codec"].lower()
            if "h265" in sub_codec or "hevc" in sub_codec:
                recommendations.append("[Performance Warning] Substream uses H.265. Home Assistant dashboard cards might experience lag or require transcoding.")

        if score >= 90:
            recommendations.append("[Success] Excellent compatibility. Ready for NVR and Home Assistant deployment.")
        elif score >= 70:
            recommendations.append("[Success] Good compatibility. Can be deployed, but review recommendations.")
        else:
            recommendations.append("[Warning] Suboptimal configuration. Review and optimize camera setup.")
            
        return max(0, score), recommendations

    def get_summary(self):
        """
        Compiles the camera scan findings into a dictionary.
        """
        score, recs = self.calculate_nvr_compatibility()
        user_str = self.auth_success[0] if self.auth_success else ""
        pwd_str = self.auth_success[1] if self.auth_success else ""
        
        return {
            "ip": self.ip,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware": self.firmware,
            "username": user_str,
            "password": pwd_str,
            "onvif_endpoint": self.onvif_endpoint or "N/A",
            "streams": self.streams,
            "nvr_score": score,
            "recommendations": recs
        }

def probe_cameras(scan_results, credentials, settings):
    """
    Orchestrates the camera probing for all hosts with open ports in parallel.
    """
    print(f"\n[*] Probing {len(scan_results)} discovered host(s) for detailed specifications...")
    camera_reports = []
    
    # Use settings.threads for concurrency when probing multiple destinations simultaneously
    with ThreadPoolExecutor(max_workers=settings.threads) as executor:
        futures = []
        for ip, open_ports in scan_results.items():
            prober = CameraProber(ip, open_ports, credentials, settings)
            futures.append(executor.submit(prober.probe))
            
        for future in as_completed(futures):
            try:
                report = future.result()
                camera_reports.append(report)
            except Exception as e:
                print(f"[-] Unexpected error probing camera: {e}", file=sys.stderr)
                
    return camera_reports
