"""Deep camera analysis — ONVIF, RTSP enumeration, firmware, backdoors, snapshots."""

import asyncio
import json
import logging
import os
import re
import subprocess
import shutil
from pathlib import Path

import aiohttp

from core.device import Device

logger = logging.getLogger("netscanner.camera_analyzer")

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_json(filename: str) -> dict:
    path = DATA_DIR / filename
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


async def analyze_camera(device: Device) -> Device:
    """Full deep analysis of a camera device."""
    if not device.is_camera and device.device_type not in ("nvr", "dvr", "unknown"):
        return device

    tasks = [
        _enumerate_rtsp(device),
        _check_onvif(device),
        _check_backdoors(device),
        _extract_firmware_info(device),
        _check_upnp(device),
    ]
    await asyncio.gather(*tasks, return_exceptions=True)
    return device


async def _enumerate_rtsp(device: Device) -> None:
    """Enumerate RTSP streams by trying known paths."""
    if 554 not in device.open_ports:
        return

    rtsp_db = _load_json("rtsp_paths.json")
    brand = device.brand.lower() if device.brand else ""

    # Get paths for this brand + generic
    paths = []
    if brand and brand in rtsp_db:
        paths.extend(rtsp_db[brand])
    paths.extend(rtsp_db.get("generic", []))
    # Deduplicate while preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)

    found_urls = []
    sem = asyncio.Semaphore(10)

    async def check_rtsp(path: str):
        url = f"rtsp://{device.ip}:554{path}"
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(device.ip, 554), timeout=3
                )
                # Send RTSP DESCRIBE
                request = (
                    f"DESCRIBE {url} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"Accept: application/sdp\r\n"
                    f"\r\n"
                )
                writer.write(request.encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(1024), timeout=3)
                resp_text = response.decode(errors="ignore")
                writer.close()

                # 200 OK = stream exists (may need auth)
                # 401 = exists but needs auth
                if "RTSP/1.0 200" in resp_text or "RTSP/1.0 401" in resp_text:
                    found_urls.append(url)
            except Exception:
                pass

    await asyncio.gather(*[check_rtsp(p) for p in unique_paths[:50]])
    device.rtsp_urls = found_urls


async def _check_onvif(device: Device) -> None:
    """Check for ONVIF service and enumerate capabilities."""
    if not any(p in device.open_ports for p in (80, 8080, 443)):
        return

    # ONVIF GetDeviceInformation SOAP request (often works without auth)
    soap_body = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>"""

    for port in (80, 8080):
        if port not in device.open_ports:
            continue
        url = f"http://{device.ip}:{port}/onvif/device_service"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
                async with session.post(url, data=soap_body, headers=headers) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        device.device_type = "camera"
                        onvif_info = _parse_onvif_response(body)
                        device.onvif_info = onvif_info
                        if onvif_info.get("manufacturer") and not device.brand:
                            device.brand = onvif_info["manufacturer"]
                        if onvif_info.get("model") and not device.model:
                            device.model = onvif_info["model"]
                        if onvif_info.get("firmware_version") and not device.firmware_version:
                            device.firmware_version = onvif_info["firmware_version"]
                        return
        except Exception as e:
            logger.debug(f"ONVIF check failed for {device.ip}:{port}: {e}")


def _parse_onvif_response(xml_text: str) -> dict:
    """Parse ONVIF GetDeviceInformation response."""
    info = {}
    patterns = {
        "manufacturer": r"<(?:\w+:)?Manufacturer>([^<]+)</",
        "model": r"<(?:\w+:)?Model>([^<]+)</",
        "firmware_version": r"<(?:\w+:)?FirmwareVersion>([^<]+)</",
        "serial_number": r"<(?:\w+:)?SerialNumber>([^<]+)</",
        "hardware_id": r"<(?:\w+:)?HardwareId>([^<]+)</",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, xml_text)
        if match:
            info[key] = match.group(1).strip()
    return info


async def _check_backdoors(device: Device) -> None:
    """Check known camera backdoors and vulnerable endpoints."""
    backdoors_db = _load_json("camera_backdoors.json")
    brand = device.brand.lower() if device.brand else ""

    # Collect checks for this brand + generic
    checks = []
    if brand in backdoors_db:
        checks.extend(backdoors_db[brand])
    checks.extend(backdoors_db.get("generic", []))

    http_ports = [p for p in (80, 8080, 443, 8443) if p in device.open_ports]
    if not http_ports:
        return

    port = http_ports[0]
    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{device.ip}:{port}"

    sem = asyncio.Semaphore(5)

    async def check_endpoint(check: dict):
        paths = check.get("paths", [check.get("path", "")])
        method = check.get("method", "GET").upper()

        for path in paths:
            if not path:
                continue
            url = f"{base_url}{path}"
            async with sem:
                try:
                    timeout = aiohttp.ClientTimeout(total=8)
                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        if method == "GET":
                            async with session.get(url) as resp:
                                if resp.status == 200:
                                    body = await resp.text(errors="ignore")
                                    if len(body) > 50:  # Non-empty meaningful response
                                        device.extra_info.setdefault("backdoors", []).append({
                                            "name": check.get("name", ""),
                                            "url": url,
                                            "cve": check.get("cve", ""),
                                            "type": check.get("type", ""),
                                            "response_size": len(body),
                                        })
                except Exception:
                    pass

    await asyncio.gather(*[check_endpoint(c) for c in checks], return_exceptions=True)


async def _extract_firmware_info(device: Device) -> None:
    """Try to extract firmware version from various endpoints."""
    if device.firmware_version:
        return

    http_ports = [p for p in (80, 8080) if p in device.open_ports]
    if not http_ports:
        return

    port = http_ports[0]
    base_url = f"http://{device.ip}:{port}"

    firmware_endpoints = [
        "/cgi-bin/magicBox.cgi?action=getDeviceType",
        "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
        "/ISAPI/System/deviceInfo",
        "/axis-cgi/param.cgi?action=list&group=Properties.Firmware",
        "/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo",
        "/stw-cgi/system.cgi?msubmenu=deviceinfo&action=view",
    ]

    for endpoint in firmware_endpoints:
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(f"{base_url}{endpoint}") as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        # Try to extract version
                        fw_match = re.search(
                            r"(?:version|firmware|softwareVersion|FirmwareVersion)[\":\s=]*[Vv]?"
                            r"(\d+\.\d+[\.\d]*(?:\s*[Bb]uild\s*\d+)?)",
                            body
                        )
                        if fw_match:
                            device.firmware_version = fw_match.group(1)
                            return
        except Exception:
            continue


async def _check_upnp(device: Device) -> None:
    """Check UPnP/SSDP for device info and port mappings."""
    upnp_endpoints = [
        "/upnp/device_description.xml",
        "/devicedesc.xml",
        "/desc.xml",
        "/rootDesc.xml",
    ]

    http_ports = [p for p in (80, 8080, 49152, 49153, 49154) if p in device.open_ports]
    if not http_ports:
        return

    for port in http_ports[:2]:
        for endpoint in upnp_endpoints:
            url = f"http://{device.ip}:{port}{endpoint}"
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if "<device>" in body.lower() or "<root" in body.lower():
                                upnp_info = _parse_upnp(body)
                                device.extra_info["upnp"] = upnp_info
                                if upnp_info.get("manufacturer") and not device.brand:
                                    device.brand = upnp_info["manufacturer"]
                                if upnp_info.get("modelName") and not device.model:
                                    device.model = upnp_info["modelName"]
                                return
            except Exception:
                continue


def _parse_upnp(xml_text: str) -> dict:
    """Parse UPnP device description XML."""
    info = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber",
                "serialNumber", "modelDescription"):
        match = re.search(rf"<{tag}>([^<]+)</{tag}>", xml_text, re.I)
        if match:
            info[tag] = match.group(1).strip()
    return info


async def capture_snapshot(device: Device, output_dir: str = "reports") -> str | None:
    """Capture a frame from camera via RTSP or HTTP snapshot."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{output_dir}/snapshot_{device.ip.replace('.', '_')}.jpg"

    # Method 1: HTTP snapshot endpoints
    snapshot_urls = [
        f"http://{device.ip}/snap.jpg",
        f"http://{device.ip}/cgi-bin/snapshot.cgi",
        f"http://{device.ip}/ISAPI/Streaming/channels/101/picture",
        f"http://{device.ip}/cgi-bin/snapshot.cgi?channel=0",
        f"http://{device.ip}/tmpfs/snap.jpg",
        f"http://{device.ip}/webcapture.jpg?command=snap&channel=0",
        f"http://{device.ip}/image.jpg",
    ]

    for url in snapshot_urls:
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                # Try without auth first
                async with session.get(url) as resp:
                    if resp.status == 200 and resp.content_type and "image" in resp.content_type:
                        data = await resp.read()
                        if len(data) > 1000:  # Valid image
                            with open(filename, "wb") as f:
                                f.write(data)
                            device.screenshots.append(filename)
                            return filename
                # Try with default creds
                for cred in device.default_creds:
                    if cred.success and cred.protocol == "http":
                        auth = aiohttp.BasicAuth(cred.username, cred.password)
                        async with session.get(url, auth=auth) as resp:
                            if resp.status == 200 and resp.content_type and "image" in resp.content_type:
                                data = await resp.read()
                                if len(data) > 1000:
                                    with open(filename, "wb") as f:
                                        f.write(data)
                                    device.screenshots.append(filename)
                                    return filename
        except Exception:
            continue

    # Method 2: RTSP via ffmpeg
    if device.rtsp_urls and shutil.which("ffmpeg"):
        for rtsp_url in device.rtsp_urls[:3]:
            try:
                result = subprocess.run(
                    ["ffmpeg", "-y", "-rtsp_transport", "tcp",
                     "-i", rtsp_url, "-frames:v", "1",
                     "-q:v", "2", filename],
                    capture_output=True, timeout=15,
                )
                if os.path.exists(filename) and os.path.getsize(filename) > 1000:
                    device.screenshots.append(filename)
                    return filename
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

    return None


async def analyze_all_cameras(devices: list[Device], callback=None) -> list[Device]:
    """Analyze all camera devices in parallel."""
    cameras = [d for d in devices if d.is_camera or d.device_type in ("nvr", "dvr")]
    if not cameras:
        return devices

    tasks = [analyze_camera(dev) for dev in cameras]
    await asyncio.gather(*tasks, return_exceptions=True)

    if callback:
        callback(len(cameras))

    return devices
