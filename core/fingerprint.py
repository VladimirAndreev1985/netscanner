"""Device fingerprinting — determine device type, brand, model from scan data."""

import asyncio
import logging
import re
from typing import Any

import aiohttp

from core.device import Device
from core.mac_lookup import is_camera_vendor, is_iot_vendor, get_brand_from_mac

logger = logging.getLogger("netscanner.fingerprint")

# Port-based device type hints
CAMERA_INDICATOR_PORTS = {554, 8000, 8001, 37777, 37778, 34567, 34599, 8899, 9000}
IOT_INDICATOR_PORTS = {1883, 8883, 5683, 502, 47808, 6668}
PRINTER_INDICATOR_PORTS = {9100, 631}
ROUTER_INDICATOR_PORTS = {53}

# HTTP header patterns for camera identification
CAMERA_HTTP_SIGNATURES = {
    "hikvision": [
        re.compile(r"hikvision", re.I),
        re.compile(r"DNVRS-Webs", re.I),
        re.compile(r"App-webs", re.I),
        re.compile(r"ISAPI", re.I),
        re.compile(r"webCms", re.I),
    ],
    "dahua": [
        re.compile(r"dahua", re.I),
        re.compile(r"DH_WEB", re.I),
        re.compile(r"NetDVR", re.I),
        re.compile(r"DHWEB", re.I),
    ],
    "axis": [
        re.compile(r"axis", re.I),
        re.compile(r"AXIS\s", re.I),
        re.compile(r"Boa/0\.\d+.*Axis", re.I),
    ],
    "reolink": [
        re.compile(r"reolink", re.I),
    ],
    "foscam": [
        re.compile(r"foscam", re.I),
        re.compile(r"IPCam", re.I),
    ],
    "amcrest": [
        re.compile(r"amcrest", re.I),
    ],
    "dlink": [
        re.compile(r"d-link", re.I),
        re.compile(r"DCS-\d+", re.I),
    ],
    "tplink": [
        re.compile(r"tp-link", re.I),
        re.compile(r"Tapo", re.I),
    ],
    "ubiquiti": [
        re.compile(r"ubiquiti", re.I),
        re.compile(r"UniFi", re.I),
        re.compile(r"airCam", re.I),
    ],
    "vivotek": [
        re.compile(r"vivotek", re.I),
    ],
    "samsung": [
        re.compile(r"samsung.*cam", re.I),
        re.compile(r"Techwin", re.I),
        re.compile(r"SNB-\d+", re.I),
        re.compile(r"SNP-\d+", re.I),
    ],
    "bosch": [
        re.compile(r"bosch", re.I),
    ],
    "panasonic": [
        re.compile(r"panasonic", re.I),
        re.compile(r"WV-\w+", re.I),
    ],
}

# Service name patterns from nmap
CAMERA_SERVICE_NAMES = {"rtsp", "rtmp", "onvif"}


async def fingerprint_device(device: Device) -> Device:
    """Full fingerprinting pipeline for a device."""
    # Step 1: Type detection from ports
    _detect_type_from_ports(device)

    # Step 2: Brand from MAC
    if not device.brand and device.mac:
        device.brand = get_brand_from_mac(device.mac)

    # Step 3: HTTP fingerprinting
    if any(p in device.open_ports for p in (80, 443, 8080, 8443, 8000, 81, 85)):
        await _http_fingerprint(device)

    # Step 4: Service banner analysis
    _analyze_service_banners(device)

    # Step 5: Refine type based on all evidence
    _refine_device_type(device)

    return device


def _detect_type_from_ports(device: Device) -> None:
    """Detect device type from open ports."""
    ports = set(device.open_ports)

    if ports & CAMERA_INDICATOR_PORTS:
        device.device_type = "camera"
    elif ports & IOT_INDICATOR_PORTS:
        device.device_type = "iot"
    elif ports & PRINTER_INDICATOR_PORTS:
        device.device_type = "printer"

    # RTSP port is strong camera indicator
    if 554 in ports:
        device.device_type = "camera"


async def _http_fingerprint(device: Device) -> None:
    """Fingerprint device via HTTP headers and content."""
    http_ports = [p for p in (80, 8080, 443, 8443, 8000, 81, 85) if p in device.open_ports]

    for port in http_ports[:2]:  # Check first 2 HTTP ports
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{device.ip}:{port}"

        try:
            timeout = aiohttp.ClientTimeout(total=8)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(url, allow_redirects=True) as resp:
                    headers = dict(resp.headers)
                    body = await resp.text(errors="ignore")

                    # Analyze Server header
                    server = headers.get("Server", "")
                    www_auth = headers.get("WWW-Authenticate", "")
                    all_text = f"{server} {www_auth} {body[:4000]}"

                    # Match against known signatures
                    for brand, patterns in CAMERA_HTTP_SIGNATURES.items():
                        for pattern in patterns:
                            if pattern.search(all_text):
                                device.brand = brand.capitalize()
                                if device.brand.lower() in ("hikvision", "dahua", "axis",
                                                             "reolink", "foscam", "amcrest"):
                                    device.device_type = "camera"
                                break

                    # Extract model from title
                    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
                    if title_match:
                        title = title_match.group(1).strip()
                        device.extra_info["web_title"] = title
                        # Try to extract model from title
                        model_match = re.search(
                            r"(DS-\w+|DH-\w+|IPC-\w+|NVR\w+|DVR\w+|DCS-\w+|"
                            r"WV-\w+|SNB-\w+|FI\d+|RLC-\w+)",
                            title, re.I
                        )
                        if model_match and not device.model:
                            device.model = model_match.group(1)

                    # Extract firmware from headers/body
                    fw_match = re.search(
                        r"(?:firmware|version|fw)[:\s]*[Vv]?(\d+\.\d+[\.\d]*(?:\s*build\s*\d+)?)",
                        all_text
                    )
                    if fw_match and not device.firmware_version:
                        device.firmware_version = fw_match.group(1)

                    # Set web interface URL
                    if not device.web_interface:
                        device.web_interface = url

        except Exception as e:
            logger.debug(f"HTTP fingerprint failed for {url}: {e}")


def _analyze_service_banners(device: Device) -> None:
    """Analyze nmap service banners for device identification."""
    for port, svc in device.services.items():
        product = svc.get("product", "").lower()
        name = svc.get("name", "").lower()
        version = svc.get("version", "")
        extra = svc.get("extrainfo", "").lower()
        all_info = f"{product} {name} {extra}"

        # RTSP service confirms camera
        if name in ("rtsp", "rtmp"):
            device.device_type = "camera"

        # Brand from service banners
        for brand in ("hikvision", "dahua", "axis", "reolink", "foscam",
                      "amcrest", "vivotek", "bosch", "panasonic"):
            if brand in all_info:
                device.brand = brand.capitalize()
                device.device_type = "camera"
                break

        # Model from service banner
        if not device.model:
            model_match = re.search(
                r"(DS-\w+|DH-\w+|IPC-\w+|NVR-?\w+|DVR-?\w+|DCS-\w+)",
                f"{product} {extra}", re.I
            )
            if model_match:
                device.model = model_match.group(1)

        # Version from service
        if version and not device.firmware_version:
            device.firmware_version = version


def _refine_device_type(device: Device) -> None:
    """Final device type refinement based on all collected evidence."""
    # MAC-based refinement
    if device.mac:
        if is_camera_vendor(device.mac) and device.device_type == "unknown":
            device.device_type = "camera"
        elif is_iot_vendor(device.mac) and device.device_type == "unknown":
            device.device_type = "iot"

    # Brand implies camera
    camera_brands = {"hikvision", "dahua", "axis", "reolink", "foscam",
                     "amcrest", "vivotek", "samsung", "bosch", "panasonic",
                     "honeywell", "geovision", "avtech"}
    if device.brand.lower() in camera_brands:
        device.device_type = "camera"

    # NVR/DVR detection
    if device.model:
        if re.search(r"NVR", device.model, re.I):
            device.device_type = "nvr"
        elif re.search(r"DVR", device.model, re.I):
            device.device_type = "dvr"

    # Router detection: has port 53 + common web ports
    ports = set(device.open_ports)
    if 53 in ports and ports & {80, 443, 8080}:
        if device.device_type == "unknown":
            device.device_type = "router"

    # PC detection: RDP or SMB
    if ports & {3389, 445, 135} and device.device_type == "unknown":
        device.device_type = "pc"

    # Default
    if not device.device_type:
        device.device_type = "unknown"


async def fingerprint_all(devices: list[Device],
                          callback=None) -> list[Device]:
    """Fingerprint all devices concurrently."""
    tasks = [fingerprint_device(dev) for dev in devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    fingerprinted = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Fingerprint failed for {devices[i].ip}: {result}")
            fingerprinted.append(devices[i])
        else:
            fingerprinted.append(result)
        if callback:
            callback(i + 1, len(devices))

    return fingerprinted
