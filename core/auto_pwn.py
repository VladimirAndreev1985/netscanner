"""Auto-Pwn — automated penetration testing pipeline."""

import asyncio
import logging
from datetime import datetime
from typing import Callable, Any

from core.device import Device
from core.scanner import full_scan
from core.fingerprint import fingerprint_all
from core.vuln_checker import check_all_devices as check_vulns
from core.cred_checker import check_all_devices as check_creds
from core.camera_analyzer import analyze_all_cameras, capture_snapshot
from core.exploit_finder import find_exploits
from core.msf_integration import msf_client, get_suggested_modules

logger = logging.getLogger("netscanner.auto_pwn")


class AutoPwnResult:
    """Results container for auto-pwn run."""
    def __init__(self):
        self.devices: list[Device] = []
        self.total_found: int = 0
        self.cameras_found: int = 0
        self.vulnerable: int = 0
        self.compromised: int = 0
        self.exploits_found: int = 0
        self.screenshots: list[str] = []
        self.log: list[str] = []
        self.start_time: str = ""
        self.end_time: str = ""

    def add_log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        self.log.append(entry)
        logger.info(message)


async def auto_pwn(target: str, mode: str = "normal",
                   log_callback: Callable | None = None,
                   progress_callback: Callable | None = None) -> AutoPwnResult:
    """Run automated penetration test pipeline.

    Modes:
    - passive: Discovery + fingerprint + CVE check only
    - normal: + credential checking + backdoor detection
    - aggressive: + exploit attempts (with MSF)
    """
    result = AutoPwnResult()
    result.start_time = datetime.now().isoformat()

    def log(msg: str):
        result.add_log(msg)
        if log_callback:
            log_callback(msg)

    log(f"Starting Auto-Pwn scan on {target} (mode: {mode})")

    # ═══ Phase 1: Network Discovery ═══
    log("Phase 1: Network Discovery")
    if progress_callback:
        progress_callback(1, 7, "Network Discovery")

    devices = await full_scan(target, scan_type="normal" if mode != "passive" else "quick")
    result.devices = devices
    result.total_found = len(devices)
    log(f"  Found {len(devices)} live hosts")

    if not devices:
        log("No hosts found. Scan complete.")
        result.end_time = datetime.now().isoformat()
        return result

    # ═══ Phase 2: Fingerprinting ═══
    log("Phase 2: Device Fingerprinting")
    if progress_callback:
        progress_callback(2, 7, "Fingerprinting")

    devices = await fingerprint_all(devices)
    cameras = [d for d in devices if d.is_camera]
    result.cameras_found = len(cameras)
    log(f"  Identified: {len(cameras)} cameras, "
        f"{sum(1 for d in devices if d.device_type == 'iot')} IoT, "
        f"{sum(1 for d in devices if d.device_type == 'router')} routers, "
        f"{sum(1 for d in devices if d.device_type == 'pc')} PCs")

    # ═══ Phase 3: Deep Camera Analysis ═══
    if cameras:
        log("Phase 3: Deep Camera Analysis")
        if progress_callback:
            progress_callback(3, 7, "Camera Analysis")

        devices = await analyze_all_cameras(devices)
        rtsp_count = sum(len(d.rtsp_urls) for d in cameras)
        log(f"  Found {rtsp_count} RTSP streams across {len(cameras)} cameras")

    # ═══ Phase 4: CVE Matching ═══
    log("Phase 4: Vulnerability Assessment")
    if progress_callback:
        progress_callback(4, 7, "CVE Matching")

    devices = check_vulns(devices)
    vuln_devices = [d for d in devices if d.is_vulnerable]
    result.vulnerable = len(vuln_devices)
    total_cves = sum(len(d.vulnerabilities) for d in devices)
    critical = sum(1 for d in devices for v in d.vulnerabilities if v.severity == "critical")
    log(f"  Found {total_cves} CVE matches ({critical} critical) across {len(vuln_devices)} devices")

    if mode == "passive":
        log("Passive mode — skipping credential and exploit checks")
        result.end_time = datetime.now().isoformat()
        return result

    # ═══ Phase 5: Credential Checking ═══
    log("Phase 5: Default Credential Testing")
    if progress_callback:
        progress_callback(5, 7, "Credential Testing")

    devices = await check_creds(devices)
    compromised = [d for d in devices if d.has_default_creds]
    result.compromised = len(compromised)
    log(f"  Found default credentials on {len(compromised)} devices")
    for dev in compromised:
        for cred in dev.default_creds:
            if cred.success:
                log(f"    {dev.ip} ({dev.brand}): {cred.protocol} "
                    f"{cred.username}:{cred.password}")

    # ═══ Phase 6: Exploit Search ═══
    log("Phase 6: Exploit Discovery")
    if progress_callback:
        progress_callback(6, 7, "Exploit Search")

    for dev in vuln_devices:
        exploits = await find_exploits(dev)
        if exploits:
            result.exploits_found += len(exploits)
            log(f"  {dev.ip}: Found {len(exploits)} exploits")

    if mode == "aggressive":
        # ═══ Phase 6b: MSF Module Suggestions ═══
        log("Phase 6b: Metasploit Module Matching")
        for dev in vuln_devices:
            modules = get_suggested_modules(dev)
            if modules:
                dev.extra_info["msf_modules"] = modules
                log(f"  {dev.ip}: {len(modules)} MSF modules available")

    # ═══ Phase 7: Screenshot Capture ═══
    log("Phase 7: Camera Screenshot Capture")
    if progress_callback:
        progress_callback(7, 7, "Screenshot Capture")

    for dev in compromised:
        if dev.is_camera:
            screenshot = await capture_snapshot(dev)
            if screenshot:
                result.screenshots.append(screenshot)
                log(f"  Captured frame from {dev.ip}")

    # ═══ Complete ═══
    result.end_time = datetime.now().isoformat()
    log("═══ Auto-Pwn Complete ═══")
    log(f"  Total hosts: {result.total_found}")
    log(f"  Cameras: {result.cameras_found}")
    log(f"  Vulnerable: {result.vulnerable}")
    log(f"  Compromised: {result.compromised}")
    log(f"  Exploits found: {result.exploits_found}")
    log(f"  Screenshots: {len(result.screenshots)}")

    return result
