"""Vulnerability checker — match devices against CVE database."""

import json
import logging
import re
from pathlib import Path

from core.device import Device, Vulnerability

logger = logging.getLogger("netscanner.vuln_checker")

DATA_DIR = Path(__file__).parent.parent / "data"


def load_cve_db() -> list[dict]:
    """Load CVE database from JSON file."""
    path = DATA_DIR / "cve_db.json"
    if not path.exists():
        logger.warning("CVE database not found")
        return []
    with open(path) as f:
        data = json.load(f)
    return data.get("vulnerabilities", [])


def check_vulnerabilities(device: Device) -> list[Vulnerability]:
    """Check device against CVE database."""
    cve_db = load_cve_db()
    if not cve_db:
        return []

    found = []
    brand = device.brand.lower() if device.brand else ""
    model = device.model.lower() if device.model else ""
    firmware = device.firmware_version.lower() if device.firmware_version else ""
    vendor_name = device.vendor.lower() if device.vendor else ""

    for entry in cve_db:
        cve_vendor = entry.get("vendor", "").lower()
        cve_product = entry.get("product", "").lower()

        # Match by vendor/brand
        match = False
        if cve_vendor == "multiple":
            # Generic CVE — match by product keywords
            if model and any(kw in model for kw in cve_product.split(",")):
                match = True
        elif cve_vendor and (cve_vendor in brand or cve_vendor in vendor_name):
            match = True

        if not match:
            continue

        # If we have firmware version, check against affected versions
        affected = entry.get("affected_firmware", "").lower()
        if firmware and affected:
            # Simple version comparison
            if not _version_affected(firmware, affected):
                continue

        vuln = Vulnerability(
            cve_id=entry["cve_id"],
            cvss_score=entry.get("cvss_score", 0.0),
            severity=entry.get("severity", "unknown"),
            description=entry.get("description", ""),
            exploit_available=entry.get("exploit_available", False),
            exploit_url=entry.get("references", [""])[0] if entry.get("references") else "",
            affected_versions=affected,
        )
        found.append(vuln)

    # Sort by CVSS score (highest first)
    found.sort(key=lambda v: v.cvss_score, reverse=True)
    device.vulnerabilities = found
    device.calculate_risk_score()

    return found


def _version_affected(device_fw: str, affected_str: str) -> bool:
    """Check if device firmware is in affected range.

    Handles patterns like:
    - "< V5.5.800 build 210628"
    - "before V5.4.5"
    - "multiple versions"
    - "Log4j < 2.17.0"
    """
    if "multiple" in affected_str:
        return True

    # Extract version number from affected string
    match = re.search(r"(?:before|<)\s*[Vv]?(\d+[\.\d]*)", affected_str)
    if not match:
        return True  # Can't parse — assume affected

    affected_ver = match.group(1)

    # Extract device version number
    dev_match = re.search(r"(\d+[\.\d]*)", device_fw)
    if not dev_match:
        return True

    device_ver = dev_match.group(1)

    # Compare versions
    try:
        dev_parts = [int(x) for x in device_ver.split(".")]
        aff_parts = [int(x) for x in affected_ver.split(".")]
        # Pad to same length
        max_len = max(len(dev_parts), len(aff_parts))
        dev_parts.extend([0] * (max_len - len(dev_parts)))
        aff_parts.extend([0] * (max_len - len(aff_parts)))
        return dev_parts < aff_parts
    except ValueError:
        return True


def check_all_devices(devices: list[Device], callback=None) -> list[Device]:
    """Check vulnerabilities for all devices."""
    for i, device in enumerate(devices):
        if device.brand or device.vendor:
            check_vulnerabilities(device)
        if callback:
            callback(i + 1, len(devices))
    return devices
