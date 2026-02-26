"""CVE database auto-updater — fetches from NVD and Exploit-DB."""

import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests

logger = logging.getLogger("netscanner.cve_updater")

DATA_DIR = Path(__file__).parent.parent / "data"
CVE_DB_PATH = DATA_DIR / "cve_db.json"

# Camera/IoT vendors to track
TRACKED_VENDORS = [
    "hikvision", "dahua", "axis", "reolink", "foscam", "amcrest",
    "vivotek", "samsung", "panasonic", "bosch", "honeywell", "geovision",
    "dlink", "tplink", "ubiquiti", "wyze", "tuya", "sonoff",
    "avtech", "wanscam", "tenvis", "acti", "mobotix",
]

# NVD API v2.0
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def needs_update(max_age_hours: int = 24) -> bool:
    """Check if CVE database needs updating."""
    if not CVE_DB_PATH.exists():
        return True
    try:
        with open(CVE_DB_PATH) as f:
            data = json.load(f)
        last_updated = data.get("_last_updated", "")
        if not last_updated:
            return True
        last_dt = datetime.fromisoformat(last_updated)
        return datetime.now() - last_dt > timedelta(hours=max_age_hours)
    except (json.JSONDecodeError, ValueError):
        return True


def update_cve_database(progress_callback=None) -> dict:
    """Fetch latest CVEs from NVD for tracked vendors."""
    logger.info("Updating CVE database...")
    if progress_callback:
        progress_callback("Starting CVE update...")

    existing_db = _load_existing()
    existing_cves = {v["cve_id"] for v in existing_db.get("vulnerabilities", [])}
    new_vulns = []

    for i, vendor in enumerate(TRACKED_VENDORS):
        if progress_callback:
            progress_callback(f"Fetching CVEs for {vendor}... ({i+1}/{len(TRACKED_VENDORS)})")

        try:
            vulns = _fetch_nvd_for_vendor(vendor)
            for v in vulns:
                if v["cve_id"] not in existing_cves:
                    new_vulns.append(v)
                    existing_cves.add(v["cve_id"])
        except Exception as e:
            logger.error(f"Failed to fetch CVEs for {vendor}: {e}")

        # NVD rate limit: 5 requests per 30 seconds without API key
        time.sleep(6)

    # Merge with existing
    all_vulns = existing_db.get("vulnerabilities", []) + new_vulns

    # Check Exploit-DB for exploit availability
    if progress_callback:
        progress_callback("Checking Exploit-DB...")
    _check_exploitdb(all_vulns)

    # Save
    db = {
        "_description": "CVE database for cameras and IoT devices. Auto-updated from NVD.",
        "_last_updated": datetime.now().isoformat(),
        "_version": "1.0",
        "vulnerabilities": all_vulns,
    }

    CVE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CVE_DB_PATH, "w") as f:
        json.dump(db, f, indent=2)

    result = {
        "total": len(all_vulns),
        "new": len(new_vulns),
        "updated": datetime.now().isoformat(),
    }

    if progress_callback:
        progress_callback(f"Done! {len(new_vulns)} new CVEs added. Total: {len(all_vulns)}")

    logger.info(f"CVE update complete: {result}")
    return result


def _load_existing() -> dict:
    """Load existing CVE database."""
    if CVE_DB_PATH.exists():
        try:
            with open(CVE_DB_PATH) as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
    return {"vulnerabilities": []}


def _fetch_nvd_for_vendor(vendor: str) -> list[dict]:
    """Fetch CVEs from NVD API for a specific vendor."""
    vulns = []
    params = {
        "keywordSearch": vendor,
        "keywordExactMatch": "",
        "resultsPerPage": 50,
    }

    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        if resp.status_code != 200:
            logger.warning(f"NVD API returned {resp.status_code} for {vendor}")
            return vulns

        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # Extract CVSS score
            cvss_score = 0.0
            severity = "unknown"
            metrics = cve_data.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "unknown").lower()
                    break

            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract references
            references = []
            for ref in cve_data.get("references", []):
                references.append(ref.get("url", ""))

            vuln = {
                "cve_id": cve_id,
                "vendor": vendor,
                "product": "",
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description[:500],
                "affected_firmware": "multiple versions",
                "exploit_available": False,
                "msf_module": "",
                "references": references[:3],
            }
            vulns.append(vuln)

    except requests.RequestException as e:
        logger.error(f"NVD request failed for {vendor}: {e}")

    return vulns


def _check_exploitdb(vulns: list[dict]) -> None:
    """Check Exploit-DB for available exploits via searchsploit."""
    import shutil
    if not shutil.which("searchsploit"):
        return

    import subprocess
    for vuln in vulns:
        if vuln.get("exploit_available"):
            continue
        cve_id = vuln.get("cve_id", "")
        if not cve_id:
            continue
        try:
            result = subprocess.run(
                ["searchsploit", "--cve", cve_id.replace("CVE-", ""), "-j"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                exploits = data.get("RESULTS_EXPLOIT", [])
                if exploits:
                    vuln["exploit_available"] = True
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
