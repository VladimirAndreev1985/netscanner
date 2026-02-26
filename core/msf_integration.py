"""Metasploit Framework integration via msfrpcd RPC."""

import asyncio
import logging
import subprocess
import shutil
import time
from typing import Any

from core.device import Device

logger = logging.getLogger("netscanner.msf")

MSF_RPC_PASSWORD = "netscanner"
MSF_RPC_PORT = 55553


class MetasploitClient:
    """Wrapper for Metasploit RPC client."""

    def __init__(self):
        self.client = None
        self.connected = False

    def connect(self, password: str = MSF_RPC_PASSWORD,
                port: int = MSF_RPC_PORT) -> bool:
        """Connect to msfrpcd."""
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            self.client = MsfRpcClient(password, port=port, ssl=True)
            self.connected = True
            logger.info("Connected to Metasploit RPC")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to msfrpcd: {e}")
            self.connected = False
            return False

    def is_running(self) -> bool:
        """Check if msfrpcd is running."""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex(("127.0.0.1", MSF_RPC_PORT))
            s.close()
            return result == 0
        except Exception:
            return False

    def start_rpc(self) -> bool:
        """Start msfrpcd daemon."""
        if not shutil.which("msfrpcd"):
            logger.error("msfrpcd not found. Install metasploit-framework.")
            return False

        try:
            subprocess.Popen(
                ["msfrpcd", "-P", MSF_RPC_PASSWORD, "-p", str(MSF_RPC_PORT),
                 "-S", "-f"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait for it to start
            for _ in range(15):
                time.sleep(1)
                if self.is_running():
                    logger.info("msfrpcd started successfully")
                    return True
            logger.error("msfrpcd failed to start in time")
            return False
        except Exception as e:
            logger.error(f"Failed to start msfrpcd: {e}")
            return False

    def ensure_connected(self) -> bool:
        """Ensure connection to MSF RPC — start if needed."""
        if self.connected:
            return True
        if not self.is_running():
            if not self.start_rpc():
                return False
        return self.connect()

    def search_exploits(self, device: Device) -> list[dict]:
        """Search for exploits matching device vulnerabilities."""
        if not self.ensure_connected():
            return []

        results = []
        search_terms = set()

        # Search by CVE
        for vuln in device.vulnerabilities:
            if vuln.cve_id:
                search_terms.add(f"cve:{vuln.cve_id.replace('CVE-', '')}")

        # Search by brand/product
        if device.brand:
            search_terms.add(device.brand.lower())
        if device.model:
            search_terms.add(device.model.lower())

        for term in search_terms:
            try:
                modules = self.client.modules.search(term)
                for mod in modules:
                    results.append({
                        "name": mod.get("name", ""),
                        "fullname": mod.get("fullname", ""),
                        "type": mod.get("type", ""),
                        "rank": mod.get("rank", ""),
                        "description": mod.get("description", "")[:200],
                        "search_term": term,
                    })
            except Exception as e:
                logger.debug(f"MSF search failed for '{term}': {e}")

        # Deduplicate by fullname
        seen = set()
        unique = []
        for r in results:
            if r["fullname"] not in seen:
                seen.add(r["fullname"])
                unique.append(r)

        return unique

    def run_auxiliary(self, module_name: str, options: dict) -> dict:
        """Run an auxiliary module."""
        if not self.ensure_connected():
            return {"error": "Not connected to MSF"}

        try:
            module = self.client.modules.use("auxiliary", module_name)
            for key, value in options.items():
                module[key] = value

            job_id = module.execute()
            return {
                "status": "running",
                "job_id": job_id,
                "module": module_name,
            }
        except Exception as e:
            return {"error": str(e)}

    def run_exploit(self, module_name: str, options: dict,
                    payload: str = "") -> dict:
        """Run an exploit module."""
        if not self.ensure_connected():
            return {"error": "Not connected to MSF"}

        try:
            exploit = self.client.modules.use("exploit", module_name)
            for key, value in options.items():
                exploit[key] = value

            if payload:
                p = self.client.modules.use("payload", payload)
                result = exploit.execute(payload=p)
            else:
                result = exploit.execute()

            return {
                "status": "running",
                "job_id": result.get("job_id"),
                "uuid": result.get("uuid"),
                "module": module_name,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_sessions(self) -> list[dict]:
        """Get active Metasploit sessions."""
        if not self.ensure_connected():
            return []
        try:
            sessions = self.client.sessions.list
            return [
                {
                    "id": sid,
                    "type": info.get("type", ""),
                    "info": info.get("info", ""),
                    "target_host": info.get("target_host", ""),
                    "via_exploit": info.get("via_exploit", ""),
                }
                for sid, info in sessions.items()
            ]
        except Exception:
            return []

    def get_jobs(self) -> list[dict]:
        """Get running Metasploit jobs."""
        if not self.ensure_connected():
            return []
        try:
            jobs = self.client.jobs.list
            return [
                {"id": jid, "name": name}
                for jid, name in jobs.items()
            ]
        except Exception:
            return []


# Known MSF modules for cameras/IoT
CAMERA_MODULES = {
    "hikvision_rce": {
        "module": "auxiliary/scanner/http/hikvision_cve_2021_36260",
        "description": "Hikvision IP Camera RCE (CVE-2021-36260)",
        "options": {"RHOSTS": "", "RPORT": "80"},
    },
    "rtsp_login": {
        "module": "auxiliary/scanner/rtsp/rtsp_login",
        "description": "RTSP Authentication Scanner",
        "options": {"RHOSTS": "", "RPORT": "554"},
    },
    "http_login": {
        "module": "auxiliary/scanner/http/http_login",
        "description": "HTTP Login Credential Scanner",
        "options": {"RHOSTS": "", "RPORT": "80"},
    },
    "snmp_enum": {
        "module": "auxiliary/scanner/snmp/snmp_enum",
        "description": "SNMP Enumeration Scanner",
        "options": {"RHOSTS": "", "RPORT": "161"},
    },
    "upnp_ssdp": {
        "module": "auxiliary/scanner/upnp/ssdp_msearch",
        "description": "UPnP SSDP M-SEARCH Discovery",
        "options": {"RHOSTS": ""},
    },
    "ssh_login": {
        "module": "auxiliary/scanner/ssh/ssh_login",
        "description": "SSH Login Check Scanner",
        "options": {"RHOSTS": "", "RPORT": "22"},
    },
    "telnet_login": {
        "module": "auxiliary/scanner/telnet/telnet_login",
        "description": "Telnet Login Check Scanner",
        "options": {"RHOSTS": "", "RPORT": "23"},
    },
}


def get_suggested_modules(device: Device) -> list[dict]:
    """Get suggested MSF modules for a device."""
    suggestions = []
    ports = set(device.open_ports)

    # RTSP scanner
    if 554 in ports:
        mod = CAMERA_MODULES["rtsp_login"].copy()
        mod["options"] = {**mod["options"], "RHOSTS": device.ip}
        suggestions.append(mod)

    # HTTP login
    if ports & {80, 8080, 443, 8443}:
        mod = CAMERA_MODULES["http_login"].copy()
        http_port = next(p for p in (80, 8080, 443, 8443) if p in ports)
        mod["options"] = {**mod["options"], "RHOSTS": device.ip, "RPORT": str(http_port)}
        suggestions.append(mod)

    # Hikvision specific
    if device.brand and device.brand.lower() == "hikvision":
        mod = CAMERA_MODULES["hikvision_rce"].copy()
        mod["options"] = {**mod["options"], "RHOSTS": device.ip}
        suggestions.append(mod)

    # SNMP
    if 161 in ports:
        mod = CAMERA_MODULES["snmp_enum"].copy()
        mod["options"] = {**mod["options"], "RHOSTS": device.ip}
        suggestions.append(mod)

    # SSH
    if 22 in ports:
        mod = CAMERA_MODULES["ssh_login"].copy()
        mod["options"] = {**mod["options"], "RHOSTS": device.ip}
        suggestions.append(mod)

    # Telnet
    if 23 in ports:
        mod = CAMERA_MODULES["telnet_login"].copy()
        mod["options"] = {**mod["options"], "RHOSTS": device.ip}
        suggestions.append(mod)

    return suggestions


# Global MSF client instance
msf_client = MetasploitClient()
