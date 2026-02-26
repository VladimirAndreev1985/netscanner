"""Device model — represents a discovered network device."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: float = 0.0
    severity: str = "unknown"  # critical, high, medium, low
    description: str = ""
    exploit_available: bool = False
    exploit_url: str = ""
    affected_versions: str = ""


@dataclass
class Credential:
    protocol: str = ""  # http, rtsp, ssh, telnet, snmp, onvif, mqtt
    username: str = ""
    password: str = ""
    success: bool = False
    url: str = ""


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""             # Manufacturer from MAC OUI
    device_type: str = "unknown" # camera, iot, pc, router, printer, nvr, dvr, unknown
    brand: str = ""              # Hikvision, Dahua, Axis, Reolink...
    model: str = ""
    firmware_version: str = ""
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, dict[str, str]] = field(default_factory=dict)
    os_guess: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    default_creds: list[Credential] = field(default_factory=list)
    web_interface: str = ""
    rtsp_urls: list[str] = field(default_factory=list)
    onvif_info: dict[str, Any] = field(default_factory=dict)
    screenshots: list[str] = field(default_factory=list)
    exploit_results: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0  # 0-10
    extra_info: dict[str, Any] = field(default_factory=dict)
    scan_time: str = ""

    @property
    def is_camera(self) -> bool:
        return self.device_type in ("camera", "nvr", "dvr")

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def has_default_creds(self) -> bool:
        return any(c.success for c in self.default_creds)

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 9.0:
            return "critical"
        elif self.risk_score >= 7.0:
            return "high"
        elif self.risk_score >= 4.0:
            return "medium"
        elif self.risk_score > 0:
            return "low"
        return "info"

    def calculate_risk_score(self) -> float:
        score = 0.0
        # CVE-based risk
        if self.vulnerabilities:
            max_cvss = max(v.cvss_score for v in self.vulnerabilities)
            score = max(score, max_cvss)
            if any(v.exploit_available for v in self.vulnerabilities):
                score = min(10.0, score + 1.0)
        # Default credentials found
        if self.has_default_creds:
            score = max(score, 8.0)
        # Open management ports without auth
        risky_ports = {23, 21, 502, 161}  # telnet, ftp, modbus, snmp
        if risky_ports & set(self.open_ports):
            score = max(score, 5.0)
        self.risk_score = round(score, 1)
        return self.risk_score

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "brand": self.brand,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "open_ports": self.open_ports,
            "services": self.services,
            "os_guess": self.os_guess,
            "vulnerabilities": [
                {"cve_id": v.cve_id, "cvss_score": v.cvss_score,
                 "severity": v.severity, "description": v.description,
                 "exploit_available": v.exploit_available, "exploit_url": v.exploit_url}
                for v in self.vulnerabilities
            ],
            "default_creds": [
                {"protocol": c.protocol, "username": c.username,
                 "password": c.password, "success": c.success, "url": c.url}
                for c in self.default_creds
            ],
            "web_interface": self.web_interface,
            "rtsp_urls": self.rtsp_urls,
            "onvif_info": self.onvif_info,
            "screenshots": self.screenshots,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "extra_info": self.extra_info,
            "scan_time": self.scan_time,
        }
