"""Dependency manager — checks and installs system/python packages."""

import subprocess
import shutil
import sys
import os
from dataclasses import dataclass


@dataclass
class Dependency:
    name: str
    check_cmd: str       # command to check if installed
    install_cmd: str     # command to install
    critical: bool       # required for basic operation
    description: str


SYSTEM_DEPS = [
    Dependency("nmap", "nmap", "apt-get install -y nmap", True,
               "Network port scanner"),
    Dependency("masscan", "masscan", "apt-get install -y masscan", False,
               "Fast mass port scanner"),
    Dependency("arp-scan", "arp-scan", "apt-get install -y arp-scan", False,
               "ARP-based network scanner"),
    Dependency("nbtscan", "nbtscan", "apt-get install -y nbtscan", False,
               "NetBIOS name scanner"),
    Dependency("snmpwalk", "snmpwalk", "apt-get install -y snmp", False,
               "SNMP enumeration tool"),
    Dependency("hydra", "hydra", "apt-get install -y hydra", False,
               "Network login cracker"),
    Dependency("ffmpeg", "ffmpeg", "apt-get install -y ffmpeg", False,
               "Media tool (RTSP frame capture)"),
    Dependency("searchsploit", "searchsploit", "apt-get install -y exploitdb", False,
               "Exploit-DB local search"),
    Dependency("msfconsole", "msfconsole", "apt-get install -y metasploit-framework", False,
               "Metasploit Framework"),
    Dependency("testssl.sh", "testssl.sh", "apt-get install -y testssl.sh", False,
               "SSL/TLS security tester"),
    Dependency("curl", "curl", "apt-get install -y curl", True,
               "HTTP client"),
]

PYTHON_DEPS = [
    "textual>=0.47.0",
    "rich>=13.0",
    "python-nmap>=0.7.1",
    "scapy>=2.5.0",
    "aiohttp>=3.9.0",
    "mac-vendor-lookup>=0.1.12",
    "netifaces>=0.11.0",
    "paramiko>=3.4.0",
    "requests>=2.31.0",
    "pymetasploit3>=1.0.3",
    "shodan>=1.31.0",
    "reportlab>=4.0",
]


def check_system_dep(dep: Dependency) -> bool:
    """Check if a system dependency is available."""
    return shutil.which(dep.check_cmd) is not None


def check_all_system_deps() -> dict[str, dict]:
    """Check all system dependencies, return status dict."""
    results = {}
    for dep in SYSTEM_DEPS:
        installed = check_system_dep(dep)
        results[dep.name] = {
            "installed": installed,
            "critical": dep.critical,
            "description": dep.description,
            "install_cmd": dep.install_cmd,
        }
    return results


def install_system_dep(dep: Dependency) -> bool:
    """Install a system dependency. Requires root."""
    if os.geteuid() != 0:
        return False
    try:
        subprocess.run(
            dep.install_cmd.split(),
            capture_output=True, timeout=120
        )
        return check_system_dep(dep)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_python_dep(package: str) -> bool:
    """Check if a Python package is installed."""
    pkg_name = package.split(">=")[0].split("==")[0].split(">")[0].split("<")[0]
    # Handle package name mapping (pip name != import name)
    import_map = {
        "python-nmap": "nmap",
        "mac-vendor-lookup": "mac_vendor_lookup",
        "pymetasploit3": "pymetasploit3",
        "Pillow": "PIL",
    }
    import_name = import_map.get(pkg_name, pkg_name.replace("-", "_"))
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


def check_all_python_deps() -> dict[str, bool]:
    """Check all Python dependencies."""
    return {pkg: check_python_dep(pkg) for pkg in PYTHON_DEPS}


def install_python_deps(packages: list[str] | None = None) -> bool:
    """Install Python packages via pip."""
    if packages is None:
        packages = PYTHON_DEPS
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q"] + packages,
            capture_output=True, timeout=300
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_missing_critical() -> list[str]:
    """Get list of missing critical dependencies."""
    missing = []
    for dep in SYSTEM_DEPS:
        if dep.critical and not check_system_dep(dep):
            missing.append(dep.name)
    return missing


def print_status():
    """Print dependency status to console."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    table = Table(title="System Dependencies")
    table.add_column("Package", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Required", style="yellow")
    table.add_column("Description")

    sys_deps = check_all_system_deps()
    for name, info in sys_deps.items():
        status = "[green]✓ Installed[/]" if info["installed"] else "[red]✗ Missing[/]"
        required = "[red]Yes[/]" if info["critical"] else "No"
        table.add_row(name, status, required, info["description"])

    console.print(table)
    console.print()

    table2 = Table(title="Python Dependencies")
    table2.add_column("Package", style="cyan")
    table2.add_column("Status", style="bold")

    py_deps = check_all_python_deps()
    for name, installed in py_deps.items():
        status = "[green]✓ Installed[/]" if installed else "[red]✗ Missing[/]"
        table2.add_row(name, status)

    console.print(table2)

    missing_critical = get_missing_critical()
    if missing_critical:
        console.print(f"\n[red][!] Missing critical dependencies: {', '.join(missing_critical)}[/]")
        console.print("[yellow]    Run: sudo bash install.sh[/]")
    else:
        console.print("\n[green][✓] All critical dependencies satisfied[/]")
