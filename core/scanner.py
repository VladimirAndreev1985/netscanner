"""Network scanner — ARP discovery, port scanning, service detection."""

import subprocess
import asyncio
import logging
import shutil
from typing import Callable

from core.device import Device
from core.mac_lookup import lookup_vendor, get_brand_from_mac

logger = logging.getLogger("netscanner.scanner")

# Key ports by device type
CAMERA_PORTS = [80, 443, 554, 8080, 8443, 8000, 8001, 8899, 37777, 37778, 34567, 34599, 9000, 85, 81]
IOT_PORTS = [1883, 8883, 5683, 502, 47808, 8081, 4443, 6668, 9090]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445, 993, 995,
                1433, 1723, 3306, 3389, 5060, 5432, 5900, 8080, 8443, 8888, 9100]
ALL_SCAN_PORTS = sorted(set(CAMERA_PORTS + IOT_PORTS + COMMON_PORTS))


async def arp_scan(subnet: str, callback: Callable | None = None) -> list[Device]:
    """Fast ARP discovery to find live hosts."""
    devices = []
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0

        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: srp(packet, timeout=3, verbose=0)[0]
        )

        for sent, received in result:
            mac = received.hwsrc
            ip = received.psrc
            vendor = lookup_vendor(mac)
            brand = get_brand_from_mac(mac)
            dev = Device(ip=ip, mac=mac, vendor=vendor, brand=brand)
            devices.append(dev)
            if callback:
                callback(dev)

    except ImportError:
        logger.warning("scapy not available, falling back to arp-scan")
        devices = await _arp_scan_fallback(subnet, callback)
    except Exception as e:
        logger.error(f"ARP scan failed: {e}")
        devices = await _arp_scan_fallback(subnet, callback)

    return devices


async def _arp_scan_fallback(subnet: str, callback: Callable | None = None) -> list[Device]:
    """Fallback ARP scan using arp-scan command."""
    devices = []
    if not shutil.which("arp-scan"):
        logger.warning("arp-scan not found, skipping ARP discovery")
        return devices

    try:
        proc = await asyncio.create_subprocess_exec(
            "arp-scan", "--localnet", subnet,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

        for line in stdout.decode().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip = parts[0].strip()
                mac = parts[1].strip()
                if _is_valid_ip(ip) and _is_valid_mac(mac):
                    vendor = lookup_vendor(mac)
                    brand = get_brand_from_mac(mac)
                    dev = Device(ip=ip, mac=mac, vendor=vendor, brand=brand)
                    devices.append(dev)
                    if callback:
                        callback(dev)
    except (asyncio.TimeoutError, FileNotFoundError) as e:
        logger.error(f"arp-scan fallback failed: {e}")

    return devices


async def nmap_scan(target: str, scan_type: str = "normal",
                    callback: Callable | None = None) -> list[Device]:
    """Nmap port scan and service detection."""
    # Build nmap arguments based on scan type
    if scan_type == "quick":
        args = ["-sS", "-T4", "--top-ports", "100", "-O", "--osscan-guess"]
    elif scan_type == "deep":
        ports = ",".join(str(p) for p in ALL_SCAN_PORTS)
        args = ["-sS", "-sV", "-T4", "-p", ports, "-O", "--osscan-guess",
                "--script=banner,http-title,http-server-header,rtsp-methods"]
    else:  # normal
        ports = ",".join(str(p) for p in ALL_SCAN_PORTS)
        args = ["-sS", "-sV", "-T4", "-p", ports, "-O", "--osscan-guess"]

    devices = []
    try:
        import nmap
        nm = nmap.PortScanner()

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, lambda: nm.scan(hosts=target, arguments=" ".join(args))
        )

        for host in nm.all_hosts():
            dev = _parse_nmap_host(nm, host)
            devices.append(dev)
            if callback:
                callback(dev)

    except ImportError:
        logger.warning("python-nmap not available, using nmap directly")
        devices = await _nmap_direct(target, args, callback)
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")

    return devices


def _parse_nmap_host(nm, host: str) -> Device:
    """Parse nmap results for a single host."""
    host_info = nm[host]
    dev = Device(ip=host)

    # MAC address
    if "mac" in host_info.get("addresses", {}):
        dev.mac = host_info["addresses"]["mac"]
        dev.vendor = lookup_vendor(dev.mac)
        dev.brand = get_brand_from_mac(dev.mac)

    # Hostname
    hostnames = host_info.get("hostnames", [])
    if hostnames and hostnames[0].get("name"):
        dev.hostname = hostnames[0]["name"]

    # OS detection
    os_matches = host_info.get("osmatch", [])
    if os_matches:
        dev.os_guess = os_matches[0].get("name", "")

    # Vendor from nmap if not from MAC
    if not dev.vendor:
        vendor_info = host_info.get("vendor", {})
        if dev.mac and dev.mac in vendor_info:
            dev.vendor = vendor_info[dev.mac]

    # Ports and services
    for proto in ("tcp", "udp"):
        if proto not in host_info:
            continue
        for port, port_info in host_info[proto].items():
            if port_info.get("state") == "open":
                dev.open_ports.append(port)
                dev.services[port] = {
                    "name": port_info.get("name", ""),
                    "product": port_info.get("product", ""),
                    "version": port_info.get("version", ""),
                    "extrainfo": port_info.get("extrainfo", ""),
                }

    dev.open_ports.sort()

    # Detect web interface
    for port in (80, 443, 8080, 8443, 8000, 81, 85, 9000):
        if port in dev.open_ports:
            scheme = "https" if port in (443, 8443) else "http"
            dev.web_interface = f"{scheme}://{dev.ip}:{port}"
            break

    return dev


async def _nmap_direct(target: str, args: list[str],
                       callback: Callable | None = None) -> list[Device]:
    """Run nmap directly via subprocess."""
    devices = []
    if not shutil.which("nmap"):
        logger.error("nmap not found!")
        return devices

    cmd = ["nmap", "-oX", "-"] + args + target.split()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
        # Parse XML output with python-nmap if available, or basic parsing
        import nmap
        nm = nmap.PortScanner()
        nm.analyse_nmap_xml_scan(stdout.decode())
        for host in nm.all_hosts():
            dev = _parse_nmap_host(nm, host)
            devices.append(dev)
            if callback:
                callback(dev)
    except Exception as e:
        logger.error(f"Direct nmap failed: {e}")

    return devices


async def masscan_scan(target: str, ports: str = "80,443,554,8080",
                       rate: int = 1000,
                       callback: Callable | None = None) -> list[Device]:
    """Fast masscan for large networks."""
    devices = []
    if not shutil.which("masscan"):
        logger.warning("masscan not available")
        return devices

    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oJ", "-"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)

        import json
        # masscan JSON output: array of objects
        text = stdout.decode().strip()
        if text.endswith(","):
            text = text[:-1]
        if not text.startswith("["):
            text = "[" + text + "]"

        found_ips = {}
        try:
            results = json.loads(text)
            for entry in results:
                ip = entry.get("ip", "")
                port = entry.get("ports", [{}])[0].get("port", 0)
                if ip and ip not in found_ips:
                    found_ips[ip] = Device(ip=ip)
                if ip and port:
                    found_ips[ip].open_ports.append(port)
        except json.JSONDecodeError:
            pass

        devices = list(found_ips.values())
        for dev in devices:
            dev.open_ports.sort()
            if callback:
                callback(dev)

    except (asyncio.TimeoutError, FileNotFoundError) as e:
        logger.error(f"masscan failed: {e}")

    return devices


async def full_scan(target: str, scan_type: str = "normal",
                    progress_callback: Callable | None = None) -> list[Device]:
    """Full scan pipeline: ARP discovery → port scan → merge results."""
    all_devices: dict[str, Device] = {}

    # Handle comma-separated targets (rescan of specific IPs)
    is_targeted = "," in target
    nmap_target = target.replace(",", " ") if is_targeted else target

    # Phase 1: ARP discovery (skip for targeted rescan — hosts already known)
    if not is_targeted:
        if progress_callback:
            progress_callback("arp", 0, "ARP Discovery...")

        arp_devices = await arp_scan(target)
        for dev in arp_devices:
            all_devices[dev.ip] = dev

        if progress_callback:
            progress_callback("arp", 100, f"Found {len(arp_devices)} hosts")

    # Phase 2: Port scanning
    if progress_callback:
        progress_callback("nmap", 0, "Port scanning...")

    nmap_devices = await nmap_scan(nmap_target, scan_type)

    # Merge results
    for dev in nmap_devices:
        if dev.ip in all_devices:
            existing = all_devices[dev.ip]
            # Merge nmap data into existing ARP-discovered device
            existing.open_ports = dev.open_ports or existing.open_ports
            existing.services = dev.services or existing.services
            existing.os_guess = dev.os_guess or existing.os_guess
            existing.hostname = dev.hostname or existing.hostname
            existing.web_interface = dev.web_interface or existing.web_interface
            if not existing.mac and dev.mac:
                existing.mac = dev.mac
                existing.vendor = dev.vendor
                existing.brand = dev.brand
        else:
            all_devices[dev.ip] = dev

    if progress_callback:
        progress_callback("nmap", 100, f"Scanned {len(all_devices)} hosts")

    return list(all_devices.values())


def _is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _is_valid_mac(mac: str) -> bool:
    return len(mac) == 17 and mac.count(":") == 5
