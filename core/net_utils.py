"""Network utilities — auto-detect interfaces, subnets, gateways."""

import subprocess
import socket
import struct
import re
from dataclasses import dataclass


@dataclass
class NetworkInterface:
    name: str
    ip: str
    netmask: str
    subnet: str      # e.g., "192.168.1.0/24"
    gateway: str
    mac: str
    is_up: bool


def get_interfaces() -> list[NetworkInterface]:
    """Detect all active network interfaces with their subnets."""
    interfaces = []
    try:
        import netifaces
        gateway_info = netifaces.gateways()
        default_gw = ""
        if netifaces.AF_INET in gateway_info.get("default", {}):
            default_gw = gateway_info["default"][netifaces.AF_INET][0]

        for iface_name in netifaces.interfaces():
            # Skip loopback
            if iface_name == "lo":
                continue
            addrs = netifaces.ifaddresses(iface_name)

            # Get IPv4 address
            if netifaces.AF_INET not in addrs:
                continue
            ipv4 = addrs[netifaces.AF_INET][0]
            ip = ipv4.get("addr", "")
            netmask = ipv4.get("netmask", "")
            if not ip or ip.startswith("127."):
                continue

            # Get MAC
            mac = ""
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0].get("addr", "")

            # Calculate subnet
            subnet = _calc_subnet(ip, netmask)

            # Determine gateway for this interface
            gw = default_gw
            for gw_entry in gateway_info.get(netifaces.AF_INET, []):
                if gw_entry[1] == iface_name:
                    gw = gw_entry[0]
                    break

            interfaces.append(NetworkInterface(
                name=iface_name,
                ip=ip,
                netmask=netmask,
                subnet=subnet,
                gateway=gw,
                mac=mac,
                is_up=True,
            ))
    except ImportError:
        # Fallback: parse ip addr output
        interfaces = _parse_ip_addr()

    return interfaces


def _calc_subnet(ip: str, netmask: str) -> str:
    """Calculate subnet in CIDR notation."""
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        network = ip_int & mask_int
        network_ip = socket.inet_ntoa(struct.pack("!I", network))
        # Count bits in mask
        cidr = bin(mask_int).count("1")
        return f"{network_ip}/{cidr}"
    except (socket.error, struct.error):
        return f"{ip}/24"


def _parse_ip_addr() -> list[NetworkInterface]:
    """Fallback: parse 'ip addr' output."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=10
        )
        current_iface = ""
        current_mac = ""
        for line in result.stdout.splitlines():
            # Interface line: "2: eth0: <BROADCAST,..."
            iface_match = re.match(r"^\d+:\s+(\S+):", line)
            if iface_match:
                current_iface = iface_match.group(1)
                current_mac = ""
                continue

            # MAC line
            mac_match = re.search(r"link/ether\s+([0-9a-f:]+)", line)
            if mac_match:
                current_mac = mac_match.group(1)
                continue

            # IPv4 line: "    inet 192.168.1.100/24 ..."
            inet_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if inet_match and current_iface != "lo":
                ip = inet_match.group(1)
                cidr = int(inet_match.group(2))
                mask_int = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
                netmask = socket.inet_ntoa(struct.pack("!I", mask_int))
                subnet = _calc_subnet(ip, netmask)

                interfaces.append(NetworkInterface(
                    name=current_iface,
                    ip=ip,
                    netmask=netmask,
                    subnet=subnet,
                    gateway=_get_default_gateway(),
                    mac=current_mac,
                    is_up=True,
                ))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return interfaces


def _get_default_gateway() -> str:
    """Get default gateway IP."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def get_local_ip() -> str:
    """Get the primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def auto_detect_targets() -> list[str]:
    """Return list of subnets available for scanning."""
    interfaces = get_interfaces()
    subnets = []
    for iface in interfaces:
        if iface.subnet and not iface.ip.startswith("127."):
            subnets.append(iface.subnet)
    return subnets
