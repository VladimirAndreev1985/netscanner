"""WiFi Manager — adapter detection, network scanning, connection, recon."""

import asyncio
import csv
import io
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("netscanner.wifi")


# ═══════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str = ""
    signal: int = 0
    frequency: str = ""
    channel: int = 0
    security: str = "Unknown"
    in_use: bool = False
    router_vendor: str = ""
    wps_enabled: bool = False
    hidden: bool = False
    clients_count: int = 0
    clients: list[str] = field(default_factory=list)
    data_packets: int = 0
    max_speed: str = ""


@dataclass
class WiFiAdapter:
    name: str
    state: str = "disconnected"
    mac: str = ""
    driver: str = ""
    chipset: str = ""
    mode: str = "managed"
    current_ssid: str = ""
    supports_monitor: bool = False


@dataclass
class ConnectedClient:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""


@dataclass
class GatewayInfo:
    ip: str = ""
    mac: str = ""
    vendor: str = ""
    ports: list[dict] = field(default_factory=list)
    model: str = ""


@dataclass
class ConnectionInfo:
    ip: str = ""
    subnet: str = ""
    gateway: str = ""
    dns: list[str] = field(default_factory=list)
    dhcp_server: str = ""
    lease_time: str = ""
    ssid: str = ""
    adapter: str = ""


# ═══════════════════════════════════════════════════════════════
# Helper: run shell command
# ═══════════════════════════════════════════════════════════════

# Comprehensive regex for ALL ANSI/terminal escape sequences
_ANSI_RE = re.compile(
    r"\x1b"           # ESC character
    r"(?:"
    r"\[[0-9;?<>=]*[A-Za-z~]"   # CSI sequences: \x1b[...X (incl. mouse, DEC private)
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences: \x1b]...BEL or \x1b]...\x1b\\
    r"|\([A-Za-z]"               # Character set: \x1b(X
    r"|[=>NOM78DHE]"             # Single-char sequences
    r"|P[^\x1b]*\x1b\\\\"       # DCS sequences
    r")"
)


def _strip_ansi(text: str) -> str:
    """Remove all ANSI/terminal escape sequences from text."""
    return _ANSI_RE.sub("", text)


async def _run(cmd: list[str], timeout: int = 30,
               new_session: bool = False) -> tuple[str, str, int]:
    """Run command and return (stdout, stderr, returncode).

    All subprocesses get stdin=/dev/null to prevent terminal interference
    when running inside a TUI. ANSI codes are stripped from output.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=new_session,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return (
            _strip_ansi(stdout.decode("utf-8", errors="replace")),
            _strip_ansi(stderr.decode("utf-8", errors="replace")),
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return "", "Timeout", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def _vendor_from_mac(mac: str) -> str:
    """Look up vendor from MAC address using mac_lookup module."""
    try:
        from core.mac_lookup import lookup_vendor
        return lookup_vendor(mac) or ""
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════
# WiFi Adapter Detection
# ═══════════════════════════════════════════════════════════════

async def get_wifi_adapters() -> list[WiFiAdapter]:
    """Detect WiFi adapters using iw dev + nmcli."""
    adapters: dict[str, WiFiAdapter] = {}

    # Method 1: iw dev — get interface names and MAC
    stdout, _, rc = await _run(["iw", "dev"])
    if rc == 0:
        current_iface = ""
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                current_iface = line.split()[-1]
                adapters[current_iface] = WiFiAdapter(name=current_iface)
            elif current_iface:
                if line.startswith("addr"):
                    adapters[current_iface].mac = line.split()[-1].upper()
                elif line.startswith("type"):
                    mode = line.split()[-1]
                    adapters[current_iface].mode = mode
                elif line.startswith("ssid"):
                    adapters[current_iface].current_ssid = line.split(None, 1)[-1]
                    adapters[current_iface].state = "connected"

    # Method 2: nmcli device status — get state info
    stdout, _, rc = await _run([
        "nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"
    ])
    if rc == 0:
        for line in stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[1] == "wifi":
                name = parts[0]
                if name not in adapters:
                    adapters[name] = WiFiAdapter(name=name)
                state = parts[2]
                if "connected" in state:
                    adapters[name].state = "connected"
                    adapters[name].current_ssid = parts[3] if parts[3] else ""
                else:
                    adapters[name].state = "disconnected"

    # Get driver info for each adapter
    for name, adapter in adapters.items():
        stdout, _, rc = await _run(["ethtool", "-i", name])
        if rc == 0:
            for line in stdout.splitlines():
                if line.startswith("driver:"):
                    adapter.driver = line.split(":", 1)[1].strip()

        # Check monitor mode support
        stdout, _, rc = await _run(["iw", "phy"])
        if rc == 0 and "monitor" in stdout:
            adapter.supports_monitor = True

        # Try iw list for more detailed check
        stdout, _, rc = await _run(["iw", name, "info"])
        if rc == 0 and "monitor" in stdout.lower():
            adapter.supports_monitor = True

    return list(adapters.values())


# ═══════════════════════════════════════════════════════════════
# Quick Scan (nmcli — no monitor mode)
# ═══════════════════════════════════════════════════════════════

async def scan_networks(adapter: str = "wlan0") -> list[WiFiNetwork]:
    """Quick WiFi scan using nmcli (no monitor mode needed)."""
    # Force rescan
    await _run(["nmcli", "device", "wifi", "rescan", "ifname", adapter])
    await asyncio.sleep(2)

    stdout, _, rc = await _run([
        "nmcli", "-t", "-f",
        "SSID,BSSID,SIGNAL,FREQ,CHAN,SECURITY,IN-USE,WPA-FLAGS,RSN-FLAGS,MODE,RATE",
        "device", "wifi", "list", "ifname", adapter
    ])
    if rc != 0:
        # Fallback without ifname
        stdout, _, rc = await _run([
            "nmcli", "-t", "-f",
            "SSID,BSSID,SIGNAL,FREQ,CHAN,SECURITY,IN-USE",
            "device", "wifi", "list"
        ])

    networks = []
    seen_bssids = set()

    if rc == 0:
        for line in stdout.strip().splitlines():
            # nmcli -t uses : as separator, but BSSID contains :
            # Parse carefully — SSID is first field, then BSSID (XX\:XX\:XX\:XX\:XX\:XX)
            parts = line.replace("\\:", "§").split(":")
            parts = [p.replace("§", ":") for p in parts]

            if len(parts) < 7:
                continue

            ssid = parts[0]
            bssid = parts[1].strip().upper()
            if bssid in seen_bssids:
                continue
            seen_bssids.add(bssid)

            try:
                signal = int(parts[2]) if parts[2] else 0
            except ValueError:
                signal = 0

            freq_str = parts[3] if len(parts) > 3 else ""
            try:
                freq_mhz = int(freq_str.split()[0]) if freq_str else 0
                frequency = "5 GHz" if freq_mhz > 4000 else "2.4 GHz"
            except (ValueError, IndexError):
                frequency = ""

            try:
                channel = int(parts[4]) if parts[4] else 0
            except ValueError:
                channel = 0

            security = parts[5] if len(parts) > 5 else ""
            in_use = parts[6].strip() == "*" if len(parts) > 6 else False

            # Detect WPS from flags
            wps = False
            if len(parts) > 8:
                wps_flags = " ".join(parts[7:9])
                if "wps" in wps_flags.lower():
                    wps = True

            # Max speed
            max_speed = parts[10] if len(parts) > 10 else ""

            hidden = not ssid or ssid == "--"
            vendor = _vendor_from_mac(bssid)

            networks.append(WiFiNetwork(
                ssid=ssid if not hidden else "",
                bssid=bssid,
                signal=signal,
                frequency=frequency,
                channel=channel,
                security=security if security else "Open",
                in_use=in_use,
                router_vendor=vendor,
                wps_enabled=wps,
                hidden=hidden,
                max_speed=max_speed,
            ))

    # Sort by signal strength descending
    networks.sort(key=lambda n: n.signal, reverse=True)
    return networks


# ═══════════════════════════════════════════════════════════════
# Deep Scan (airodump-ng — monitor mode, shows clients)
# ═══════════════════════════════════════════════════════════════

async def scan_networks_deep(
    adapter: str = "wlan0",
    duration: int = 20,
    log_callback=None,
    update_callback=None,
) -> list[WiFiNetwork]:
    """Deep WiFi scan using airodump-ng — shows clients per network."""

    def log(msg):
        if log_callback:
            log_callback(msg)
        logger.info(msg)

    mon_iface = f"{adapter}mon"
    tmp_prefix = os.path.join(tempfile.gettempdir(), f"netscanner_airodump_{int(time.time())}")
    csv_file = f"{tmp_prefix}-01.csv"

    cleanup_needed = True
    try:
        # 0. Suppress kernel console messages (they corrupt TUI display)
        await _run(["dmesg", "-D"], timeout=3, new_session=True)

        # 1. Kill interfering processes (fully isolated from TUI)
        log("Stopping interfering processes...")
        await _run(["airmon-ng", "check", "kill"], timeout=10, new_session=True)
        await asyncio.sleep(1)

        # 2. Start monitor mode
        log(f"Starting monitor mode on {adapter}...")
        stdout, stderr, rc = await _run(
            ["airmon-ng", "start", adapter], timeout=15, new_session=True
        )
        if rc != 0:
            log(f"Failed to start monitor mode: {stderr}")
            return []

        # Detect actual monitor interface name
        for possible in [mon_iface, "mon0", f"{adapter}mon"]:
            check_out, _, _ = await _run(["iw", "dev"])
            if possible in check_out:
                mon_iface = possible
                break

        log(f"Monitor interface: {mon_iface}")

        # 3. Run airodump-ng (fully isolated: new session, no stdin/stdout/stderr)
        log(f"Scanning airwaves for {duration} seconds...")
        proc = await asyncio.create_subprocess_exec(
            "airodump-ng", mon_iface,
            "--write", tmp_prefix,
            "--output-format", "csv",
            "--write-interval", "1",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )

        # Wait for scan duration with progress updates and intermediate results
        for elapsed in range(duration):
            await asyncio.sleep(1)
            if log_callback and elapsed % 5 == 4:
                log(f"Scanning... {elapsed + 1}/{duration}s")
            # Send intermediate results every 3 seconds for real-time table updates
            if update_callback and elapsed >= 3 and elapsed % 3 == 0:
                try:
                    intermediate = _parse_airodump_csv(csv_file, skip_vendor=True)
                    if intermediate:
                        update_callback(intermediate, elapsed + 1, duration)
                except Exception:
                    pass

        # Kill airodump (kill entire process group since it's in its own session)
        try:
            import signal as sig
            os.killpg(os.getpgid(proc.pid), sig.SIGTERM)
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass

        # 4. Stop monitor mode
        log("Stopping monitor mode...")
        await _run(["airmon-ng", "stop", mon_iface], timeout=10, new_session=True)

        # 5. Restart NetworkManager
        log("Restarting NetworkManager...")
        await _run(["systemctl", "restart", "NetworkManager"], timeout=15)
        await asyncio.sleep(3)

        # 6. Re-enable kernel console messages
        await _run(["dmesg", "-E"], timeout=3, new_session=True)

        # 7. Parse CSV results
        log("Parsing scan results...")
        cleanup_needed = False
        return _parse_airodump_csv(csv_file)

    except Exception as e:
        logger.error(f"Deep scan error: {e}")
        log(f"Error: {e}")
        return []
    finally:
        if cleanup_needed:
            # Only cleanup if the try block didn't complete fully
            await _run(["airmon-ng", "stop", mon_iface], timeout=5, new_session=True)
            await _run(["systemctl", "restart", "NetworkManager"], timeout=10)
        # Always re-enable kernel console messages
        await _run(["dmesg", "-E"], timeout=3, new_session=True)
        # Clean temp files
        for suffix in ["-01.csv", "-01.kismet.csv", "-01.kismet.netxml",
                       "-01.cap", "-01.log.csv"]:
            try:
                Path(tmp_prefix + suffix).unlink(missing_ok=True)
            except Exception:
                pass


def _parse_airodump_csv(csv_path: str, skip_vendor: bool = False) -> list[WiFiNetwork]:
    """Parse airodump-ng CSV output into WiFiNetwork list.

    Finds sections by header text (BSSID / Station MAC) instead of
    relying on blank-line splitting, which breaks across different
    OS line-ending variants.

    Args:
        skip_vendor: skip MAC vendor lookup (faster for intermediate updates).
    """
    networks: dict[str, WiFiNetwork] = {}
    client_map: dict[str, list[str]] = {}

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except FileNotFoundError:
        return []

    # Normalize line endings
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.splitlines()

    # Find section boundaries by header text
    ap_start = -1
    client_start = -1
    for i, line in enumerate(lines):
        stripped = line.strip().lstrip("\ufeff")  # strip BOM
        if ap_start < 0 and stripped.startswith("BSSID"):
            ap_start = i + 1  # data starts after header
        elif stripped.startswith("Station MAC"):
            client_start = i + 1

    # Parse APs section
    if ap_start >= 0:
        ap_end = client_start - 1 if client_start > ap_start else len(lines)
        for i in range(ap_start, ap_end):
            line = lines[i]
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 14:
                continue

            bssid = parts[0].upper()
            if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", bssid):
                continue

            try:
                channel = int(parts[3]) if parts[3].strip() else 0
            except ValueError:
                channel = 0

            speed = parts[4].strip()
            privacy = parts[5].strip()
            cipher = parts[6].strip()

            security = privacy
            if cipher:
                security += f" {cipher}"
            if security == "OPN":
                security = "Open"

            try:
                power = int(parts[8]) if parts[8].strip() else -100
            except ValueError:
                power = -100
            # Convert dBm to percentage (rough: -30 = 100%, -90 = 0%)
            signal = max(0, min(100, int((power + 90) * (100 / 60))))

            try:
                data = int(parts[10]) if parts[10].strip() else 0
            except ValueError:
                data = 0

            essid = parts[13].strip() if len(parts) > 13 else ""
            hidden = not essid

            frequency = "5 GHz" if channel > 14 else "2.4 GHz"
            vendor = "" if skip_vendor else _vendor_from_mac(bssid)

            networks[bssid] = WiFiNetwork(
                ssid=essid,
                bssid=bssid,
                signal=signal,
                frequency=frequency,
                channel=channel,
                security=security,
                router_vendor=vendor,
                hidden=hidden,
                data_packets=data,
                max_speed=speed,
            )
            client_map[bssid] = []

    # Parse Clients section
    if client_start >= 0:
        for i in range(client_start, len(lines)):
            line = lines[i]
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue

            station_mac = parts[0].upper()
            if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", station_mac):
                continue

            assoc_bssid = parts[5].upper()
            if assoc_bssid in client_map:
                client_map[assoc_bssid].append(station_mac)

    # Merge client counts into networks
    for bssid, net in networks.items():
        clients = client_map.get(bssid, [])
        net.clients_count = len(clients)
        net.clients = clients

    result = list(networks.values())
    result.sort(key=lambda n: n.signal, reverse=True)
    return result


# ═══════════════════════════════════════════════════════════════
# Connection Management
# ═══════════════════════════════════════════════════════════════

async def connect(adapter: str, ssid: str, password: str = "") -> tuple[bool, str]:
    """Connect to WiFi network. Returns (success, message)."""
    # Delete stale connection profiles for this SSID to avoid
    # "802-11-wireless-security.key-mgmt: property is missing" error
    await _run(["nmcli", "connection", "delete", "id", ssid], timeout=10)
    await asyncio.sleep(1)

    cmd = ["nmcli", "device", "wifi", "connect", ssid, "ifname", adapter]
    if password:
        cmd += ["password", password]

    stdout, stderr, rc = await _run(cmd, timeout=30)

    if rc == 0 and "successfully" in stdout.lower():
        return True, stdout.strip()

    # Fallback: create connection profile manually
    error_msg = stderr.strip() or stdout.strip() or ""
    if "key-mgmt" in error_msg or "property is missing" in error_msg:
        logger.info("Trying manual connection profile creation...")
        conn_name = f"netscanner-{ssid}"
        await _run(["nmcli", "connection", "delete", "id", conn_name], timeout=5)

        add_cmd = [
            "nmcli", "connection", "add",
            "type", "wifi",
            "ifname", adapter,
            "con-name", conn_name,
            "ssid", ssid,
        ]
        if password:
            add_cmd += [
                "wifi-sec.key-mgmt", "wpa-psk",
                "wifi-sec.psk", password,
            ]

        stdout2, stderr2, rc2 = await _run(add_cmd, timeout=15)
        if rc2 == 0:
            # Activate the connection
            stdout3, stderr3, rc3 = await _run(
                ["nmcli", "connection", "up", conn_name, "ifname", adapter],
                timeout=30,
            )
            if rc3 == 0:
                return True, stdout3.strip()
            else:
                return False, stderr3.strip() or stdout3.strip() or "Activation failed"
        else:
            return False, stderr2.strip() or stdout2.strip() or "Profile creation failed"

    return False, error_msg or "Unknown error"


async def disconnect(adapter: str) -> tuple[bool, str]:
    """Disconnect WiFi adapter."""
    stdout, stderr, rc = await _run(
        ["nmcli", "device", "disconnect", adapter], timeout=10
    )
    if rc == 0:
        return True, "Disconnected"
    return False, stderr.strip() or "Failed"


async def get_connection_info(adapter: str) -> ConnectionInfo:
    """Get current connection details after connecting."""
    info = ConnectionInfo(adapter=adapter)

    # Get connection name
    stdout, _, rc = await _run([
        "nmcli", "-t", "-f", "GENERAL.CONNECTION", "device", "show", adapter
    ])
    connection = ""
    if rc == 0:
        for line in stdout.splitlines():
            if "CONNECTION" in line:
                connection = line.split(":", 1)[-1].strip()
                info.ssid = connection

    # Get IP details
    stdout, _, rc = await _run([
        "nmcli", "-t", "-f",
        "IP4.ADDRESS,IP4.GATEWAY,IP4.DNS,GENERAL.CONNECTION",
        "device", "show", adapter
    ])
    if rc == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("IP4.ADDRESS"):
                addr = line.split(":", 1)[-1].strip()
                info.ip = addr.split("/")[0] if "/" in addr else addr
                # Calculate subnet CIDR
                if "/" in addr:
                    prefix = addr.split("/")[1]
                    parts = info.ip.split(".")
                    if len(parts) == 4:
                        import ipaddress
                        try:
                            net = ipaddress.IPv4Network(addr, strict=False)
                            info.subnet = str(net)
                        except Exception:
                            info.subnet = addr
            elif line.startswith("IP4.GATEWAY"):
                info.gateway = line.split(":", 1)[-1].strip()
            elif line.startswith("IP4.DNS"):
                dns = line.split(":", 1)[-1].strip()
                if dns:
                    info.dns.append(dns)

    # Get DHCP details
    if connection:
        stdout, _, rc = await _run([
            "nmcli", "-t", "connection", "show", connection
        ])
        if rc == 0:
            for line in stdout.splitlines():
                if "DHCP4.OPTION" in line and "dhcp-lease-time" in line:
                    m = re.search(r"dhcp-lease-time\s*=\s*(\d+)", line)
                    if m:
                        secs = int(m.group(1))
                        hours = secs // 3600
                        info.lease_time = f"{hours}h" if hours else f"{secs}s"
                elif "DHCP4.OPTION" in line and "dhcp-server-identifier" in line:
                    m = re.search(r"dhcp-server-identifier\s*=\s*([\d.]+)", line)
                    if m:
                        info.dhcp_server = m.group(1)

    return info


# ═══════════════════════════════════════════════════════════════
# Network Recon (after connection)
# ═══════════════════════════════════════════════════════════════

async def get_gateway_info(gateway_ip: str) -> GatewayInfo:
    """Get gateway/router details — MAC, vendor, open ports."""
    info = GatewayInfo(ip=gateway_ip)

    # Get gateway MAC from ARP
    stdout, _, rc = await _run(["arp", "-n", gateway_ip])
    if rc == 0:
        for line in stdout.splitlines():
            if gateway_ip in line:
                m = re.search(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", line)
                if m:
                    info.mac = m.group(1).upper()
                    info.vendor = _vendor_from_mac(info.mac)

    # Quick port scan of gateway (top 20 ports)
    stdout, _, rc = await _run([
        "nmap", "-F", "--top-ports", "20", "-T4", "-sT",
        gateway_ip, "--open", "-oG", "-"
    ], timeout=30)
    if rc == 0:
        for line in stdout.splitlines():
            if "Ports:" in line:
                ports_str = line.split("Ports:")[1].strip()
                for port_entry in ports_str.split(","):
                    port_entry = port_entry.strip()
                    parts = port_entry.split("/")
                    if len(parts) >= 5 and parts[1] == "open":
                        info.ports.append({
                            "port": int(parts[0]),
                            "service": parts[4] if len(parts) > 4 else "",
                        })

    return info


async def get_connected_clients(subnet: str) -> list[ConnectedClient]:
    """Discover clients on the network using arp-scan."""
    clients = []
    seen_macs = set()

    # Method 1: arp-scan
    stdout, _, rc = await _run(
        ["arp-scan", "--localnet", "--interface=auto", "-q"],
        timeout=30,
    )
    if rc != 0:
        # Try with subnet explicitly
        stdout, _, rc = await _run(
            ["arp-scan", subnet, "-q"],
            timeout=30,
        )

    if rc == 0:
        for line in stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip = parts[0].strip()
                mac = parts[1].strip().upper()
                if mac in seen_macs:
                    continue
                seen_macs.add(mac)
                vendor = parts[2].strip() if len(parts) > 2 else _vendor_from_mac(mac)
                clients.append(ConnectedClient(
                    ip=ip, mac=mac, vendor=vendor
                ))

    # Method 2 fallback: nmap ping scan
    if not clients:
        stdout, _, rc = await _run(
            ["nmap", "-sn", subnet, "-oG", "-"],
            timeout=60,
        )
        if rc == 0:
            for line in stdout.splitlines():
                m = re.search(r"Host:\s+([\d.]+)\s+\(([^)]*)\)", line)
                if m:
                    ip = m.group(1)
                    hostname = m.group(2) or ""
                    clients.append(ConnectedClient(
                        ip=ip, hostname=hostname
                    ))

    # Try to resolve hostnames
    for client in clients:
        if not client.hostname:
            stdout, _, rc = await _run(
                ["nmblookup", "-A", client.ip],
                timeout=5,
            )
            if rc == 0:
                for line in stdout.splitlines():
                    if "<00>" in line and "GROUP" not in line:
                        client.hostname = line.split()[0].strip()
                        break

    # Sort by IP
    clients.sort(key=lambda c: tuple(int(x) for x in c.ip.split(".") if x.isdigit()))
    return clients


async def check_internet_access() -> dict:
    """Check internet connectivity and get public IP."""
    result = {"online": False, "public_ip": "", "dns_ok": False}

    # Ping test
    _, _, rc = await _run(["ping", "-c", "1", "-W", "3", "8.8.8.8"], timeout=5)
    result["online"] = rc == 0

    # DNS test
    _, _, rc = await _run(
        ["nslookup", "google.com"], timeout=5
    )
    result["dns_ok"] = rc == 0

    # Public IP
    if result["online"]:
        stdout, _, rc = await _run(
            ["curl", "-s", "--max-time", "5", "https://ifconfig.me"],
            timeout=10,
        )
        if rc == 0 and stdout.strip():
            ip = stdout.strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                result["public_ip"] = ip

    return result


async def get_saved_networks() -> list[str]:
    """Get list of saved WiFi connections."""
    stdout, _, rc = await _run([
        "nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"
    ])
    saved = []
    if rc == 0:
        for line in stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and "wireless" in parts[1]:
                saved.append(parts[0])
    return saved
