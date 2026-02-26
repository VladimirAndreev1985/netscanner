"""Default credential checker — HTTP, RTSP, SSH, Telnet, SNMP, MQTT."""

import asyncio
import json
import logging
import socket
from pathlib import Path

import aiohttp

from core.device import Device, Credential

logger = logging.getLogger("netscanner.cred_checker")

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_creds_db() -> dict:
    path = DATA_DIR / "default_creds.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _load_snmp_communities() -> list[str]:
    path = DATA_DIR / "snmp_communities.json"
    if path.exists():
        with open(path) as f:
            data = json.load(f)
            return data.get("communities", [])
    return ["public", "private"]


def _get_creds_for_device(device: Device) -> list[dict]:
    """Get relevant default credentials for a device."""
    db = _load_creds_db()
    brand = device.brand.lower() if device.brand else ""
    dev_type = device.device_type.lower()

    creds = []
    # Brand-specific camera creds
    if brand and "cameras" in db:
        creds.extend(db["cameras"].get(brand, []))
    # Type-specific creds
    if dev_type in ("camera", "nvr", "dvr") and "cameras" in db:
        creds.extend(db["cameras"].get("generic", []))
    elif dev_type == "router" and "routers" in db:
        creds.extend(db["routers"].get("generic", []))
    elif dev_type == "iot" and "iot" in db:
        creds.extend(db["iot"].get("generic", []))
    else:
        # Try all generic creds
        for category in db.values():
            if isinstance(category, dict):
                creds.extend(category.get("generic", []))

    # Deduplicate
    seen = set()
    unique = []
    for c in creds:
        key = (c["username"], c["password"])
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


async def check_credentials(device: Device) -> list[Credential]:
    """Check all default credentials for a device."""
    creds_list = _get_creds_for_device(device)
    if not creds_list:
        return []

    results = []
    tasks = []

    # HTTP auth check
    http_ports = [p for p in (80, 8080, 443, 8443, 8000, 81, 85) if p in device.open_ports]
    if http_ports:
        tasks.append(_check_http(device, http_ports[0], creds_list))

    # RTSP auth check
    if 554 in device.open_ports:
        tasks.append(_check_rtsp(device, creds_list))

    # SSH auth check
    if 22 in device.open_ports:
        tasks.append(_check_ssh(device, creds_list))

    # Telnet auth check
    if 23 in device.open_ports:
        tasks.append(_check_telnet(device, creds_list))

    # SNMP check
    if 161 in device.open_ports:
        tasks.append(_check_snmp(device))

    # MQTT check
    if 1883 in device.open_ports:
        tasks.append(_check_mqtt(device))

    task_results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in task_results:
        if isinstance(result, list):
            results.extend(result)
        elif isinstance(result, Exception):
            logger.debug(f"Credential check failed: {result}")

    device.default_creds = results
    device.calculate_risk_score()
    return results


async def _check_http(device: Device, port: int,
                      creds: list[dict]) -> list[Credential]:
    """Check HTTP Basic/Digest authentication."""
    results = []
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{device.ip}:{port}/"

    # First check if auth is required
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    # No auth required
                    results.append(Credential(
                        protocol="http", username="", password="",
                        success=True, url=url
                    ))
                    return results
                elif resp.status not in (401, 403):
                    return results
    except Exception:
        return results

    # Try credentials
    for cred in creds:
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                auth = aiohttp.BasicAuth(cred["username"], cred["password"])
                async with session.get(url, auth=auth) as resp:
                    success = resp.status == 200
                    result = Credential(
                        protocol="http",
                        username=cred["username"],
                        password=cred["password"],
                        success=success,
                        url=url,
                    )
                    if success:
                        results.append(result)
                        return results  # First success is enough
        except Exception:
            continue

    return results


async def _check_rtsp(device: Device, creds: list[dict]) -> list[Credential]:
    """Check RTSP authentication."""
    results = []
    rtsp_url = f"rtsp://{device.ip}:554/"

    # First check if auth is required
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(device.ip, 554), timeout=5
        )
        request = f"DESCRIBE {rtsp_url} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=5)
        resp_text = response.decode(errors="ignore")
        writer.close()

        if "200 OK" in resp_text:
            results.append(Credential(
                protocol="rtsp", username="", password="",
                success=True, url=rtsp_url
            ))
            return results

        if "401" not in resp_text:
            return results
    except Exception:
        return results

    # Try credentials with RTSP Basic auth
    for cred in creds:
        try:
            import base64
            auth_str = base64.b64encode(
                f"{cred['username']}:{cred['password']}".encode()
            ).decode()

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(device.ip, 554), timeout=5
            )
            request = (
                f"DESCRIBE {rtsp_url} RTSP/1.0\r\n"
                f"CSeq: 2\r\n"
                f"Authorization: Basic {auth_str}\r\n"
                f"\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            resp_text = response.decode(errors="ignore")
            writer.close()

            if "200 OK" in resp_text:
                results.append(Credential(
                    protocol="rtsp",
                    username=cred["username"],
                    password=cred["password"],
                    success=True,
                    url=f"rtsp://{cred['username']}:{cred['password']}@{device.ip}:554/",
                ))
                return results
        except Exception:
            continue

    return results


async def _check_ssh(device: Device, creds: list[dict]) -> list[Credential]:
    """Check SSH authentication via paramiko."""
    results = []
    try:
        import paramiko
    except ImportError:
        return results

    loop = asyncio.get_event_loop()

    for cred in creds[:10]:  # Limit attempts to avoid lockout
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            def try_connect():
                client.connect(
                    device.ip, port=22,
                    username=cred["username"],
                    password=cred["password"],
                    timeout=5,
                    look_for_keys=False,
                    allow_agent=False,
                )
                client.close()
                return True

            success = await asyncio.wait_for(
                loop.run_in_executor(None, try_connect), timeout=8
            )

            if success:
                results.append(Credential(
                    protocol="ssh",
                    username=cred["username"],
                    password=cred["password"],
                    success=True,
                    url=f"ssh://{cred['username']}@{device.ip}",
                ))
                return results
        except Exception:
            continue

    return results


async def _check_telnet(device: Device, creds: list[dict]) -> list[Credential]:
    """Check Telnet authentication."""
    results = []

    for cred in creds[:5]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(device.ip, 23), timeout=5
            )

            # Read banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            banner_text = banner.decode(errors="ignore").lower()

            # Send username
            if "login" in banner_text or "username" in banner_text:
                writer.write(f"{cred['username']}\r\n".encode())
                await writer.drain()
                await asyncio.sleep(0.5)
                response = await asyncio.wait_for(reader.read(1024), timeout=3)
                resp_text = response.decode(errors="ignore").lower()

                # Send password
                if "password" in resp_text:
                    writer.write(f"{cred['password']}\r\n".encode())
                    await writer.drain()
                    await asyncio.sleep(1)
                    response = await asyncio.wait_for(reader.read(1024), timeout=3)
                    resp_text = response.decode(errors="ignore").lower()

                    # Check for success indicators
                    fail_indicators = ("incorrect", "failed", "denied", "invalid", "login")
                    success_indicators = ("#", "$", ">", "welcome", "connected")

                    if any(s in resp_text for s in success_indicators) and \
                       not any(f in resp_text for f in fail_indicators):
                        results.append(Credential(
                            protocol="telnet",
                            username=cred["username"],
                            password=cred["password"],
                            success=True,
                            url=f"telnet://{device.ip}",
                        ))
                        writer.close()
                        return results

            writer.close()
        except Exception:
            continue

    return results


async def _check_snmp(device: Device) -> list[Credential]:
    """Check SNMP community strings."""
    results = []
    communities = _load_snmp_communities()

    for community in communities:
        try:
            # Simple SNMP GET request for sysDescr (OID 1.3.6.1.2.1.1.1.0)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Build SNMPv1 GET request
            oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"  # sysDescr
            community_bytes = community.encode()

            # SNMP packet construction (simplified)
            varbind = b"\x30" + bytes([len(oid) + 4]) + \
                      b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
            varbindlist = b"\x30" + bytes([len(varbind)]) + varbind

            request_id = b"\x02\x01\x01"  # Integer 1
            error = b"\x02\x01\x00"       # Integer 0
            error_idx = b"\x02\x01\x00"   # Integer 0

            pdu_content = request_id + error + error_idx + varbindlist
            pdu = b"\xa0" + bytes([len(pdu_content)]) + pdu_content

            version = b"\x02\x01\x00"  # SNMPv1
            comm = b"\x04" + bytes([len(community_bytes)]) + community_bytes

            msg_content = version + comm + pdu
            message = b"\x30" + bytes([len(msg_content)]) + msg_content

            loop = asyncio.get_event_loop()

            def send_recv():
                sock.sendto(message, (device.ip, 161))
                data, _ = sock.recvfrom(4096)
                sock.close()
                return data

            data = await asyncio.wait_for(
                loop.run_in_executor(None, send_recv), timeout=3
            )

            if data and len(data) > 10:
                results.append(Credential(
                    protocol="snmp",
                    username=community,
                    password="",
                    success=True,
                    url=f"snmp://{device.ip} (community: {community})",
                ))
                if community == "private":
                    break  # private gives write access, found what we need

        except Exception:
            continue

    return results


async def _check_mqtt(device: Device) -> list[Credential]:
    """Check MQTT anonymous access."""
    results = []
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(device.ip, 1883), timeout=5
        )

        # MQTT CONNECT packet (anonymous)
        connect_packet = bytes([
            0x10,  # CONNECT
            0x0e,  # Remaining length
            0x00, 0x04,  # Protocol name length
            0x4d, 0x51, 0x54, 0x54,  # "MQTT"
            0x04,  # Protocol level (4 = MQTT 3.1.1)
            0x02,  # Connect flags (Clean session)
            0x00, 0x3c,  # Keep alive (60s)
            0x00, 0x02,  # Client ID length
            0x6e, 0x73,  # Client ID "ns"
        ])

        writer.write(connect_packet)
        await writer.drain()

        response = await asyncio.wait_for(reader.read(4), timeout=5)
        writer.close()

        if len(response) >= 4 and response[0] == 0x20:
            return_code = response[3]
            if return_code == 0:
                results.append(Credential(
                    protocol="mqtt",
                    username="anonymous",
                    password="",
                    success=True,
                    url=f"mqtt://{device.ip}:1883",
                ))

    except Exception:
        pass

    return results


async def check_all_devices(devices: list[Device],
                            callback=None) -> list[Device]:
    """Check credentials for all devices."""
    sem = asyncio.Semaphore(5)

    async def check_with_sem(dev):
        async with sem:
            await check_credentials(dev)

    tasks = [check_with_sem(dev) for dev in devices if dev.open_ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    if callback:
        callback(len(devices))

    return devices
