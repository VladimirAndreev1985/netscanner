"""External API integrations — Shodan, Censys, GreyNoise."""

import asyncio
import logging
import json
from pathlib import Path

import aiohttp

from core.device import Device

logger = logging.getLogger("netscanner.external_apis")

CONFIG_PATH = Path(__file__).parent.parent / "data" / "api_keys.json"


def load_api_keys() -> dict:
    """Load API keys from config file."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def save_api_key(service: str, key: str):
    """Save an API key."""
    keys = load_api_keys()
    keys[service] = key
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(keys, f, indent=2)


async def shodan_lookup(ip: str) -> dict | None:
    """Look up IP on Shodan."""
    keys = load_api_keys()
    api_key = keys.get("shodan", "")
    if not api_key:
        logger.debug("Shodan API key not configured")
        return None

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "ip": data.get("ip_str", ""),
                        "org": data.get("org", ""),
                        "os": data.get("os", ""),
                        "ports": data.get("ports", []),
                        "hostnames": data.get("hostnames", []),
                        "country": data.get("country_name", ""),
                        "city": data.get("city", ""),
                        "vulns": data.get("vulns", []),
                        "last_update": data.get("last_update", ""),
                        "banners": [
                            {
                                "port": s.get("port"),
                                "product": s.get("product", ""),
                                "version": s.get("version", ""),
                                "banner": s.get("data", "")[:200],
                            }
                            for s in data.get("data", [])[:5]
                        ],
                    }
                elif resp.status == 404:
                    return {"ip": ip, "message": "Not found in Shodan"}
    except Exception as e:
        logger.error(f"Shodan lookup failed for {ip}: {e}")
    return None


async def censys_lookup(ip: str) -> dict | None:
    """Look up IP on Censys."""
    keys = load_api_keys()
    api_id = keys.get("censys_id", "")
    api_secret = keys.get("censys_secret", "")
    if not api_id or not api_secret:
        logger.debug("Censys API keys not configured")
        return None

    try:
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        timeout = aiohttp.ClientTimeout(total=15)
        auth = aiohttp.BasicAuth(api_id, api_secret)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, auth=auth) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = data.get("result", {})
                    return {
                        "ip": ip,
                        "services": [
                            {
                                "port": s.get("port"),
                                "service_name": s.get("service_name", ""),
                                "transport_protocol": s.get("transport_protocol", ""),
                            }
                            for s in result.get("services", [])
                        ],
                        "os": result.get("operating_system", {}).get("product", ""),
                        "location": result.get("location", {}),
                        "autonomous_system": result.get("autonomous_system", {}),
                        "last_updated": result.get("last_updated_at", ""),
                    }
    except Exception as e:
        logger.error(f"Censys lookup failed for {ip}: {e}")
    return None


async def greynoise_lookup(ip: str) -> dict | None:
    """Check IP on GreyNoise (is it scanning/botnet?)."""
    keys = load_api_keys()
    api_key = keys.get("greynoise", "")

    # GreyNoise community API works without key for basic queries
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {}
        if api_key:
            headers["key"] = api_key
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "ip": ip,
                        "noise": data.get("noise", False),
                        "riot": data.get("riot", False),
                        "classification": data.get("classification", ""),
                        "name": data.get("name", ""),
                        "message": data.get("message", ""),
                        "last_seen": data.get("last_seen", ""),
                    }
    except Exception as e:
        logger.debug(f"GreyNoise lookup failed for {ip}: {e}")
    return None


async def enrich_device(device: Device) -> dict:
    """Enrich device with all available external API data."""
    results = {}

    tasks = {
        "shodan": shodan_lookup(device.ip),
        "censys": censys_lookup(device.ip),
        "greynoise": greynoise_lookup(device.ip),
    }

    for name, task in tasks.items():
        try:
            result = await task
            if result:
                results[name] = result
        except Exception as e:
            logger.debug(f"{name} enrichment failed: {e}")

    device.extra_info["external_apis"] = results
    return results
