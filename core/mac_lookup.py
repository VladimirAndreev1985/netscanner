"""MAC address vendor lookup."""

import json
import os

# Well-known camera/IoT OUI prefixes (first 3 bytes of MAC)
CAMERA_OUI = {
    # Hikvision
    "c0:56:e3": "Hikvision", "44:19:b6": "Hikvision", "54:c4:15": "Hikvision",
    "c4:2f:90": "Hikvision", "bc:ad:28": "Hikvision", "a4:14:37": "Hikvision",
    "18:68:cb": "Hikvision", "28:57:be": "Hikvision", "e0:50:8b": "Hikvision",
    "80:09:02": "Hikvision", "48:57:02": "Hikvision",
    # Dahua
    "3c:ef:8c": "Dahua", "a0:bd:1d": "Dahua", "e0:50:8b": "Dahua",
    "40:2c:76": "Dahua", "90:02:a9": "Dahua", "b8:a8:af": "Dahua",
    "00:12:34": "Dahua", "4c:11:bf": "Dahua",
    # Axis Communications
    "00:40:8c": "Axis", "ac:cc:8e": "Axis", "b8:a4:4f": "Axis",
    "00:1a:07": "Axis", "d8:a2:5e": "Axis",
    # Reolink
    "ec:71:db": "Reolink", "b4:6b:fc": "Reolink",
    # Foscam
    "c0:6d:1a": "Foscam", "00:62:6e": "Foscam",
    # Amcrest
    "9c:8e:cd": "Amcrest",
    # Ubiquiti
    "fc:ec:da": "Ubiquiti", "04:18:d6": "Ubiquiti", "44:d9:e7": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti", "dc:9f:db": "Ubiquiti", "80:2a:a8": "Ubiquiti",
    "24:5a:4c": "Ubiquiti", "68:72:51": "Ubiquiti", "74:83:c2": "Ubiquiti",
    # TP-Link
    "50:c7:bf": "TP-Link", "14:cc:20": "TP-Link", "60:32:b1": "TP-Link",
    "b0:95:75": "TP-Link", "a8:42:a1": "TP-Link", "c0:25:e9": "TP-Link",
    # D-Link
    "28:10:7b": "D-Link", "1c:7e:e5": "D-Link", "00:26:5a": "D-Link",
    "c8:be:19": "D-Link", "b8:a3:86": "D-Link",
    # Samsung (cameras)
    "00:16:6c": "Samsung", "00:1a:8a": "Samsung", "00:1e:e1": "Samsung",
    # Bosch
    "00:04:13": "Bosch", "00:07:5f": "Bosch",
    # Panasonic
    "00:80:45": "Panasonic", "70:5a:0f": "Panasonic", "00:b0:c7": "Panasonic",
    # Vivotek
    "00:02:d1": "Vivotek",
    # Honeywell
    "00:30:ab": "Honeywell",
    # GeoVision
    "00:13:e2": "GeoVision",
}

# Device type hints from OUI
IOT_OUI = {
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    # Espressif (ESP8266/ESP32)
    "24:6f:28": "Espressif", "ac:67:b2": "Espressif", "24:0a:c4": "Espressif",
    "30:ae:a4": "Espressif", "cc:50:e3": "Espressif", "a4:cf:12": "Espressif",
    # Sonoff/ITEAD
    "d8:f1:5b": "Sonoff/ITEAD",
    # Tuya
    "d8:1f:12": "Tuya",
    # Shelly
    "e8:db:84": "Shelly",
    # Amazon Echo
    "68:54:fd": "Amazon Echo", "fc:65:de": "Amazon Echo",
    # Google Home
    "f4:f5:d8": "Google Nest",
}


def lookup_vendor(mac: str) -> str:
    """Look up device vendor/manufacturer from MAC address."""
    if not mac:
        return ""
    mac_prefix = mac.lower().replace("-", ":").strip()[:8]

    # Check camera OUI first
    if mac_prefix in CAMERA_OUI:
        return CAMERA_OUI[mac_prefix]

    # Check IoT OUI
    if mac_prefix in IOT_OUI:
        return IOT_OUI[mac_prefix]

    # Try mac-vendor-lookup library
    try:
        from mac_vendor_lookup import MacLookup
        ml = MacLookup()
        return ml.lookup(mac)
    except Exception:
        pass

    return ""


def is_camera_vendor(mac: str) -> bool:
    """Check if MAC belongs to a known camera manufacturer."""
    if not mac:
        return False
    mac_prefix = mac.lower().replace("-", ":").strip()[:8]
    return mac_prefix in CAMERA_OUI


def is_iot_vendor(mac: str) -> bool:
    """Check if MAC belongs to a known IoT manufacturer."""
    if not mac:
        return False
    mac_prefix = mac.lower().replace("-", ":").strip()[:8]
    return mac_prefix in IOT_OUI


def get_brand_from_mac(mac: str) -> str:
    """Get specific brand name from MAC (for cameras)."""
    if not mac:
        return ""
    mac_prefix = mac.lower().replace("-", ":").strip()[:8]
    return CAMERA_OUI.get(mac_prefix, "")
