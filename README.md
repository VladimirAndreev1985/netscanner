# NetScanner

**Professional Network Scanner for Kali Linux** — discover, analyze, and pentest network devices with focus on IP cameras and IoT.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94)
![License](https://img.shields.io/badge/License-MIT-green)

```
  _   _      _   ____
 | \| | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
 |  \| |/ _ \ __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |
 |_| \_|\___|\__|____/ \___\__,_|_| |_|_| |_|\___|_|
```

## Features

### Network Discovery
- **ARP scanning** (scapy) — fast host discovery
- **Masscan** — ultra-fast scanning for large networks (/16, /8)
- **Nmap** — detailed port scanning, service detection, OS fingerprinting
- **Auto-detect** — automatic subnet and interface detection

### Device Fingerprinting
- Device type classification: cameras, IoT, routers, PCs, printers, NVR/DVR
- Brand identification via MAC OUI (Hikvision, Dahua, Axis, Reolink, 20+ vendors)
- HTTP header analysis, RTSP banner parsing, ONVIF discovery
- UPnP/SSDP enumeration, SNMP sysDescr matching
- Firmware version extraction

### Camera Deep Analysis
- **ONVIF enumeration** — profiles, PTZ, users, network config
- **RTSP stream discovery** — 200+ known paths per vendor
- **Snapshot capture** — via HTTP endpoints or ffmpeg/RTSP
- **Firmware extraction** — download attempts via known endpoints
- **Backdoor detection** — Hikvision magic string, Dahua config leak, and more
- **Cloud P2P check** — Hik-Connect, Dahua DMSS, Tuya

### Vulnerability Assessment
- **Auto-updating CVE database** from NVD API (20+ camera/IoT vendors)
- CVSS score prioritization (Critical → High → Medium → Low)
- Exploit availability check via Exploit-DB (searchsploit)
- Nmap NSE vulnerability scripts

### Credential Testing
- HTTP Basic/Digest/Form authentication
- RTSP authentication
- SSH and Telnet (paramiko)
- SNMP community string enumeration
- MQTT anonymous access check
- Default credentials database by vendor

### Metasploit Integration
- Auto-connect to msfrpcd (RPC)
- CVE → MSF module matching
- Suggested auxiliary modules per device
- Built-in camera modules: Hikvision RCE, RTSP login, SNMP enum, etc.

### Auto-Pwn Mode
Fully automated penetration testing pipeline:
1. Network discovery
2. Device fingerprinting
3. CVE matching with prioritization
4. Default credential testing
5. Backdoor detection
6. Exploit search (MSF + Exploit-DB + GitHub)
7. Camera screenshot capture
8. Report generation

Three modes: **Passive** / **Normal** / **Aggressive**

### Exploit Finder
- **GitHub** — PoC search by CVE ID
- **Exploit-DB** — searchsploit integration
- **PacketStorm** — CVE search

### External API Integration (optional)
- **Shodan** — internet-facing device info
- **Censys** — certificates and services
- **GreyNoise** — botnet/scanner IP check

### Reports
- **PDF** — executive summary with CVSS metrics
- **HTML** — interactive dark-themed report
- **JSON** — machine-readable export

### Professional TUI Interface
- Dark Kali-style theme with green accents
- 5 screens: Scan, Results, Device Detail, Auto-Pwn, Gallery
- Device filtering by type, brand, risk level
- Color-coded risk indicators
- Real-time scan progress

## Installation

```bash
# Clone or copy to Kali
git clone https://github.com/YOUR_USERNAME/netscanner.git /opt/netscanner

# Install
cd /opt/netscanner
sudo bash install.sh

# Run
sudo netscanner
```

### What install.sh does:
- Installs system packages: nmap, masscan, arp-scan, hydra, ffmpeg, metasploit-framework, etc.
- Creates Python virtual environment
- Installs pip dependencies
- Creates `/usr/local/bin/netscanner` launcher
- Initializes msfdb

## Usage

```bash
# Launch TUI interface
sudo netscanner

# Quick CLI scan (no TUI)
sudo netscanner --scan 192.168.1.0/24

# Check dependencies
sudo netscanner --check-deps

# Update CVE database
sudo netscanner --update-cve

# Update all (CVE + MSF + Exploit-DB)
sudo netscanner --update
```

### TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1` | Scan screen |
| `2` | Results screen |
| `3` | Camera gallery |
| `4` | Auto-Pwn screen |
| `Q` | Quit |
| `Enter` | Select/Confirm |
| `Tab` | Navigate |

## Project Structure

```
netscanner/
├── netscanner.py          # Entry point
├── install.sh             # Installer
├── requirements.txt       # Python dependencies
├── core/                  # Core modules
│   ├── scanner.py         # Network scanning (ARP, nmap, masscan)
│   ├── device.py          # Device data model
│   ├── net_utils.py       # Auto-detect subnets
│   ├── fingerprint.py     # Device fingerprinting
│   ├── mac_lookup.py      # MAC → vendor lookup
│   ├── camera_analyzer.py # Deep camera analysis
│   ├── vuln_checker.py    # CVE matching
│   ├── cve_updater.py     # CVE database updater
│   ├── cred_checker.py    # Default credential testing
│   ├── msf_integration.py # Metasploit integration
│   ├── auto_pwn.py        # Automated pentest pipeline
│   ├── exploit_finder.py  # PoC search
│   ├── report_generator.py# PDF/HTML/JSON reports
│   ├── external_apis.py   # Shodan/Censys/GreyNoise
│   └── dep_manager.py     # Dependency management
├── data/                  # Databases
│   ├── default_creds.json # Default passwords by vendor
│   ├── cve_db.json        # CVE database (auto-updated)
│   ├── rtsp_paths.json    # 200+ RTSP paths
│   ├── camera_backdoors.json # Known backdoors
│   └── snmp_communities.json # SNMP community strings
├── ui/                    # TUI interface
│   ├── app.py             # Main application
│   ├── styles.tcss        # Textual CSS styles
│   ├── screens/           # 5 screens
│   └── widgets/           # Custom widgets
└── reports/               # Generated reports
```

## Requirements

- **OS**: Kali Linux (or any Debian-based with security tools)
- **Python**: 3.10+
- **Root access**: Required for raw socket scanning

### System packages
nmap, masscan, arp-scan, ffmpeg, hydra, metasploit-framework, snmp, searchsploit

### Python packages
textual, rich, python-nmap, scapy, aiohttp, paramiko, requests, pymetasploit3, shodan, reportlab

## Disclaimer

**This tool is intended for authorized security testing and educational purposes only.** Always obtain proper authorization before scanning or testing any network or device. Unauthorized access to computer systems is illegal.

## License

MIT License — see [LICENSE](LICENSE)
