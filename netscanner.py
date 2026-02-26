#!/usr/bin/env python3
"""
NetScanner — Professional Network Scanner for Kali Linux
=========================================================
Discover, analyze, and pentest network devices (cameras, IoT, PCs).

Usage:
    sudo netscanner                         Launch TUI
    sudo netscanner --check-deps            Check dependencies
    sudo netscanner --update-cve            Update CVE database
    sudo netscanner --update                Update all (CVE + MSF)
    sudo netscanner --scan 192.168.1.0/24   Quick scan without TUI
    sudo netscanner --help                  Show help
"""

import argparse
import asyncio
import json
import logging
import os
import sys

# Add project root to path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)


BANNER = """
\033[92m
  _   _      _   ____
 | \\| | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
 |  \\| |/ _ \\ __\\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 | |\\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |
 |_| \\_|\\___|\\__|____/ \\___\\__,_|_| |_|_| |_|\\___|_|
\033[0m
\033[96m  Professional Network Scanner for Kali Linux\033[0m
\033[90m  v1.0.0\033[0m
"""


def check_root():
    """Check if running as root (required for raw sockets)."""
    if os.geteuid() != 0:
        print("\033[91m[!] NetScanner requires root privileges for network scanning.\033[0m")
        print("\033[93m    Run: sudo netscanner\033[0m")
        sys.exit(1)


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_check_deps():
    """Check and display dependency status."""
    print(BANNER)
    print("\033[92m[*] Checking dependencies...\033[0m\n")

    try:
        from core.dep_manager import print_status
        print_status()
    except ImportError as e:
        print(f"\033[91m[!] Cannot import dep_manager: {e}\033[0m")
        print("\033[93m    Run: pip install rich\033[0m")


def cmd_update_cve():
    """Update CVE database."""
    print(BANNER)
    print("\033[92m[*] Updating CVE database...\033[0m\n")

    try:
        from core.cve_updater import update_cve_database
        result = update_cve_database(
            progress_callback=lambda msg: print(f"  \033[96m{msg}\033[0m")
        )
        print(f"\n\033[92m[+] CVE update complete!\033[0m")
        print(f"    New CVEs: {result['new']}")
        print(f"    Total CVEs: {result['total']}")
    except Exception as e:
        print(f"\033[91m[!] CVE update failed: {e}\033[0m")


def cmd_update_all():
    """Update CVE database and Metasploit."""
    cmd_update_cve()

    print("\n\033[92m[*] Updating Metasploit database...\033[0m")
    import subprocess
    import shutil
    if shutil.which("msfdb"):
        try:
            subprocess.run(["msfdb", "init"], timeout=60, capture_output=True)
            print("\033[92m[+] msfdb initialized\033[0m")
        except Exception as e:
            print(f"\033[91m[!] msfdb failed: {e}\033[0m")

    if shutil.which("searchsploit"):
        try:
            print("\033[92m[*] Updating searchsploit...\033[0m")
            subprocess.run(["searchsploit", "-u"], timeout=120, capture_output=True)
            print("\033[92m[+] searchsploit updated\033[0m")
        except Exception as e:
            print(f"\033[91m[!] searchsploit update failed: {e}\033[0m")


def cmd_quick_scan(target: str):
    """Run a quick scan without TUI and print results."""
    print(BANNER)
    print(f"\033[92m[*] Quick scanning: {target}\033[0m\n")

    async def do_scan():
        from core.scanner import full_scan
        from core.fingerprint import fingerprint_all
        from core.vuln_checker import check_all_devices

        print("\033[96m  [1/3] Network discovery...\033[0m")
        devices = await full_scan(target, scan_type="quick")
        print(f"\033[92m  Found {len(devices)} hosts\033[0m")

        print("\033[96m  [2/3] Fingerprinting...\033[0m")
        devices = await fingerprint_all(devices)

        print("\033[96m  [3/3] CVE matching...\033[0m")
        devices = check_all_devices(devices)

        print(f"\n\033[92m{'═' * 70}\033[0m")
        print(f"\033[92m{'IP':<16} {'MAC':<18} {'Type':<10} {'Brand':<12} {'Risk':<6} {'Status'}\033[0m")
        print(f"\033[90m{'─' * 70}\033[0m")

        for dev in sorted(devices, key=lambda d: d.risk_score, reverse=True):
            # Color based on risk
            if dev.risk_score >= 9:
                color = "\033[91m"  # Red
            elif dev.risk_score >= 7:
                color = "\033[38;5;208m"  # Orange
            elif dev.risk_score >= 4:
                color = "\033[93m"  # Yellow
            else:
                color = "\033[92m"  # Green

            status = []
            if dev.is_vulnerable:
                status.append(f"{len(dev.vulnerabilities)} CVE")
            if dev.has_default_creds:
                status.append("CREDS!")
            status_str = " | ".join(status) if status else "OK"

            print(
                f"{color}"
                f"{dev.ip:<16} "
                f"{(dev.mac or '-'):<18} "
                f"{dev.device_type:<10} "
                f"{(dev.brand or '-'):<12} "
                f"{dev.risk_score:<6.1f} "
                f"{status_str}"
                f"\033[0m"
            )

        print(f"\033[92m{'═' * 70}\033[0m")
        print(f"\n\033[92mTotal: {len(devices)}\033[0m | "
              f"\033[93mCameras: {sum(1 for d in devices if d.is_camera)}\033[0m | "
              f"\033[91mVulnerable: {sum(1 for d in devices if d.is_vulnerable)}\033[0m | "
              f"\033[91mCompromised: {sum(1 for d in devices if d.has_default_creds)}\033[0m")

        # Save JSON report
        from core.report_generator import generate_json_report
        path = generate_json_report(devices)
        print(f"\n\033[96m[*] Results saved to: {path}\033[0m")

    asyncio.run(do_scan())


def cmd_launch_tui():
    """Launch the TUI application."""
    # Check for critical dependencies before launching TUI
    try:
        from core.dep_manager import get_missing_critical
        missing = get_missing_critical()
        if missing:
            print(f"\033[91m[!] Missing critical dependencies: {', '.join(missing)}\033[0m")
            print("\033[93m    Run: sudo bash install.sh\033[0m")
            sys.exit(1)
    except ImportError:
        pass

    # Check CVE database freshness
    try:
        from core.cve_updater import needs_update
        if needs_update(max_age_hours=168):  # 7 days
            print("\033[93m[*] CVE database is outdated. Consider: sudo netscanner --update-cve\033[0m")
    except ImportError:
        pass

    # Launch TUI
    from ui.app import NetScannerApp
    app = NetScannerApp()
    app.run()


def main():
    parser = argparse.ArgumentParser(
        description="NetScanner — Professional Network Scanner for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo netscanner                         Launch TUI interface
  sudo netscanner --scan 192.168.1.0/24   Quick CLI scan
  sudo netscanner --check-deps            Check installed tools
  sudo netscanner --update-cve            Update vulnerability database
  sudo netscanner --update                Update all databases
        """,
    )

    parser.add_argument("--check-deps", action="store_true",
                        help="Check and display dependency status")
    parser.add_argument("--update-cve", action="store_true",
                        help="Update CVE database from NVD")
    parser.add_argument("--update", action="store_true",
                        help="Update all databases (CVE + MSF + Exploit-DB)")
    parser.add_argument("--scan", metavar="TARGET",
                        help="Quick scan target (IP/subnet) without TUI")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.check_deps:
        cmd_check_deps()
    elif args.update_cve:
        check_root()
        cmd_update_cve()
    elif args.update:
        check_root()
        cmd_update_all()
    elif args.scan:
        check_root()
        cmd_quick_scan(args.scan)
    else:
        check_root()
        cmd_launch_tui()


if __name__ == "__main__":
    main()
