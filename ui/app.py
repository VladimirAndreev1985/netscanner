"""NetScanner TUI Application — main application with screen management."""

import asyncio
import logging
from pathlib import Path

from textual.app import App
from textual.binding import Binding

from core.device import Device
from ui.screens.scan_screen import ScanScreen
from ui.screens.results_screen import ResultsScreen
from ui.screens.device_screen import DeviceScreen
from ui.screens.autopwn_screen import AutoPwnScreen
from ui.screens.gallery_screen import GalleryScreen

logger = logging.getLogger("netscanner.app")

CSS_PATH = Path(__file__).parent / "styles.tcss"


class NetScannerApp(App):
    """NetScanner — Professional Network Scanner TUI."""

    TITLE = "NetScanner"
    SUB_TITLE = "Professional Network Scanner"
    CSS_PATH = CSS_PATH

    SCREENS = {
        "scan": ScanScreen,
        "results": ResultsScreen,
        "device": DeviceScreen,
        "autopwn": AutoPwnScreen,
        "gallery": GalleryScreen,
    }

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("f1", "help", "Help", show=True),
        Binding("1", "show_scan", "Scan", show=True),
        Binding("2", "show_results", "Results", show=True),
        Binding("3", "show_gallery", "Gallery", show=True),
        Binding("4", "show_autopwn", "Auto-Pwn", show=True),
    ]

    def __init__(self):
        super().__init__()
        self._devices: list[Device] = []
        self._scan_running = False

    def on_mount(self) -> None:
        """Show scan screen on startup."""
        self.push_screen("scan")

    # ═══ Screen switching ═══

    def action_show_scan(self) -> None:
        self.switch_screen("scan")

    def action_show_results(self) -> None:
        if self._devices:
            self.switch_screen("results")
            screen = self.query_one(ResultsScreen)
            screen.load_devices(self._devices)
        else:
            self.notify("No scan results yet. Run a scan first.", severity="warning")

    def action_show_gallery(self) -> None:
        if self._devices:
            self.switch_screen("gallery")
            screen = self.query_one(GalleryScreen)
            screen.load_cameras(self._devices)
        else:
            self.notify("No scan results yet.", severity="warning")

    def action_show_autopwn(self) -> None:
        self.switch_screen("autopwn")

    def action_help(self) -> None:
        self.notify(
            "NetScanner Help:\n"
            "1: Scan Screen | 2: Results | 3: Gallery | 4: Auto-Pwn\n"
            "Q: Quit | Enter: Select | Tab: Navigate",
            title="Help",
            timeout=10,
        )

    # ═══ Scan Screen Events ═══

    def on_scan_screen_scan_requested(self, event: ScanScreen.ScanRequested) -> None:
        """Handle scan request from scan screen."""
        if self._scan_running:
            self.notify("Scan already running!", severity="warning")
            return
        self._run_scan(event.target, event.scan_type)

    def on_scan_screen_auto_pwn_requested(self, event: ScanScreen.AutoPwnRequested) -> None:
        """Handle auto-pwn request from scan screen."""
        self.switch_screen("autopwn")
        screen = self.query_one(AutoPwnScreen)
        screen.set_target(event.target)
        self._run_autopwn(event.target, event.mode)

    # ═══ Results Screen Events ═══

    def on_results_screen_device_selected(self, event: ResultsScreen.DeviceSelected) -> None:
        """Handle device selection — switch to detail view."""
        self.switch_screen("device")
        screen = self.query_one(DeviceScreen)
        screen.load_device(event.device)

    def on_results_screen_export_requested(self, event: ResultsScreen.ExportRequested) -> None:
        """Handle export request."""
        self._export_report(event.format)

    # ═══ Device Screen Events ═══

    def on_device_screen_action_requested(self, event: DeviceScreen.ActionRequested) -> None:
        """Handle device action requests."""
        device = event.device
        action = event.action
        screen = self.query_one(DeviceScreen)

        if action == "deep_scan":
            self._deep_scan_device(device, screen)
        elif action == "check_creds":
            self._check_device_creds(device, screen)
        elif action == "grab_frame":
            self._grab_frame(device, screen)
        elif action == "exploit":
            self._exploit_device(device, screen)
        elif action == "find_poc":
            self._find_poc(device, screen)
        elif action == "shodan_lookup":
            self._shodan_lookup(device, screen)

    # ═══ Auto-Pwn Screen Events ═══

    def on_auto_pwn_screen_report_requested(self, event: AutoPwnScreen.ReportRequested) -> None:
        self._export_report(event.format)

    # ═══ Core Operations ═══

    def _run_scan(self, target: str, scan_type: str) -> None:
        """Run network scan in background."""
        self._scan_running = True

        async def do_scan():
            try:
                scan_screen = self.query_one(ScanScreen)
                scan_screen.set_progress(10, f"Scanning {target}...")

                from core.scanner import full_scan
                devices = await full_scan(target, scan_type)

                scan_screen.set_progress(50, "Fingerprinting devices...")
                from core.fingerprint import fingerprint_all
                devices = await fingerprint_all(devices)

                scan_screen.set_progress(70, "Checking vulnerabilities...")
                from core.vuln_checker import check_all_devices
                devices = check_all_devices(devices)

                if scan_type == "deep":
                    scan_screen.set_progress(80, "Analyzing cameras...")
                    from core.camera_analyzer import analyze_all_cameras
                    devices = await analyze_all_cameras(devices)

                    scan_screen.set_progress(90, "Checking credentials...")
                    from core.cred_checker import check_all_devices as check_creds
                    devices = await check_creds(devices)

                self._devices = devices
                scan_screen.scan_complete(len(devices))

                self.notify(
                    f"Scan complete! Found {len(devices)} devices.",
                    title="Scan Complete",
                    severity="information",
                )

                # Auto-switch to results
                self.switch_screen("results")
                results_screen = self.query_one(ResultsScreen)
                results_screen.load_devices(devices)

            except Exception as e:
                logger.error(f"Scan failed: {e}")
                self.notify(f"Scan failed: {e}", severity="error")
            finally:
                self._scan_running = False

        asyncio.create_task(do_scan())

    def _run_autopwn(self, target: str, mode: str) -> None:
        """Run auto-pwn in background."""
        self._scan_running = True

        async def do_autopwn():
            try:
                screen = self.query_one(AutoPwnScreen)

                def log_cb(msg: str):
                    self.call_from_thread(screen.log, msg)

                from core.auto_pwn import auto_pwn
                result = await auto_pwn(
                    target, mode=screen.mode,
                    log_callback=lambda msg: screen.log(msg),
                    progress_callback=lambda step, total, desc:
                        screen.log(f"[#00aaff]Step {step}/{total}: {desc}[/]"),
                )

                self._devices = result.devices
                screen.update_stats(
                    found=result.total_found,
                    cameras=result.cameras_found,
                    vulnerable=result.vulnerable,
                    compromised=result.compromised,
                )

                self.notify(
                    f"Auto-Pwn complete! "
                    f"{result.total_found} found, "
                    f"{result.vulnerable} vulnerable, "
                    f"{result.compromised} compromised.",
                    title="Auto-Pwn Complete",
                    severity="information",
                    timeout=15,
                )

            except Exception as e:
                logger.error(f"Auto-Pwn failed: {e}")
                screen.log(f"[bold #ff0000]Error: {e}[/]")
                self.notify(f"Auto-Pwn failed: {e}", severity="error")
            finally:
                self._scan_running = False

        asyncio.create_task(do_autopwn())

    def _deep_scan_device(self, device: Device, screen: DeviceScreen) -> None:
        """Deep scan a single device."""
        async def do_deep():
            screen.log_action("[#00aaff]Starting deep scan...[/]")
            try:
                from core.scanner import nmap_scan
                results = await nmap_scan(device.ip, scan_type="deep")
                if results:
                    dev = results[0]
                    device.open_ports = dev.open_ports
                    device.services = dev.services
                    device.os_guess = dev.os_guess or device.os_guess

                from core.fingerprint import fingerprint_device
                await fingerprint_device(device)

                from core.camera_analyzer import analyze_camera
                await analyze_camera(device)

                from core.vuln_checker import check_vulnerabilities
                check_vulnerabilities(device)

                screen.load_device(device)
                screen.log_action("[bold #00ff00]Deep scan complete![/]")
            except Exception as e:
                screen.log_action(f"[#ff0000]Error: {e}[/]")

        asyncio.create_task(do_deep())

    def _check_device_creds(self, device: Device, screen: DeviceScreen) -> None:
        """Check credentials for a device."""
        async def do_check():
            screen.log_action("[#00aaff]Checking default credentials...[/]")
            try:
                from core.cred_checker import check_credentials
                results = await check_credentials(device)
                screen.load_device(device)
                success = sum(1 for c in results if c.success)
                screen.log_action(
                    f"[bold #00ff00]Credential check complete! "
                    f"{success} successful logins found.[/]"
                )
            except Exception as e:
                screen.log_action(f"[#ff0000]Error: {e}[/]")

        asyncio.create_task(do_check())

    def _grab_frame(self, device: Device, screen: DeviceScreen) -> None:
        """Capture a frame from camera."""
        async def do_grab():
            screen.log_action("[#00aaff]Attempting to capture frame...[/]")
            try:
                from core.camera_analyzer import capture_snapshot
                path = await capture_snapshot(device)
                if path:
                    screen.log_action(f"[bold #00ff00]Frame saved to: {path}[/]")
                else:
                    screen.log_action("[#ffaa00]Could not capture frame.[/]")
                screen.load_device(device)
            except Exception as e:
                screen.log_action(f"[#ff0000]Error: {e}[/]")

        asyncio.create_task(do_grab())

    def _exploit_device(self, device: Device, screen: DeviceScreen) -> None:
        """Search and suggest MSF exploits for device."""
        async def do_exploit():
            screen.log_action("[#ff0000]Searching Metasploit modules...[/]")
            try:
                from core.msf_integration import msf_client, get_suggested_modules

                modules = get_suggested_modules(device)
                if modules:
                    screen.log_action(f"[bold #ffaa00]Found {len(modules)} MSF modules:[/]")
                    for mod in modules:
                        screen.log_action(
                            f"  [#00aaff]{mod['module']}[/] — {mod['description']}"
                        )
                    screen.log_action(
                        "\n[bold #ff0000]⚠ To run exploits, use msfconsole manually.[/]"
                        "\n[#888]MSF RPC integration requires msfrpcd running.[/]"
                    )
                else:
                    screen.log_action("[#888]No matching MSF modules found.[/]")

                # Also search by CVE in MSF
                if device.vulnerabilities and msf_client.is_running():
                    screen.log_action("\n[#00aaff]Searching by CVE in MSF...[/]")
                    found = msf_client.search_exploits(device)
                    if found:
                        for f in found:
                            screen.log_action(
                                f"  [#ff6600]{f['fullname']}[/] — {f['description'][:80]}"
                            )
            except Exception as e:
                screen.log_action(f"[#ff0000]Error: {e}[/]")

        asyncio.create_task(do_exploit())

    def _find_poc(self, device: Device, screen: DeviceScreen) -> None:
        """Find PoC exploits for device."""
        async def do_find():
            screen.log_action("[#00aaff]Searching for PoC exploits...[/]")
            try:
                from core.exploit_finder import find_exploits
                results = await find_exploits(device)
                if results:
                    screen.log_action(f"[bold #ffaa00]Found {len(results)} exploits:[/]")
                    for r in results:
                        stars = f" ★{r['stars']}" if r.get('stars') else ""
                        screen.log_action(
                            f"  [{r['source']}] [#00aaff]{r['name']}[/]{stars}\n"
                            f"    {r['url']}"
                        )
                else:
                    screen.log_action("[#888]No public exploits found.[/]")
            except Exception as e:
                screen.log_action(f"[#ff0000]Error: {e}[/]")

        asyncio.create_task(do_find())

    def _shodan_lookup(self, device: Device, screen: DeviceScreen) -> None:
        """Look up device on Shodan."""
        async def do_lookup():
            screen.log_action("[#00aaff]Querying Shodan...[/]")
            try:
                from core.external_apis import shodan_lookup
                result = await shodan_lookup(device.ip)
                if result:
                    if "message" in result:
                        screen.log_action(f"[#888]{result['message']}[/]")
                    else:
                        screen.log_action("[bold #00ff00]Shodan results:[/]")
                        screen.log_action(f"  Org: {result.get('org', 'N/A')}")
                        screen.log_action(f"  OS: {result.get('os', 'N/A')}")
                        screen.log_action(f"  Country: {result.get('country', 'N/A')}")
                        screen.log_action(f"  Ports: {result.get('ports', [])}")
                        vulns = result.get('vulns', [])
                        if vulns:
                            screen.log_action(f"  [#ff0000]Vulns: {', '.join(vulns[:10])}[/]")
                else:
                    screen.log_action(
                        "[#ffaa00]Shodan API key not configured. "
                        "Set it in data/api_keys.json[/]"
                    )
            except Exception as e:
                screen.log_action(f"[#ff0000]Error: {e}[/]")

        asyncio.create_task(do_lookup())

    def _export_report(self, format: str) -> None:
        """Export scan results."""
        if not self._devices:
            self.notify("No data to export.", severity="warning")
            return

        try:
            from core.report_generator import (
                generate_html_report, generate_pdf_report, generate_json_report
            )

            if format == "html":
                path = generate_html_report(self._devices)
            elif format == "pdf":
                path = generate_pdf_report(self._devices)
            else:
                path = generate_json_report(self._devices)

            self.notify(f"Report saved: {path}", title="Export Complete", timeout=10)
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")
