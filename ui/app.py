"""NetScanner TUI Application — main application with screen management."""

import asyncio
import logging
from pathlib import Path

from textual.app import App
from textual.binding import Binding

from core.device import Device
from core.i18n import t, load_language
from ui.screens.wifi_screen import WiFiScreen
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
        "wifi": WiFiScreen,
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
        Binding("5", "show_wifi", "WiFi", show=True),
    ]

    def __init__(self):
        super().__init__()
        load_language()
        self._devices: list[Device] = []
        self._scan_running = False
        self._scan_task: asyncio.Task | None = None

    def on_mount(self) -> None:
        """Show WiFi screen on startup."""
        self.push_screen("wifi")

    # ═══ Screen switching ═══

    def action_show_wifi(self) -> None:
        self.switch_screen("wifi")

    def action_show_scan(self) -> None:
        self.switch_screen("scan")

    def action_show_results(self) -> None:
        if self._devices:
            self.switch_screen("results")
            screen = self.screen
            if isinstance(screen, ResultsScreen):
                screen.load_devices(self._devices)
        else:
            self.notify(t("no_results"), severity="warning")

    def action_show_gallery(self) -> None:
        if self._devices:
            self.switch_screen("gallery")
            screen = self.screen
            if isinstance(screen, GalleryScreen):
                screen.load_cameras(self._devices)
        else:
            self.notify(t("no_results"), severity="warning")

    def action_show_autopwn(self) -> None:
        self.switch_screen("autopwn")

    def action_help(self) -> None:
        self.notify(
            t("help_text"),
            title=t("help"),
            timeout=10,
        )

    # ═══ WiFi Screen Events ═══

    def on_wifi_screen_wifi_connected(self, event: WiFiScreen.WiFiConnected) -> None:
        """Handle WiFi connection — store subnet info."""
        self.notify(
            t("connection_success", ssid=event.ssid),
            severity="information",
            timeout=5,
        )

    def on_wifi_screen_proceed_to_scan(self, event: WiFiScreen.ProceedToScan) -> None:
        """Switch to scan screen with pre-filled target (backup handler)."""
        subnet = event.subnet
        self.switch_screen("scan")
        if subnet:
            self.call_after_refresh(lambda: self._try_set_scan_target(subnet))

    def _try_set_scan_target(self, subnet: str) -> None:
        screen = self.screen
        if isinstance(screen, ScanScreen):
            screen.set_target(subnet)

    # ═══ Scan Screen Events ═══

    def on_scan_screen_scan_requested(self, event: ScanScreen.ScanRequested) -> None:
        """Handle scan request from scan screen."""
        if self._scan_running:
            self.notify(t("scan_already_running"), severity="warning")
            return
        self._run_scan(event.target, event.scan_type)

    def on_scan_screen_rescan_requested(self, event: ScanScreen.RescanRequested) -> None:
        """Handle rescan of selected devices."""
        if self._scan_running:
            self.notify(t("scan_already_running"), severity="warning")
            return
        self._run_scan(event.targets, event.scan_type)

    def on_scan_screen_scan_abort_requested(self, event: ScanScreen.ScanAbortRequested) -> None:
        """Handle scan abort request."""
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            self._scan_running = False
            screen = self.screen
            if isinstance(screen, ScanScreen):
                screen.show_aborted_state()
            self.notify(t("scan_aborted"), severity="warning")

    def on_scan_screen_view_results_requested(self, event: ScanScreen.ViewResultsRequested) -> None:
        """Handle view results request — switch to results without scanning."""
        self.action_show_results()

    def on_scan_screen_auto_pwn_requested(self, event: ScanScreen.AutoPwnRequested) -> None:
        """Handle auto-pwn request from scan screen."""
        self.switch_screen("autopwn")
        screen = self.screen
        if isinstance(screen, AutoPwnScreen):
            screen.set_target(event.target)
        self._run_autopwn(event.target, event.mode)

    # ═══ Results Screen Events ═══

    def on_results_screen_device_selected(self, event: ResultsScreen.DeviceSelected) -> None:
        """Handle device selection — switch to detail view."""
        self.switch_screen("device")
        screen = self.screen
        if isinstance(screen, DeviceScreen):
            screen.load_device(event.device)

    def on_results_screen_export_requested(self, event: ResultsScreen.ExportRequested) -> None:
        """Handle export request."""
        self._export_report(event.format)

    # ═══ Device Screen Events ═══

    def on_device_screen_action_requested(self, event: DeviceScreen.ActionRequested) -> None:
        """Handle device action requests."""
        device = event.device
        action = event.action
        screen = self.screen
        if not isinstance(screen, DeviceScreen):
            return

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

    def _pass_devices_to_scan_screen(self, devices) -> None:
        """Pass found devices to scan screen for targeted rescanning."""
        try:
            for s in self.screen_stack:
                if isinstance(s, ScanScreen):
                    s.load_devices(devices)
                    return
            # If scan screen is not in stack, try installed screens
            scan_screen = self.get_screen("scan")
            if isinstance(scan_screen, ScanScreen):
                scan_screen.load_devices(devices)
        except Exception:
            pass

    def _run_scan(self, target: str, scan_type: str) -> None:
        """Run network scan in background."""
        self._scan_running = True

        # Show scanning state on scan screen
        screen = self.screen
        if isinstance(screen, ScanScreen):
            screen.show_scanning_state()

        async def do_scan():
            try:
                screen = self.screen
                if isinstance(screen, ScanScreen):
                    screen.set_progress(10, t("scanning_target", target=target))

                from core.scanner import full_scan
                devices = await full_scan(target, scan_type)

                screen = self.screen
                if isinstance(screen, ScanScreen):
                    screen.set_progress(50, t("fingerprinting"))

                from core.fingerprint import fingerprint_all
                devices = await fingerprint_all(devices)

                screen = self.screen
                if isinstance(screen, ScanScreen):
                    screen.set_progress(70, t("checking_vulns"))

                from core.vuln_checker import check_all_devices
                devices = check_all_devices(devices)

                if scan_type == "deep":
                    screen = self.screen
                    if isinstance(screen, ScanScreen):
                        screen.set_progress(80, t("analyzing_cameras"))
                    from core.camera_analyzer import analyze_all_cameras
                    devices = await analyze_all_cameras(devices)

                    screen = self.screen
                    if isinstance(screen, ScanScreen):
                        screen.set_progress(90, t("checking_credentials"))
                    from core.cred_checker import check_all_devices as check_creds
                    devices = await check_creds(devices)

                self._devices = devices

                screen = self.screen
                if isinstance(screen, ScanScreen):
                    screen.scan_complete(len(devices))

                self.notify(
                    t("scan_complete", count=len(devices)),
                    title=t("scan_complete_title"),
                    severity="information",
                )

                # Save devices to scan screen for targeted rescan
                self._pass_devices_to_scan_screen(devices)

                # Auto-switch to results
                self.switch_screen("results")
                screen = self.screen
                if isinstance(screen, ResultsScreen):
                    screen.load_devices(devices)

            except asyncio.CancelledError:
                logger.info("Scan cancelled by user")
                # UI already updated by on_scan_screen_scan_abort_requested
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                try:
                    self.notify(f"{t('error')}: {e}", severity="error")
                    screen = self.screen
                    if isinstance(screen, ScanScreen):
                        screen.show_standby_state()
                except Exception:
                    pass
            finally:
                self._scan_running = False
                self._scan_task = None

        self._scan_task = asyncio.create_task(do_scan())

    def _run_autopwn(self, target: str, mode: str) -> None:
        """Run auto-pwn in background."""
        self._scan_running = True

        async def do_autopwn():
            try:
                screen = self.screen
                if not isinstance(screen, AutoPwnScreen):
                    return

                from core.auto_pwn import auto_pwn
                result = await auto_pwn(
                    target, mode=screen.mode,
                    log_callback=lambda msg: screen.write_log(msg),
                    progress_callback=lambda step, total, desc:
                        screen.write_log(f"[#00d4ff]Step {step}/{total}: {desc}[/]"),
                )

                self._devices = result.devices
                screen.update_stats(
                    found=result.total_found,
                    cameras=result.cameras_found,
                    vulnerable=result.vulnerable,
                    compromised=result.compromised,
                )

                self.notify(
                    t("autopwn_complete",
                      found=result.total_found,
                      vuln=result.vulnerable,
                      comp=result.compromised),
                    title=t("autopwn_complete_title"),
                    severity="information",
                    timeout=15,
                )

            except Exception as e:
                logger.error(f"Auto-Pwn failed: {e}")
                self.notify(f"{t('error')}: {e}", severity="error")
            finally:
                self._scan_running = False

        asyncio.create_task(do_autopwn())

    def _deep_scan_device(self, device: Device, screen: DeviceScreen) -> None:
        """Deep scan a single device."""
        async def do_deep():
            screen.log_action(f"[#00d4ff]{t('starting_deep_scan')}[/]")
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
                screen.log_action(f"[bold #00ff41]{t('deep_scan_complete')}[/]")
            except Exception as e:
                screen.log_action(f"[#ff0000]{t('error')}: {e}[/]")

        asyncio.create_task(do_deep())

    def _check_device_creds(self, device: Device, screen: DeviceScreen) -> None:
        """Check credentials for a device."""
        async def do_check():
            screen.log_action(f"[#00d4ff]{t('checking_creds')}[/]")
            try:
                from core.cred_checker import check_credentials
                results = await check_credentials(device)
                screen.load_device(device)
                success = sum(1 for c in results if c.success)
                screen.log_action(
                    f"[bold #00ff41]{t('cred_check_complete', count=success)}[/]"
                )
            except Exception as e:
                screen.log_action(f"[#ff0000]{t('error')}: {e}[/]")

        asyncio.create_task(do_check())

    def _grab_frame(self, device: Device, screen: DeviceScreen) -> None:
        """Capture a frame from camera."""
        async def do_grab():
            screen.log_action(f"[#00d4ff]{t('capturing_frame')}[/]")
            try:
                from core.camera_analyzer import capture_snapshot
                path = await capture_snapshot(device)
                if path:
                    screen.log_action(f"[bold #00ff41]{t('frame_saved', path=path)}[/]")
                else:
                    screen.log_action(f"[#ffaa00]{t('frame_failed')}[/]")
                screen.load_device(device)
            except Exception as e:
                screen.log_action(f"[#ff0000]{t('error')}: {e}[/]")

        asyncio.create_task(do_grab())

    def _exploit_device(self, device: Device, screen: DeviceScreen) -> None:
        """Search and suggest MSF exploits for device."""
        async def do_exploit():
            screen.log_action(f"[#ff0000]{t('searching_msf')}[/]")
            try:
                from core.msf_integration import msf_client, get_suggested_modules

                modules = get_suggested_modules(device)
                if modules:
                    screen.log_action(
                        f"[bold #ffaa00]{t('found_msf_modules', count=len(modules))}[/]"
                    )
                    for mod in modules:
                        screen.log_action(
                            f"  [#00d4ff]{mod['module']}[/] — {mod['description']}"
                        )
                    screen.log_action(
                        f"\n[bold #ff0000]⚠ {t('msf_manual_note')}[/]"
                        f"\n[#888]MSF RPC integration requires msfrpcd running.[/]"
                    )
                else:
                    screen.log_action(f"[#888]{t('no_msf_modules')}[/]")

                # Also search by CVE in MSF
                if device.vulnerabilities and msf_client.is_running():
                    screen.log_action(f"\n[#00d4ff]{t('searching_msf')}[/]")
                    found = msf_client.search_exploits(device)
                    if found:
                        for f in found:
                            screen.log_action(
                                f"  [#ff6600]{f['fullname']}[/] — {f['description'][:80]}"
                            )
            except Exception as e:
                screen.log_action(f"[#ff0000]{t('error')}: {e}[/]")

        asyncio.create_task(do_exploit())

    def _find_poc(self, device: Device, screen: DeviceScreen) -> None:
        """Find PoC exploits for device."""
        async def do_find():
            screen.log_action(f"[#00d4ff]{t('searching_poc')}[/]")
            try:
                from core.exploit_finder import find_exploits
                results = await find_exploits(device)
                if results:
                    screen.log_action(
                        f"[bold #ffaa00]{t('found_exploits', count=len(results))}[/]"
                    )
                    for r in results:
                        stars = f" ★{r['stars']}" if r.get('stars') else ""
                        screen.log_action(
                            f"  [{r['source']}] [#00d4ff]{r['name']}[/]{stars}\n"
                            f"    {r['url']}"
                        )
                else:
                    screen.log_action(f"[#888]{t('no_exploits')}[/]")
            except Exception as e:
                screen.log_action(f"[#ff0000]{t('error')}: {e}[/]")

        asyncio.create_task(do_find())

    def _shodan_lookup(self, device: Device, screen: DeviceScreen) -> None:
        """Look up device on Shodan."""
        async def do_lookup():
            screen.log_action(f"[#00d4ff]{t('querying_shodan')}[/]")
            try:
                from core.external_apis import shodan_lookup
                result = await shodan_lookup(device.ip)
                if result:
                    if "message" in result:
                        screen.log_action(f"[#888]{result['message']}[/]")
                    else:
                        screen.log_action(f"[bold #00ff41]{t('shodan_results')}[/]")
                        screen.log_action(f"  Org: {result.get('org', 'N/A')}")
                        screen.log_action(f"  OS: {result.get('os', 'N/A')}")
                        screen.log_action(f"  Country: {result.get('country', 'N/A')}")
                        screen.log_action(f"  Ports: {result.get('ports', [])}")
                        vulns = result.get('vulns', [])
                        if vulns:
                            screen.log_action(f"  [#ff0000]Vulns: {', '.join(vulns[:10])}[/]")
                else:
                    screen.log_action(f"[#ffaa00]{t('shodan_no_key')}[/]")
            except Exception as e:
                screen.log_action(f"[#ff0000]{t('error')}: {e}[/]")

        asyncio.create_task(do_lookup())

    def _export_report(self, format: str) -> None:
        """Export scan results."""
        if not self._devices:
            self.notify(t("no_data_export"), severity="warning")
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

            self.notify(
                t("export_complete", path=path),
                title=t("export_complete_title"),
                timeout=10,
            )
        except Exception as e:
            self.notify(t("export_failed", error=str(e)), severity="error")
