"""WiFi screen — adapter selection, network scanning, connection, recon."""

import asyncio
import logging
import time
from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button, Input, RichLog, DataTable
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.message import Message

from core.i18n import t
from ui.widgets.progress_bar import ScanProgress

logger = logging.getLogger("netscanner.wifi_screen")


class WiFiScreen(Screen):
    """WiFi management: scan, connect, recon."""

    class WiFiConnected(Message):
        def __init__(self, adapter: str, ssid: str, ip: str, subnet: str, gateway: str) -> None:
            super().__init__()
            self.adapter = adapter
            self.ssid = ssid
            self.ip = ip
            self.subnet = subnet
            self.gateway = gateway

    class ProceedToScan(Message):
        def __init__(self, subnet: str) -> None:
            super().__init__()
            self.subnet = subnet

    def __init__(self):
        super().__init__()
        self._adapters = []
        self._networks = []
        self._selected_adapter = ""
        self._selected_ssid = ""
        self._connection_info = None
        self._gateway_info = None
        self._clients = []
        self._internet_info = {}
        self._scanning = False
        self._quick_scan_cache: dict[str, object] = {}  # BSSID -> WiFiNetwork from quick scan
        self._known_networks: dict[str, object] = {}   # BSSID -> best known WiFiNetwork (across ticks)
        # Deep scan state (continuous monitor mode)
        self._mon_iface: str | None = None
        self._airodump_proc = None
        self._csv_path: str | None = None
        self._tmp_prefix: str | None = None
        self._scan_timer = None
        self._scan_start: float = 0

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #00ff41]\u25c6 NETSCANNER[/] [#1a3a1a]//[/] "
            "[#00d4ff]SIGNAL INTELLIGENCE[/]",
            id="header",
        )

        with ScrollableContainer(id="wifi-container"):
            # ═══ Adapter Section ═══
            yield Static(
                f"[bold #00ff41]{t('adapter').upper()}[/]",
                classes="section-title",
            )
            yield Static("", id="adapter-buttons")
            yield Static(
                f"[#888]{t('not_connected')}[/]",
                id="wifi-status",
            )

            # ═══ Available Networks ═══
            yield Static(
                f"[bold #00ff41]{t('available_networks').upper()}[/]",
                classes="section-title",
            )
            with Horizontal(id="wifi-scan-buttons"):
                yield Button(
                    t("quick_scan_wifi"), id="wifi-quick-scan",
                    variant="primary", classes="action-btn",
                )
                yield Button(
                    t("deep_scan_wifi"), id="wifi-deep-scan",
                    classes="action-btn",
                )
                yield Button("⟳", id="wifi-refresh", classes="action-btn")
                yield Button(
                    t("stop_scan"), id="wifi-stop-scan",
                    variant="error", classes="action-btn",
                )

            yield DataTable(id="wifi-networks")
            yield ScanProgress()

            # ═══ Connection ═══
            yield Static(
                f"[bold #00ff41]{t('connection_section').upper()}[/]",
                classes="section-title",
            )
            yield Static("", id="selected-network-label")
            with Horizontal(id="wifi-connect-row"):
                yield Input(
                    placeholder=t("enter_password"),
                    password=True,
                    id="wifi-password",
                )
                yield Button(
                    t("connect_btn"), id="wifi-connect",
                    variant="success", classes="action-btn",
                )
                yield Button(
                    t("disconnect_btn"), id="wifi-disconnect",
                    classes="action-btn",
                )

            # ═══ Network Recon ═══
            yield Static(
                f"[bold #00ff41]{t('network_recon').upper()}[/]",
                classes="section-title",
            )
            yield Static(
                f"[#888]{t('recon_after_connect')}[/]",
                id="recon-info",
            )
            yield RichLog(id="recon-log", wrap=True, max_lines=200, markup=True)

            # ═══ Proceed button ═══
            yield Button(
                t("proceed_to_scan"), id="wifi-proceed",
                variant="success", classes="action-btn",
            )

        yield Static(
            f" [#3a4a3a]{t('footer_wifi')}[/]",
            id="footer",
        )

    def on_mount(self) -> None:
        """Initialize WiFi screen."""
        table = self.query_one("#wifi-networks", DataTable)
        table.add_columns(
            t("network_ssid"),
            t("network_signal"),
            t("network_channel"),
            t("network_security"),
            t("network_wps"),
            t("network_clients"),
            t("network_packets"),
            t("network_router"),
            t("network_bssid"),
        )
        table.cursor_type = "row"

        # Hide stop button initially
        self.query_one("#wifi-stop-scan", Button).display = False

        # Auto-detect adapters
        asyncio.create_task(self._load_adapters())

    async def _load_adapters(self) -> None:
        """Detect WiFi adapters."""
        from core.wifi_manager import get_wifi_adapters

        self._adapters = await get_wifi_adapters()
        if not self._adapters:
            self.query_one("#adapter-buttons", Static).update(
                f"[#ff4444]{t('no_adapters')}[/]"
            )
            return

        # Display adapter buttons
        lines = []
        for adapter in self._adapters:
            mon = t("monitor_supported") if adapter.supports_monitor else t("monitor_not_supported")
            info = t("adapter_info", name=adapter.name, driver=adapter.driver or "?", monitor=mon)
            status_icon = "[bold #00ff41]●[/]" if adapter.state == "connected" else "[#888]○[/]"
            lines.append(f"  {status_icon} [bold #00d4ff]{info}[/]")
            if adapter.state == "connected" and adapter.current_ssid:
                lines.append(f"    └─ {adapter.current_ssid}")

        self.query_one("#adapter-buttons", Static).update("\n".join(lines))

        # Select first adapter
        self._selected_adapter = self._adapters[0].name

        # If already connected, show info
        for adapter in self._adapters:
            if adapter.state == "connected":
                self._selected_adapter = adapter.name
                asyncio.create_task(self._update_connection_status())
                break

    async def _update_connection_status(self) -> None:
        """Update connection status display."""
        from core.wifi_manager import get_connection_info

        info = await get_connection_info(self._selected_adapter)
        self._connection_info = info

        if info.ip:
            status = (
                f"[bold #00ff41]● {t('connected_to', ssid=info.ssid, ip=info.ip)}[/]\n"
                f"  [#888]GW: {info.gateway}[/]"
            )
            if info.dns:
                status += f" [#888]│ DNS: {', '.join(info.dns)}[/]"
            self.query_one("#wifi-status", Static).update(status)

            # Auto-run recon
            asyncio.create_task(self._run_recon())
        else:
            self.query_one("#wifi-status", Static).update(
                f"[#888]{t('not_connected')}[/]"
            )

    async def _refresh_all(self) -> None:
        """Reload adapters, then scan networks."""
        await self._load_adapters()
        if self._selected_adapter:
            await self._quick_scan()

    # ═══ Network Scanning ═══

    async def _quick_scan(self) -> None:
        """Quick WiFi scan using nmcli."""
        if self._scanning:
            return
        self._scanning = True

        progress = self.query_one(ScanProgress)
        progress.update_progress(30, t("scanning_wifi"))

        from core.wifi_manager import scan_networks
        self._networks = await scan_networks(self._selected_adapter)

        # Cache quick scan results (WPS, vendor) for merging with deep scan later
        self._quick_scan_cache = {n.bssid: n for n in self._networks}

        progress.update_progress(100, "")
        progress.complete("")
        self._populate_network_table()
        self._scanning = False

    async def _deep_scan(self) -> None:
        """Start continuous deep WiFi scan (monitor mode).

        Enters monitor mode, starts airodump-ng, and uses a Textual timer
        to periodically read the CSV and update the table in real-time.
        Scanning continues until user presses Stop.
        """
        if self._scanning:
            return
        self._scanning = True
        self._known_networks.clear()  # Fresh start for new scan

        log = self.query_one("#recon-log", RichLog)
        progress = self.query_one(ScanProgress)

        def log_cb(msg):
            try:
                log.write(f"[#00d4ff]{msg}[/]")
            except Exception:
                pass

        try:
            # Pre-scan for WPS/vendor data (nmcli — airodump CSV lacks WPS)
            if not self._quick_scan_cache:
                progress.update_progress(5, t("scanning_wifi"))
                log_cb("Quick pre-scan for WPS/vendor data...")
                from core.wifi_manager import scan_networks
                quick_results = await scan_networks(self._selected_adapter)
                self._quick_scan_cache = {n.bssid: n for n in quick_results}
                self._networks = quick_results
                self._populate_network_table()
                log_cb(f"Pre-scan: {len(quick_results)} networks cached")

            progress.update_progress(10, t("starting_monitor"))

            # Enter monitor mode
            from core.wifi_manager import enter_monitor_mode, start_airodump
            self._mon_iface = await enter_monitor_mode(
                self._selected_adapter, log_callback=log_cb
            )
            if not self._mon_iface:
                log_cb("[#ff0040]Failed to enter monitor mode[/]")
                self._scanning = False
                progress.complete("")
                return

            # Start airodump-ng (runs in background)
            result = await start_airodump(self._mon_iface, log_callback=log_cb)
            if not result:
                log_cb("[#ff0040]Failed to start airodump[/]")
                from core.wifi_manager import exit_monitor_mode
                await exit_monitor_mode(
                    self._mon_iface, self._selected_adapter, log_callback=log_cb
                )
                self._mon_iface = None
                self._scanning = False
                progress.complete("")
                return

            self._airodump_proc, self._csv_path, self._tmp_prefix = result

            # Show stop button (keep other buttons visible)
            self.query_one("#wifi-stop-scan", Button).display = True

            # Start periodic timer — reads CSV every 2 seconds
            self._scan_start = time.time()
            self._scan_timer = self.set_interval(2.0, self._on_scan_tick)

            progress.update_progress(50, "Monitor mode — scanning...")

        except Exception as e:
            log_cb(f"[#ff0040]Error: {e}[/]")
            progress.complete("")
            self._scanning = False

    def _on_scan_tick(self) -> None:
        """Periodic callback: read airodump CSV and update network table.

        Reads the file ONCE per tick to avoid race condition with airodump
        rewriting the CSV (which caused parser to see partial file without
        the client section, while a second read saw the complete file).
        Merges data across ticks to prevent SSID flickering.
        """
        if not self._csv_path:
            return
        try:
            # Read CSV file ONCE — avoid race condition with airodump rewrite
            try:
                with open(self._csv_path, "r", encoding="utf-8",
                          errors="replace") as _f:
                    raw_content = _f.read()
            except (OSError, FileNotFoundError):
                return

            if not raw_content or len(raw_content) < 20:
                return

            # Parse using the same content (no second read)
            from core.wifi_manager import _parse_airodump_csv
            networks = _parse_airodump_csv(
                skip_vendor=True, raw_content=raw_content
            )

            # Diagnostic from the SAME content
            has_station = "Station MAC" in raw_content
            diag_info = f"St={'Y' if has_station else 'N'}"

            if not networks:
                elapsed = int(time.time() - self._scan_start)
                self.query_one(ScanProgress).update_progress(
                    50, f"Monitor: {elapsed}s — waiting... ({diag_info})"
                )
                return

            # Merge with quick scan cache (WPS, vendor)
            for net in networks:
                cached = self._quick_scan_cache.get(net.bssid)
                if cached:
                    if cached.wps_enabled:
                        net.wps_enabled = True
                    if cached.router_vendor and not net.router_vendor:
                        net.router_vendor = cached.router_vendor

            # Merge across ticks — prevent SSID flickering and data loss
            for net in networks:
                prev = self._known_networks.get(net.bssid)
                if prev:
                    # Keep known SSID if current parse shows empty
                    if not net.ssid and prev.ssid:
                        net.ssid = prev.ssid
                        net.hidden = False
                    # Keep max observed values
                    if prev.clients_count > net.clients_count:
                        net.clients_count = prev.clients_count
                        net.clients = prev.clients
                    if prev.data_packets > net.data_packets:
                        net.data_packets = prev.data_packets
                self._known_networks[net.bssid] = net

            self._networks = networks
            self._populate_network_table()

            elapsed = int(time.time() - self._scan_start)
            total_clients = sum(n.clients_count for n in networks)
            self.query_one(ScanProgress).update_progress(
                50,
                f"Monitor: {elapsed}s — {len(networks)} nets, "
                f"{total_clients} clients ({diag_info})"
            )
        except Exception as exc:
            logger.error(f"scan_tick error: {exc}")

    async def _stop_deep_scan(self) -> None:
        """Stop continuous deep scan — exit monitor mode."""
        # Stop periodic timer
        if self._scan_timer:
            self._scan_timer.stop()
            self._scan_timer = None

        log = self.query_one("#recon-log", RichLog)

        def log_cb(msg):
            try:
                log.write(f"[#00d4ff]{msg}[/]")
            except Exception:
                pass

        try:
            # Stop airodump
            if self._airodump_proc:
                from core.wifi_manager import stop_airodump
                await stop_airodump(self._airodump_proc)
                self._airodump_proc = None

            # Save CSV copy for diagnostics before cleanup
            if self._csv_path:
                try:
                    import shutil
                    from pathlib import Path
                    logs_dir = Path(__file__).resolve().parent.parent.parent / "logs"
                    logs_dir.mkdir(exist_ok=True)
                    saved = logs_dir / "last_airodump.csv"
                    shutil.copy2(self._csv_path, saved)
                    log_cb(f"CSV saved to {saved}")
                except Exception as e:
                    log_cb(f"Could not save CSV: {e}")

            # Final parse WITH vendor lookup (airodump stopped, safe to read)
            if self._csv_path:
                from core.wifi_manager import _parse_airodump_csv
                final = _parse_airodump_csv(self._csv_path)
                if final:
                    for net in final:
                        cached = self._quick_scan_cache.get(net.bssid)
                        if cached:
                            if cached.wps_enabled:
                                net.wps_enabled = True
                            if cached.router_vendor and not net.router_vendor:
                                net.router_vendor = cached.router_vendor
                        # Merge with known data (preserve best SSID, max clients)
                        prev = self._known_networks.get(net.bssid)
                        if prev:
                            if not net.ssid and prev.ssid:
                                net.ssid = prev.ssid
                                net.hidden = False
                            if prev.clients_count > net.clients_count:
                                net.clients_count = prev.clients_count
                                net.clients = prev.clients
                    self._networks = final
                    self._populate_network_table()

            # Exit monitor mode
            if self._mon_iface:
                from core.wifi_manager import exit_monitor_mode
                await exit_monitor_mode(
                    self._mon_iface, self._selected_adapter, log_callback=log_cb
                )
                self._mon_iface = None

            # Cleanup temp files
            if self._tmp_prefix:
                from core.wifi_manager import cleanup_airodump_files
                cleanup_airodump_files(self._tmp_prefix)
                self._tmp_prefix = None

            self._csv_path = None
            self.query_one(ScanProgress).complete("")
            log_cb("Scan complete")

            # Update status — disconnected after monitor mode
            self.query_one("#wifi-status", Static).update(
                f"[#888]{t('not_connected')}[/]"
            )
            self._connection_info = None
            self.query_one("#recon-info", Static).update(
                f"[#888]{t('recon_after_connect')}[/]"
            )

        except Exception as e:
            log_cb(f"[#ff0040]Error stopping scan: {e}[/]")
        finally:
            self._scanning = False
            # Hide stop button
            self.query_one("#wifi-stop-scan", Button).display = False

    def _populate_network_table(self) -> None:
        """Fill network table with scan results."""
        table = self.query_one("#wifi-networks", DataTable)
        table.clear()

        for net in self._networks:
            # Signal bars
            bars = "█" * (net.signal // 20)
            bars_colored = f"[#00ff41]{bars}[/]" if net.signal > 60 else \
                f"[#ffaa00]{bars}[/]" if net.signal > 30 else \
                f"[#ff4444]{bars}[/]"
            signal_str = f"{bars_colored} {net.signal}%"

            # SSID
            ssid = net.ssid if net.ssid else t("hidden_network")
            if net.in_use:
                ssid = f"▶ {ssid}"

            # Security coloring
            sec = net.security
            if "WPA3" in sec:
                sec = f"[#00ff41]{sec}[/]"
            elif "WPA2" in sec or "WPA" in sec:
                sec = f"[#ffaa00]{sec}[/]"
            elif "WEP" in sec:
                sec = f"[#ff0000]{sec}[/]"
            elif sec == "Open" or sec == "":
                sec = f"[#ff0000]{t('open_warning')}[/]"

            # WPS
            wps = "[#ff4444]✓⚠[/]" if net.wps_enabled else "[#666]✗[/]"

            # Clients
            clients = str(net.clients_count) if net.clients_count else "[#666]—[/]"

            # Packets
            pkts = ""
            if net.data_packets:
                if net.data_packets > 1000:
                    pkts = f"{net.data_packets / 1000:.1f}k"
                else:
                    pkts = str(net.data_packets)
            else:
                pkts = "[#666]—[/]"

            # Router vendor
            router = net.router_vendor[:12] if net.router_vendor else "[#666]—[/]"

            # BSSID (shortened)
            bssid = net.bssid[:14] + ".." if len(net.bssid) > 14 else net.bssid

            table.add_row(
                ssid, signal_str, str(net.channel), sec,
                wps, clients, pkts, router, bssid,
                key=net.bssid,
            )

    # ═══ Connection ═══

    async def _connect_to_network(self) -> None:
        """Connect to selected WiFi network."""
        if not self._selected_ssid:
            return

        # If deep scan is running, stop it first (need managed mode to connect)
        if self._mon_iface:
            await self._stop_deep_scan()

        password = self.query_one("#wifi-password", Input).value
        log = self.query_one("#recon-log", RichLog)

        log.write(f"[#00d4ff]{t('connecting_to', ssid=self._selected_ssid)}[/]")

        from core.wifi_manager import connect
        success, message = await connect(
            self._selected_adapter,
            self._selected_ssid,
            password,
        )

        if success:
            log.write(f"[bold #00ff41]{t('connection_success', ssid=self._selected_ssid)}[/]")
            await self._update_connection_status()

            # Notify app
            if self._connection_info:
                self.post_message(self.WiFiConnected(
                    adapter=self._selected_adapter,
                    ssid=self._selected_ssid,
                    ip=self._connection_info.ip,
                    subnet=self._connection_info.subnet,
                    gateway=self._connection_info.gateway,
                ))
        else:
            log.write(f"[#ff4444]{t('connection_failed', error=message)}[/]")

    async def _disconnect_wifi(self) -> None:
        """Disconnect from current network."""
        from core.wifi_manager import disconnect

        success, msg = await disconnect(self._selected_adapter)
        log = self.query_one("#recon-log", RichLog)
        if success:
            log.write(f"[#888]{t('disconnected_ok')}[/]")
            self.query_one("#wifi-status", Static).update(
                f"[#888]{t('not_connected')}[/]"
            )
            self._connection_info = None
            self.query_one("#recon-info", Static).update(
                f"[#888]{t('recon_after_connect')}[/]"
            )
        else:
            log.write(f"[#ff4444]{msg}[/]")

    # ═══ Network Recon ═══

    async def _run_recon(self) -> None:
        """Run full network recon after connection."""
        if not self._connection_info or not self._connection_info.gateway:
            return

        log = self.query_one("#recon-log", RichLog)
        log.write(f"\n[bold #00ff41]{'═' * 50}[/]")
        log.write(f"[bold #00ff41]{t('recon_running')}[/]")

        from core.wifi_manager import (
            get_gateway_info, get_connected_clients,
            check_internet_access,
        )

        # 1. Gateway info
        log.write(f"[#00d4ff]{t('scanning_gateway')}[/]")
        self._gateway_info = await get_gateway_info(self._connection_info.gateway)
        gw = self._gateway_info

        gw_text = (
            f"[bold #00ff41]{t('router_info')}:[/] {gw.ip}"
            f" │ {gw.vendor or '?'}"
            f" │ {gw.mac or '?'}"
        )
        if gw.ports:
            ports_str = ", ".join(
                f"{p['port']}({p['service']})" for p in gw.ports
            )
            gw_text += f"\n  [bold #00ff41]{t('router_ports')}:[/] {ports_str}"

        # 2. Internet access
        log.write(f"[#00d4ff]{t('checking_internet')}[/]")
        self._internet_info = await check_internet_access()
        inet = self._internet_info

        inet_status = f"[#00ff41]{t('online')}[/]" if inet.get("online") else f"[#ff4444]{t('offline')}[/]"
        gw_text += f"\n  [bold #00ff41]{t('internet_access')}:[/] {inet_status}"
        if inet.get("public_ip"):
            gw_text += f" │ {t('public_ip')}: {inet['public_ip']}"

        # DHCP
        ci = self._connection_info
        if ci.dhcp_server or ci.lease_time:
            dhcp_str = ""
            if ci.dhcp_server:
                dhcp_str += ci.dhcp_server
            if ci.lease_time:
                dhcp_str += f" │ Lease: {ci.lease_time}"
            if ci.dns:
                dhcp_str += f" │ DNS: {', '.join(ci.dns)}"
            gw_text += f"\n  [bold #00ff41]{t('dhcp_info')}:[/] {dhcp_str}"

        self.query_one("#recon-info", Static).update(gw_text)

        # 3. Connected clients
        log.write(f"[#00d4ff]{t('discovering_clients')}[/]")
        self._clients = await get_connected_clients(ci.subnet or ci.gateway + "/24")

        if self._clients:
            log.write(f"\n[bold #00ff41]{t('clients_in_network', count=len(self._clients))}[/]")
            log.write(
                f"  [bold]{'IP':<16} {'MAC':<18} {'Vendor':<16} {'Hostname'}[/]"
            )
            log.write(f"  [#30363d]{'─' * 65}[/]")

            for client in self._clients:
                # Highlight cameras and IoT
                vendor = client.vendor or "—"
                vendor_color = "#888"
                camera_vendors = ["hikvision", "dahua", "axis", "foscam", "reolink",
                                  "amcrest", "vivotek", "hanwha", "uniview"]
                iot_vendors = ["raspberry", "esp", "tuya", "sonoff", "shelly"]

                for cv in camera_vendors:
                    if cv in vendor.lower():
                        vendor_color = "#ff6600"
                        vendor = f"📷 {vendor}"
                        break
                for iv in iot_vendors:
                    if iv in vendor.lower():
                        vendor_color = "#ffaa00"
                        vendor = f"🔌 {vendor}"
                        break

                log.write(
                    f"  {client.ip:<16} "
                    f"{client.mac:<18} "
                    f"[{vendor_color}]{vendor:<16}[/] "
                    f"{client.hostname or '—'}"
                )

        # Update status with client count
        status = self.query_one("#wifi-status", Static)
        status_text = (
            f"[bold #00ff41]● {t('connected_to', ssid=ci.ssid, ip=ci.ip)}[/]\n"
            f"  [#888]GW: {ci.gateway} ({gw.vendor or '?'})[/]"
        )
        if ci.dns:
            status_text += f" [#888]│ DNS: {', '.join(ci.dns)}[/]"
        status_text += f"\n  [#888]{t('internet_access')}: {inet_status}[/]"
        status_text += f" [#888]│ {t('network_clients')}: {len(self._clients)}[/]"
        status.update(status_text)

        log.write(f"\n[bold #00ff41]{t('recon_complete')}[/]")
        log.write(f"[#30363d]{'═' * 50}[/]")

    # ═══ Event Handlers ═══

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""

        if btn_id == "wifi-quick-scan":
            asyncio.create_task(self._quick_scan())
        elif btn_id == "wifi-deep-scan":
            asyncio.create_task(self._deep_scan())
        elif btn_id == "wifi-stop-scan":
            asyncio.create_task(self._stop_deep_scan())
        elif btn_id == "wifi-refresh":
            asyncio.create_task(self._refresh_all())
        elif btn_id == "wifi-connect":
            asyncio.create_task(self._connect_to_network())
        elif btn_id == "wifi-disconnect":
            asyncio.create_task(self._disconnect_wifi())
        elif btn_id == "wifi-proceed":
            subnet = ""
            if self._connection_info and self._connection_info.subnet:
                subnet = self._connection_info.subnet
            # Switch to scan screen directly
            self.app.switch_screen("scan")
            if subnet:
                self.app.call_after_refresh(
                    lambda: self._set_scan_target(subnet)
                )

    def _set_scan_target(self, subnet: str) -> None:
        """Set target on scan screen after switch."""
        try:
            from ui.screens.scan_screen import ScanScreen
            screen = self.app.screen
            if isinstance(screen, ScanScreen):
                screen.set_target(subnet)
        except Exception:
            pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle network selection from table."""
        if event.row_key and event.row_key.value:
            bssid = event.row_key.value
            for net in self._networks:
                if net.bssid == bssid:
                    self._selected_ssid = net.ssid or net.bssid
                    label = self.query_one("#selected-network-label", Static)
                    sec_info = f" [{net.security}]"
                    if net.wps_enabled:
                        sec_info += f" [#ff4444]{t('wps_warning')}[/]"
                    label.update(
                        f"[bold #00ff41]{t('selected_network')}:[/] "
                        f"[bold]{self._selected_ssid}[/]{sec_info}"
                    )

                    # If open network, clear password
                    if "Open" in net.security or not net.security:
                        self.query_one("#wifi-password", Input).value = ""
                    break
