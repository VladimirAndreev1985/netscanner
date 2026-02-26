"""Scan setup screen — target acquisition, scan mode, abort, view intel."""

from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button, Input, RichLog, DataTable
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.message import Message

from core.i18n import t
from ui.widgets.progress_bar import ScanProgress


class ScanScreen(Screen):
    """Main scan configuration and launch screen."""

    class ScanRequested(Message):
        def __init__(self, target: str, scan_type: str) -> None:
            super().__init__()
            self.target = target
            self.scan_type = scan_type

    class AutoPwnRequested(Message):
        def __init__(self, target: str, mode: str) -> None:
            super().__init__()
            self.target = target
            self.mode = mode

    class RescanRequested(Message):
        def __init__(self, targets: str, scan_type: str) -> None:
            super().__init__()
            self.targets = targets
            self.scan_type = scan_type

    class ScanAbortRequested(Message):
        pass

    class ViewResultsRequested(Message):
        pass

    def __init__(self):
        super().__init__()
        self._scan_type = "normal"
        self._subnets: list[str] = []
        self._devices = []
        self._selected_ips: set[str] = set()
        self._all_selected = False

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #00ff41]\u25c6 NETSCANNER[/] [#1a3a1a]//[/] "
            "[#00d4ff]NETWORK RECONNAISSANCE[/]",
            id="header",
        )

        with ScrollableContainer(id="scan-container"):
            # ═══ Target Acquisition ═══
            yield Static(
                f"[bold #00ff41]{t('target')}[/]",
                classes="section-title",
            )
            with Horizontal(id="target-row"):
                yield Input(placeholder=t("target_placeholder"), id="target-input")
                yield Button(t("auto_detect"), id="auto-detect-btn", variant="primary")

            yield Static("", id="subnet-info")

            # ═══ Scan Mode ═══
            yield Static(
                f"[bold #00ff41]{t('scan_mode')}[/]",
                classes="section-title",
            )
            with Horizontal(id="scan-options"):
                yield Button(t("quick"), id="mode-quick", classes="scan-mode-btn")
                yield Button(t("normal"), id="mode-normal", classes="scan-mode-btn selected")
                yield Button(t("deep"), id="mode-deep", classes="scan-mode-btn")
                yield Button(t("auto_pwn"), id="mode-autopwn", classes="scan-mode-btn danger")

            yield Static("", id="mode-description")
            yield ScanProgress()

            # ═══ Action Buttons — compact row ═══
            with Horizontal(id="action-row"):
                yield Button(
                    t("execute_scan"), id="start-scan-btn", variant="success",
                )
                yield Button(
                    t("stop_scan"), id="stop-scan-btn", variant="error",
                    classes="hidden",
                )
                yield Button(
                    t("view_results"), id="view-results-btn",
                )
                yield Static(
                    f"[#3a4a3a]{t('status_standby')}[/]",
                    id="scan-status",
                )

            # ═══ Found Devices Section ═══
            with Vertical(id="found-section", classes="hidden"):
                yield Static("", id="found-count")
                with Horizontal(id="found-buttons"):
                    yield Button(
                        t("select_all"), id="select-all-btn",
                        classes="action-btn",
                    )
                    yield Button(
                        t("rescan_selected"), id="rescan-btn",
                        variant="success", classes="action-btn",
                    )
                    yield Static("", id="selected-info")
                yield DataTable(id="found-devices")

            yield Static(
                f"[bold #00ff41]{t('detected_subnets')}[/]",
                classes="section-title",
            )
            yield RichLog(id="subnet-list", wrap=True, max_lines=50, markup=True)

        yield Static(f" [#3a4a3a]{t('footer_scan')}[/]", id="footer")

    def on_mount(self) -> None:
        self._update_mode_description()
        table = self.query_one("#found-devices", DataTable)
        table.add_columns(
            t("col_select"), t("col_ip"), t("col_mac"),
            t("col_vendor"), t("col_ports"), t("col_type"), t("col_risk"),
        )
        table.cursor_type = "row"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == "auto-detect-btn":
            self._auto_detect()
        elif btn_id == "start-scan-btn":
            self._start_scan()
        elif btn_id == "stop-scan-btn":
            self.post_message(self.ScanAbortRequested())
        elif btn_id == "view-results-btn":
            self.post_message(self.ViewResultsRequested())
        elif btn_id == "select-all-btn":
            self._toggle_select_all()
        elif btn_id == "rescan-btn":
            self._rescan_selected()
        elif btn_id.startswith("mode-"):
            self._select_mode(btn_id.replace("mode-", ""))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Toggle device selection on row click."""
        table_id = event.data_table.id
        if table_id != "found-devices":
            return
        if not event.row_key or not event.row_key.value:
            return

        ip = event.row_key.value
        if ip in self._selected_ips:
            self._selected_ips.discard(ip)
        else:
            self._selected_ips.add(ip)
        self._refresh_found_table()

    def _select_mode(self, mode: str) -> None:
        for btn in self.query(".scan-mode-btn"):
            btn.remove_class("selected")
        self.query_one(f"#mode-{mode}", Button).add_class("selected")
        self._scan_type = mode
        self._update_mode_description()
        self._update_rescan_label()

    def _update_mode_description(self) -> None:
        descriptions = {
            "quick": f"[#00d4ff]{t('mode_quick_desc')}[/]",
            "normal": f"[#ff8800]{t('mode_normal_desc')}[/]",
            "deep": f"[#ff8800]{t('mode_deep_desc')}[/]",
            "autopwn": f"[#ff0040]{t('mode_autopwn_desc')}[/]",
        }
        self.query_one("#mode-description", Static).update(
            descriptions.get(self._scan_type, "")
        )

    def _auto_detect(self) -> None:
        from core.net_utils import get_interfaces

        subnet_log = self.query_one("#subnet-list", RichLog)
        subnet_log.clear()
        subnet_log.write(f"[bold #00ff41]{t('detecting_interfaces')}[/]\n")

        try:
            interfaces = get_interfaces()
            self._subnets = []

            if not interfaces:
                subnet_log.write(f"[#ff0040]{t('no_interfaces')}[/]")
                return

            for iface in interfaces:
                subnet_log.write(
                    f"[#00d4ff]{iface.name}[/]: "
                    f"[#b0b8c0]{iface.ip}[/] "
                    f"[#3a4a3a]({iface.subnet})[/] "
                    f"[#3a4a3a]GW: {iface.gateway or t('not_available')}[/] "
                    f"[#3a4a3a]MAC: {iface.mac or t('not_available')}[/]"
                )
                if iface.subnet:
                    self._subnets.append(iface.subnet)

            subnet_log.write("")
            if self._subnets:
                subnet_log.write(
                    f"[bold #00ff41]{t('found_subnets', count=len(self._subnets))}[/]"
                )
                target_input = self.query_one("#target-input", Input)
                target_input.value = self._subnets[0]
                info = self.query_one("#subnet-info", Static)
                info.update(f"[#3a4a3a]Available: {', '.join(self._subnets)}[/]")
        except Exception as e:
            subnet_log.write(f"[#ff0040]{t('error')}: {e}[/]")

    def _start_scan(self) -> None:
        target_input = self.query_one("#target-input", Input)
        target = target_input.value.strip()
        if not target:
            subnet_log = self.query_one("#subnet-list", RichLog)
            subnet_log.write(f"[#ff0040]{t('enter_target')}[/]")
            return
        if self._scan_type == "autopwn":
            self.post_message(self.AutoPwnRequested(target, "normal"))
        else:
            self.post_message(self.ScanRequested(target, self._scan_type))

    # ═══ Scan State UI ═══

    def show_scanning_state(self) -> None:
        """Show abort button, hide start button during scan."""
        self.query_one("#stop-scan-btn").remove_class("hidden")
        self.query_one("#scan-status", Static).update(
            f"[bold #ff8800]{t('status_scanning')}[/]"
        )

    def show_standby_state(self) -> None:
        """Show start button, hide abort button."""
        self.query_one("#stop-scan-btn").add_class("hidden")
        self.query_one("#scan-status", Static).update(
            f"[#3a4a3a]{t('status_standby')}[/]"
        )

    def show_aborted_state(self) -> None:
        """Show aborted status."""
        self.query_one("#stop-scan-btn").add_class("hidden")
        self.query_one("#scan-status", Static).update(
            f"[#ff0040]{t('scan_aborted')}[/]"
        )

    # ═══ Found Devices ═══

    def load_devices(self, devices) -> None:
        """Load found devices into the table (called from app after scan)."""
        self._devices = devices
        self._selected_ips = set()
        self._all_selected = False

        section = self.query_one("#found-section")
        if devices:
            section.remove_class("hidden")
            self.query_one("#found-count", Static).update(
                f"[bold #00ff41]{t('found_devices').upper()} ({len(devices)})[/]"
            )
        else:
            section.add_class("hidden")
            return

        self._refresh_found_table()
        self._update_rescan_label()

    def _refresh_found_table(self) -> None:
        """Refresh the found devices table with current selection state."""
        table = self.query_one("#found-devices", DataTable)
        table.clear()

        for dev in self._devices:
            ip = dev.ip
            check = "\u2611" if ip in self._selected_ips else "\u2610"

            mac = (dev.mac or "\u2014")[:17]
            vendor = (dev.vendor or "\u2014")[:14]
            ports = str(len(dev.open_ports)) if dev.open_ports else "0"
            dtype = (dev.device_type or "host")[:10]

            # Risk coloring
            risk = dev.risk_level if hasattr(dev, "risk_level") else "info"
            risk_colors = {
                "critical": "[#ff0040]CRIT[/]",
                "high": "[#ff8800]HIGH[/]",
                "medium": "[#ff8800]MED[/]",
                "low": "[#00d4ff]LOW[/]",
                "info": "[#3a4a3a]\u2014[/]",
            }
            risk_str = risk_colors.get(risk, "[#3a4a3a]\u2014[/]")

            table.add_row(check, ip, mac, vendor, ports, dtype, risk_str, key=ip)

        # Update selected count
        count = len(self._selected_ips)
        info = self.query_one("#selected-info", Static)
        if count:
            info.update(f"[#00ff41]{t('selected_count', count=count)}[/]")
        else:
            info.update("")

    def _toggle_select_all(self) -> None:
        """Toggle select/deselect all devices."""
        if self._all_selected:
            self._selected_ips.clear()
            self._all_selected = False
            self.query_one("#select-all-btn", Button).label = t("select_all")
        else:
            self._selected_ips = {dev.ip for dev in self._devices}
            self._all_selected = True
            self.query_one("#select-all-btn", Button).label = t("deselect_all")
        self._refresh_found_table()

    def _update_rescan_label(self) -> None:
        """Update rescan button label to show current scan mode."""
        try:
            mode = self._scan_type if self._scan_type != "autopwn" else "deep"
            mode_name = t(mode) if mode != "deep" else t("deep")
            btn = self.query_one("#rescan-btn", Button)
            btn.label = f"{t('rescan_selected')} [{mode_name}]"
        except Exception:
            pass

    def _rescan_selected(self) -> None:
        """Rescan selected devices."""
        if not self._selected_ips:
            # If nothing selected, select all
            self._selected_ips = {dev.ip for dev in self._devices}

        targets = ",".join(sorted(self._selected_ips))
        scan_type = self._scan_type if self._scan_type != "autopwn" else "deep"
        self.post_message(self.RescanRequested(targets, scan_type))

    # ═══ Public API ═══

    def set_target(self, target: str) -> None:
        """Pre-fill the target input (called from WiFi screen)."""
        try:
            target_input = self.query_one("#target-input", Input)
            target_input.value = target
            info = self.query_one("#subnet-info", Static)
            info.update(f"[#00ff41]WiFi \u2192 {target}[/]")
        except Exception:
            pass

    def set_progress(self, value: int, status: str = "") -> None:
        self.query_one(ScanProgress).update_progress(value, status)

    def scan_complete(self, count: int) -> None:
        self.query_one(ScanProgress).complete(t("scan_complete", count=count))
        self.show_standby_state()
