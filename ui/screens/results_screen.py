"""Results screen — device table with filtering and sorting."""

from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button, DataTable
from textual.containers import Vertical, Horizontal
from textual.message import Message

from core.device import Device
from core.i18n import t
from ui.widgets.device_table import DeviceTable
from ui.widgets.filter_bar import FilterBar


class ResultsScreen(Screen):
    """Screen showing scan results with filtering."""

    class DeviceSelected(Message):
        """Emitted when a device is selected for detail view."""
        def __init__(self, device: Device) -> None:
            super().__init__()
            self.device = device

    class ExportRequested(Message):
        """Emitted when user requests export."""
        def __init__(self, format: str) -> None:
            super().__init__()
            self.format = format

    def __init__(self):
        super().__init__()
        self._devices: list[Device] = []
        self._active_filter = "all"

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #00ff41]\u25c6 NETSCANNER[/] [#1a3a1a]//[/] "
            "[#00d4ff]INTELLIGENCE REPORT[/]",
            id="header",
        )

        with Vertical(id="results-container"):
            yield FilterBar()
            yield DeviceTable(id="device-table")

            with Horizontal(id="stats-bar"):
                yield Static(f"{t('total')}: 0", id="stat-total", classes="stat-item stat-total")
                yield Static(f"{t('cameras')}: 0", id="stat-cameras", classes="stat-item stat-cameras")
                yield Static(f"{t('vulnerable')}: 0", id="stat-vuln", classes="stat-item stat-vulnerable")
                yield Static(f"{t('compromised')}: 0", id="stat-comp", classes="stat-item stat-compromised")

            with Horizontal():
                yield Button(t("export_html"), id="export-html", classes="action-btn")
                yield Button(t("export_pdf"), id="export-pdf", classes="action-btn")
                yield Button(t("export_json"), id="export-json", classes="action-btn")
                yield Button(t("back_to_scan"), id="back-btn", classes="action-btn")

        yield Static(
            f" [#3a4a3a]{t('footer_results')}[/]",
            id="footer",
        )

    def load_devices(self, devices: list[Device]) -> None:
        """Load scan results into the table."""
        self._devices = devices
        table = self.query_one(DeviceTable)
        self._apply_filter(self._active_filter)
        self._update_stats()

    def _apply_filter(self, filter_type: str) -> None:
        """Apply device type filter."""
        self._active_filter = filter_type
        table = self.query_one(DeviceTable)

        if filter_type == "all":
            filtered = self._devices
        elif filter_type == "vulnerable":
            filtered = [d for d in self._devices if d.is_vulnerable]
        elif filter_type == "compromised":
            filtered = [d for d in self._devices if d.has_default_creds]
        elif filter_type == "nvr":
            filtered = [d for d in self._devices if d.device_type in ("nvr", "dvr")]
        else:
            filtered = [d for d in self._devices if d.device_type == filter_type]

        table.load_devices(filtered)

    def _update_stats(self) -> None:
        """Update statistics bar."""
        total = len(self._devices)
        cameras = sum(1 for d in self._devices if d.is_camera)
        vulnerable = sum(1 for d in self._devices if d.is_vulnerable)
        compromised = sum(1 for d in self._devices if d.has_default_creds)

        self.query_one("#stat-total", Static).update(f"{t('total')}: {total}")
        self.query_one("#stat-cameras", Static).update(f"{t('cameras')}: {cameras}")
        self.query_one("#stat-vuln", Static).update(f"{t('vulnerable')}: {vulnerable}")
        self.query_one("#stat-comp", Static).update(f"{t('compromised')}: {compromised}")

    def on_filter_bar_filter_changed(self, event: FilterBar.FilterChanged) -> None:
        self._apply_filter(event.filter_type)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle device selection."""
        table = self.query_one(DeviceTable)
        device = table.get_selected_device()
        if device:
            self.post_message(self.DeviceSelected(device))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == "export-html":
            self.post_message(self.ExportRequested("html"))
        elif btn_id == "export-pdf":
            self.post_message(self.ExportRequested("pdf"))
        elif btn_id == "export-json":
            self.post_message(self.ExportRequested("json"))
        elif btn_id == "back-btn":
            self.app.switch_screen("scan")
