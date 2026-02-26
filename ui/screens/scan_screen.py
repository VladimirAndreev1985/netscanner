"""Scan setup screen — target selection, scan mode, auto-detect."""

from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button, Input, RadioSet, RadioButton, RichLog
from textual.containers import Vertical, Horizontal
from textual.message import Message

from ui.widgets.progress_bar import ScanProgress


class ScanScreen(Screen):
    """Main scan configuration and launch screen."""

    class ScanRequested(Message):
        """Emitted when user starts a scan."""
        def __init__(self, target: str, scan_type: str) -> None:
            super().__init__()
            self.target = target
            self.scan_type = scan_type

    class AutoPwnRequested(Message):
        """Emitted when user starts auto-pwn."""
        def __init__(self, target: str, mode: str) -> None:
            super().__init__()
            self.target = target
            self.mode = mode

    def __init__(self):
        super().__init__()
        self._scan_type = "normal"
        self._subnets: list[str] = []

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #00ff00]"
            "  _   _      _   ____                                  \n"
            " | \\| | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __ \n"
            " |  \\| |/ _ \\ __\\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|\n"
            " | |\\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |   \n"
            " |_| \\_|\\___|\\__|____/ \\___\\__,_|_| |_|_| |_|\\___|_|   \n"
            "[/]\n"
            "[#00aaff]  Professional Network Scanner for Kali Linux[/]",
            id="header",
        )

        with Vertical(id="scan-container"):
            yield Static("[bold #00ff00]Target[/]", classes="section-title")
            with Horizontal():
                yield Input(
                    placeholder="IP, subnet (192.168.1.0/24), or range",
                    id="target-input",
                )
                yield Button("Auto-Detect", id="auto-detect-btn", variant="primary")

            yield Static("", id="subnet-info")

            yield Static("[bold #00ff00]Scan Mode[/]", classes="section-title")
            with Horizontal(id="scan-options"):
                yield Button("Quick", id="mode-quick", classes="scan-mode-btn")
                yield Button("Normal", id="mode-normal", classes="scan-mode-btn selected")
                yield Button("Deep", id="mode-deep", classes="scan-mode-btn")
                yield Button("Auto-Pwn", id="mode-autopwn", classes="scan-mode-btn danger")

            yield Static("", id="mode-description")
            yield ScanProgress()
            yield Button("START SCAN", id="start-scan-btn", variant="success")

            yield Static("[bold #00ff00]Detected Subnets[/]", classes="section-title")
            yield RichLog(id="subnet-list", wrap=True, max_lines=50)

        yield Static(
            " [#8b949e]Tab[/]: Navigate | [#8b949e]Enter[/]: Select | "
            "[#8b949e]Q[/]: Quit | [#8b949e]F1[/]: Help",
            id="footer",
        )

    def on_mount(self) -> None:
        self._update_mode_description()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""

        if btn_id == "auto-detect-btn":
            self._auto_detect()
        elif btn_id == "start-scan-btn":
            self._start_scan()
        elif btn_id.startswith("mode-"):
            self._select_mode(btn_id.replace("mode-", ""))

    def _select_mode(self, mode: str) -> None:
        """Select scan mode."""
        for btn in self.query(".scan-mode-btn"):
            btn.remove_class("selected")

        mode_btn = self.query_one(f"#mode-{mode}", Button)
        mode_btn.add_class("selected")
        self._scan_type = mode
        self._update_mode_description()

    def _update_mode_description(self) -> None:
        """Update mode description text."""
        descriptions = {
            "quick": "[#00aaff]Quick:[/] ARP discovery + top 100 ports. Fast network overview.",
            "normal": "[#ffaa00]Normal:[/] ARP + targeted port scan + service detection + OS fingerprint.",
            "deep": "[#ff6600]Deep:[/] Full port scan + service versions + NSE scripts + fingerprinting.",
            "autopwn": "[#ff0000]Auto-Pwn:[/] Full automated pipeline: scan → fingerprint → CVE → "
                       "creds → exploit search → screenshots.",
        }
        desc = self.query_one("#mode-description", Static)
        desc.update(descriptions.get(self._scan_type, ""))

    def _auto_detect(self) -> None:
        """Auto-detect available subnets."""
        from core.net_utils import get_interfaces

        subnet_log = self.query_one("#subnet-list", RichLog)
        subnet_log.clear()
        subnet_log.write("[bold #00ff00]Detecting network interfaces...[/]\n")

        try:
            interfaces = get_interfaces()
            self._subnets = []

            if not interfaces:
                subnet_log.write("[#ff4444]No active interfaces found.[/]")
                return

            for iface in interfaces:
                subnet_log.write(
                    f"[#00aaff]{iface.name}[/]: "
                    f"[#d0d0d0]{iface.ip}[/] "
                    f"[#888]({iface.subnet})[/] "
                    f"[#666]GW: {iface.gateway or 'N/A'}[/] "
                    f"[#666]MAC: {iface.mac or 'N/A'}[/]"
                )
                if iface.subnet:
                    self._subnets.append(iface.subnet)

            subnet_log.write("")
            if self._subnets:
                subnet_log.write(f"[bold #00ff00]Found {len(self._subnets)} subnet(s)[/]")
                # Auto-fill first subnet into input
                target_input = self.query_one("#target-input", Input)
                target_input.value = self._subnets[0]

                info = self.query_one("#subnet-info", Static)
                subnets_str = ", ".join(self._subnets)
                info.update(f"[#888]Available: {subnets_str}[/]")
        except Exception as e:
            subnet_log.write(f"[#ff4444]Error: {e}[/]")

    def _start_scan(self) -> None:
        """Start the scan."""
        target_input = self.query_one("#target-input", Input)
        target = target_input.value.strip()

        if not target:
            subnet_log = self.query_one("#subnet-list", RichLog)
            subnet_log.write("[#ff4444]Please enter a target or use Auto-Detect[/]")
            return

        if self._scan_type == "autopwn":
            self.post_message(self.AutoPwnRequested(target, "normal"))
        else:
            self.post_message(self.ScanRequested(target, self._scan_type))

    def set_progress(self, value: int, status: str = "") -> None:
        """Update scan progress."""
        progress = self.query_one(ScanProgress)
        progress.update_progress(value, status)

    def scan_complete(self, count: int) -> None:
        """Mark scan as complete."""
        progress = self.query_one(ScanProgress)
        progress.complete(f"Scan complete! Found {count} devices")
