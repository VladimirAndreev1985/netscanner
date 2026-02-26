"""Scan setup screen — target selection, scan mode, auto-detect."""

from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button, Input, RichLog
from textual.containers import Vertical, Horizontal
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
            f"[/]\n[#00aaff]  {t('app_subtitle')}[/]",
            id="header",
        )

        with Vertical(id="scan-container"):
            yield Static(f"[bold #00ff00]{t('target')}[/]", classes="section-title")
            with Horizontal():
                yield Input(placeholder=t("target_placeholder"), id="target-input")
                yield Button(t("auto_detect"), id="auto-detect-btn", variant="primary")

            yield Static("", id="subnet-info")

            yield Static(f"[bold #00ff00]{t('scan_mode')}[/]", classes="section-title")
            with Horizontal(id="scan-options"):
                yield Button(t("quick"), id="mode-quick", classes="scan-mode-btn")
                yield Button(t("normal"), id="mode-normal", classes="scan-mode-btn selected")
                yield Button(t("deep"), id="mode-deep", classes="scan-mode-btn")
                yield Button(t("auto_pwn"), id="mode-autopwn", classes="scan-mode-btn danger")

            yield Static("", id="mode-description")
            yield ScanProgress()
            yield Button(t("start_scan"), id="start-scan-btn", variant="success")

            yield Static(f"[bold #00ff00]{t('detected_subnets')}[/]", classes="section-title")
            yield RichLog(id="subnet-list", wrap=True, max_lines=50)

        yield Static(f" [#8b949e]{t('footer_scan')}[/]", id="footer")

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
        for btn in self.query(".scan-mode-btn"):
            btn.remove_class("selected")
        self.query_one(f"#mode-{mode}", Button).add_class("selected")
        self._scan_type = mode
        self._update_mode_description()

    def _update_mode_description(self) -> None:
        descriptions = {
            "quick": f"[#00aaff]{t('mode_quick_desc')}[/]",
            "normal": f"[#ffaa00]{t('mode_normal_desc')}[/]",
            "deep": f"[#ff6600]{t('mode_deep_desc')}[/]",
            "autopwn": f"[#ff0000]{t('mode_autopwn_desc')}[/]",
        }
        self.query_one("#mode-description", Static).update(
            descriptions.get(self._scan_type, "")
        )

    def _auto_detect(self) -> None:
        from core.net_utils import get_interfaces

        subnet_log = self.query_one("#subnet-list", RichLog)
        subnet_log.clear()
        subnet_log.write(f"[bold #00ff00]{t('detecting_interfaces')}[/]\n")

        try:
            interfaces = get_interfaces()
            self._subnets = []

            if not interfaces:
                subnet_log.write(f"[#ff4444]{t('no_interfaces')}[/]")
                return

            for iface in interfaces:
                subnet_log.write(
                    f"[#00aaff]{iface.name}[/]: "
                    f"[#d0d0d0]{iface.ip}[/] "
                    f"[#888]({iface.subnet})[/] "
                    f"[#666]GW: {iface.gateway or t('not_available')}[/] "
                    f"[#666]MAC: {iface.mac or t('not_available')}[/]"
                )
                if iface.subnet:
                    self._subnets.append(iface.subnet)

            subnet_log.write("")
            if self._subnets:
                subnet_log.write(
                    f"[bold #00ff00]{t('found_subnets', count=len(self._subnets))}[/]"
                )
                target_input = self.query_one("#target-input", Input)
                target_input.value = self._subnets[0]
                info = self.query_one("#subnet-info", Static)
                info.update(f"[#888]Available: {', '.join(self._subnets)}[/]")
        except Exception as e:
            subnet_log.write(f"[#ff4444]{t('error')}: {e}[/]")

    def _start_scan(self) -> None:
        target_input = self.query_one("#target-input", Input)
        target = target_input.value.strip()
        if not target:
            subnet_log = self.query_one("#subnet-list", RichLog)
            subnet_log.write(f"[#ff4444]{t('enter_target')}[/]")
            return
        if self._scan_type == "autopwn":
            self.post_message(self.AutoPwnRequested(target, "normal"))
        else:
            self.post_message(self.ScanRequested(target, self._scan_type))

    def set_progress(self, value: int, status: str = "") -> None:
        self.query_one(ScanProgress).update_progress(value, status)

    def scan_complete(self, count: int) -> None:
        self.query_one(ScanProgress).complete(t("scan_complete", count=count))
