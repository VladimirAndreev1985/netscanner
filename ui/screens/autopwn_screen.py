"""Auto-Pwn screen — automated penetration testing with live log."""

from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button, RichLog
from textual.containers import Vertical, Horizontal
from textual.message import Message

from core.i18n import t


class AutoPwnScreen(Screen):
    """Screen for running and monitoring auto-pwn operations."""

    class PwnStartRequested(Message):
        """Emitted when user starts auto-pwn."""
        def __init__(self, target: str, mode: str) -> None:
            super().__init__()
            self.target = target
            self.mode = mode

    class ReportRequested(Message):
        """Emitted when user requests report generation."""
        def __init__(self, format: str) -> None:
            super().__init__()
            self.format = format

    def __init__(self):
        super().__init__()
        self._mode = "normal"
        self._target = ""
        self._running = False

    def compose(self) -> ComposeResult:
        yield Static(
            f"[bold #00ff00] {t('autopwn_title')} [/] │ "
            f"[#ff0000]{t('autopwn_subtitle')}[/]",
            id="header",
        )

        with Vertical(id="autopwn-container"):
            yield Static(f"[bold #00ff00]{t('mode_selection')}[/]", classes="section-title")
            with Horizontal(id="pwn-mode-select"):
                yield Button(t("passive"), id="pwn-passive",
                             classes="mode-btn passive")
                yield Button(t("normal"), id="pwn-normal",
                             classes="mode-btn normal selected")
                yield Button(t("aggressive"), id="pwn-aggressive",
                             classes="mode-btn aggressive")

            yield Static("", id="pwn-mode-desc")

            with Horizontal(id="pwn-stats"):
                yield Static(f"{t('found')}: [bold]0[/]", id="pwn-found",
                             classes="stat-item stat-total")
                yield Static(f"{t('cameras')}: [bold]0[/]", id="pwn-cameras",
                             classes="stat-item stat-cameras")
                yield Static(f"{t('vulnerable')}: [bold]0[/]", id="pwn-vuln",
                             classes="stat-item stat-vulnerable")
                yield Static(f"{t('compromised')}: [bold]0[/]", id="pwn-comp",
                             classes="stat-item stat-compromised")

            yield RichLog(id="pwn-log", wrap=True, max_lines=500)

            with Horizontal():
                yield Button(t("generate_html"), id="gen-html",
                             classes="action-btn")
                yield Button(t("generate_pdf"), id="gen-pdf",
                             classes="action-btn")
                yield Button(t("view_results"), id="view-results",
                             classes="action-btn")
                yield Button(t("back"), id="pwn-back",
                             classes="action-btn")

        yield Static(
            f" [#8b949e]{t('autopwn_pipeline')}[/]",
            id="footer",
        )

    def on_mount(self) -> None:
        self._update_mode_desc()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""

        if btn_id.startswith("pwn-") and btn_id != "pwn-back":
            mode = btn_id.replace("pwn-", "")
            if mode in ("passive", "normal", "aggressive"):
                self._select_mode(mode)
        elif btn_id == "gen-html":
            self.post_message(self.ReportRequested("html"))
        elif btn_id == "gen-pdf":
            self.post_message(self.ReportRequested("pdf"))
        elif btn_id == "view-results":
            self.app.switch_screen("results")
        elif btn_id == "pwn-back":
            self.app.switch_screen("scan")

    def _select_mode(self, mode: str) -> None:
        for btn in self.query(".mode-btn"):
            btn.remove_class("selected")
        self.query_one(f"#pwn-{mode}", Button).add_class("selected")
        self._mode = mode
        self._update_mode_desc()

    def _update_mode_desc(self) -> None:
        descs = {
            "passive": f"[#00aaff]{t('mode_passive_desc')}[/]",
            "normal": f"[#ffaa00]{t('mode_normal_autopwn_desc')}[/]",
            "aggressive": f"[#ff0000]{t('mode_aggressive_desc')}[/]",
        }
        self.query_one("#pwn-mode-desc", Static).update(
            descs.get(self._mode, "")
        )

    @property
    def mode(self) -> str:
        return self._mode

    def set_target(self, target: str) -> None:
        self._target = target

    def log(self, message: str) -> None:
        """Add message to the live log."""
        try:
            log_widget = self.query_one("#pwn-log", RichLog)
            log_widget.write(message)
        except Exception:
            pass

    def update_stats(self, found: int = 0, cameras: int = 0,
                     vulnerable: int = 0, compromised: int = 0) -> None:
        """Update statistics display."""
        try:
            self.query_one("#pwn-found", Static).update(
                f"{t('found')}: [bold #00aaff]{found}[/]"
            )
            self.query_one("#pwn-cameras", Static).update(
                f"{t('cameras')}: [bold #ff6600]{cameras}[/]"
            )
            self.query_one("#pwn-vuln", Static).update(
                f"{t('vulnerable')}: [bold #ff0000]{vulnerable}[/]"
            )
            self.query_one("#pwn-comp", Static).update(
                f"{t('compromised')}: [bold #ff4444]{compromised}[/]"
            )
        except Exception:
            pass
