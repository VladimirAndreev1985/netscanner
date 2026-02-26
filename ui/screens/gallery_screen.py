"""Gallery screen — camera screenshot thumbnails."""

from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.message import Message

from core.device import Device
from core.i18n import t


class GalleryScreen(Screen):
    """Screen showing camera screenshots gallery."""

    class CameraSelected(Message):
        """Emitted when a camera is selected."""
        def __init__(self, device: Device) -> None:
            super().__init__()
            self.device = device

    def __init__(self):
        super().__init__()
        self._devices: list[Device] = []

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #00ff41]\u25c6 NETSCANNER[/] [#1a3a1a]//[/] "
            "[#00d4ff]VISUAL INTELLIGENCE[/]",
            id="header",
        )

        with ScrollableContainer(id="gallery-container"):
            yield Static("", id="gallery-content")

        with Horizontal():
            yield Button(t("capture_all"), id="capture-all", classes="action-btn")
            yield Button(t("back"), id="gallery-back", classes="action-btn")

        yield Static(
            f" [#3a4a3a]{t('footer_gallery')}[/]",
            id="footer",
        )

    def load_cameras(self, devices: list[Device]) -> None:
        """Load camera devices into the gallery."""
        self._devices = [d for d in devices if d.is_camera]
        self._render_gallery()

    def _render_gallery(self) -> None:
        """Render camera gallery as text-based cards."""
        if not self._devices:
            self.query_one("#gallery-content", Static).update(
                f"[#888]{t('no_cameras')}[/]"
            )
            return

        na = t("not_available")
        lines = []
        for i, dev in enumerate(self._devices):
            border = "═" * 60
            risk_color = {
                "critical": "#ff0000", "high": "#ff6600",
                "medium": "#ffaa00", "low": "#00d4ff", "info": "#3a4a3a"
            }.get(dev.risk_level, "#888")

            screenshot_indicator = (
                f"[bold #00ff41]◉ {t('frame_captured')}[/]" if dev.screenshots
                else f"[#888]○ {t('no_frame')}[/]"
            )

            creds_str = ""
            for c in dev.default_creds:
                if c.success:
                    creds_str = f"[#ff4444]{c.username}:{c.password}[/]"
                    break

            rtsp_str = ""
            if dev.rtsp_urls:
                rtsp_str = f"\n  [#00d4ff]RTSP:[/] {dev.rtsp_urls[0]}"
                if len(dev.rtsp_urls) > 1:
                    rtsp_str += f" (+{len(dev.rtsp_urls) - 1} more)"

            vuln_str = ""
            if dev.vulnerabilities:
                crit = sum(1 for v in dev.vulnerabilities if v.severity == "critical")
                if crit:
                    vuln_str = f"  [#ff0000]{crit} CRITICAL CVE[/]"
                else:
                    vuln_str = f"  [#ffaa00]{len(dev.vulnerabilities)} CVE[/]"

            card = (
                f"[#30363d]{border}[/]\n"
                f"  [bold #00ff41]Camera #{i+1}[/] — "
                f"[bold]{dev.ip}[/]  {screenshot_indicator}\n"
                f"  [#00ff41]Brand:[/] {dev.brand or 'Unknown'}  "
                f"[#00ff41]Model:[/] {dev.model or 'Unknown'}  "
                f"[#00ff41]FW:[/] {dev.firmware_version or na}\n"
                f"  [#00ff41]MAC:[/] {dev.mac or na}  "
                f"[#00ff41]Vendor:[/] {dev.vendor or na}\n"
                f"  [#00ff41]Risk:[/] [{risk_color}]{dev.risk_score:.1f}/10 "
                f"({dev.risk_level})[/]{vuln_str}\n"
                f"  [#00ff41]Web:[/] {dev.web_interface or na}"
                f"{rtsp_str}"
            )
            if creds_str:
                card += f"\n  [bold #ff0000]{t('default_creds_label')}:[/] {creds_str}"

            lines.append(card)

        lines.append(f"[#30363d]{'═' * 60}[/]")
        lines.append(f"\n[bold #00ff41]{t('total_cameras', count=len(self._devices))}[/]")

        self.query_one("#gallery-content", Static).update("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id == "gallery-back":
            self.app.switch_screen("results")
        elif btn_id == "capture-all":
            pass  # Handled by app
