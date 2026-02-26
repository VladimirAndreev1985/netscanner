"""Device detail screen — full info, CVEs, credentials, actions."""

from textual.screen import Screen
from textual.app import ComposeResult
from textual.widgets import Static, Button, RichLog
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.message import Message

from core.device import Device


class DeviceScreen(Screen):
    """Detailed view for a single device."""

    class ActionRequested(Message):
        """Emitted when user requests an action on the device."""
        def __init__(self, device: Device, action: str) -> None:
            super().__init__()
            self.device = device
            self.action = action

    def __init__(self):
        super().__init__()
        self._device: Device | None = None

    def compose(self) -> ComposeResult:
        yield Static(
            "[bold #00ff00] Device Detail [/] │ "
            "[#8b949e]B[/] Back │ [#8b949e]D[/] Deep Scan │ [#8b949e]C[/] Check Creds",
            id="header",
        )

        with ScrollableContainer(id="detail-container"):
            yield Static("", id="device-info")
            yield Static("[bold #00ff00]Open Ports & Services[/]", classes="section-title")
            yield Static("", id="ports-info")
            yield Static("[bold #00ff00]Vulnerabilities[/]", classes="section-title")
            yield Static("", id="vuln-info")
            yield Static("[bold #00ff00]Credentials[/]", classes="section-title")
            yield Static("", id="creds-info")
            yield Static("[bold #00ff00]RTSP Streams[/]", classes="section-title")
            yield Static("", id="rtsp-info")
            yield Static("[bold #00ff00]ONVIF Info[/]", classes="section-title")
            yield Static("", id="onvif-info")
            yield Static("[bold #00ff00]Additional Info[/]", classes="section-title")
            yield Static("", id="extra-info")

            with Horizontal(id="action-buttons"):
                yield Button("Deep Scan", id="btn-deepscan", classes="action-btn")
                yield Button("Check Creds", id="btn-checkcreds", classes="action-btn")
                yield Button("Grab Frame", id="btn-grabframe", classes="action-btn")
                yield Button("Exploit (MSF)", id="btn-exploit", classes="action-btn danger")
                yield Button("Find PoC", id="btn-findpoc", classes="action-btn")
                yield Button("Shodan", id="btn-shodan", classes="action-btn")
                yield Button("Back", id="btn-back", classes="action-btn")

            yield RichLog(id="action-log", wrap=True, max_lines=100)

        yield Static(
            " [#8b949e]↑↓[/] Scroll │ [#8b949e]Enter[/] Action │ [#8b949e]B[/] Back",
            id="footer",
        )

    def load_device(self, device: Device) -> None:
        """Load device data into the screen."""
        self._device = device
        self._render_device_info()
        self._render_ports()
        self._render_vulns()
        self._render_creds()
        self._render_rtsp()
        self._render_onvif()
        self._render_extra()

    def _render_device_info(self) -> None:
        dev = self._device
        if not dev:
            return

        risk_color = {
            "critical": "#ff0000", "high": "#ff6600",
            "medium": "#ffaa00", "low": "#00aaff", "info": "#888888"
        }.get(dev.risk_level, "#888")

        info = (
            f"[bold #00ff00]IP:[/] {dev.ip}  "
            f"[bold #00ff00]MAC:[/] {dev.mac or 'N/A'}  "
            f"[bold #00ff00]Hostname:[/] {dev.hostname or 'N/A'}\n"
            f"[bold #00ff00]Vendor:[/] {dev.vendor or 'N/A'}  "
            f"[bold #00ff00]Brand:[/] {dev.brand or 'N/A'}  "
            f"[bold #00ff00]Model:[/] {dev.model or 'N/A'}\n"
            f"[bold #00ff00]Type:[/] {dev.device_type}  "
            f"[bold #00ff00]OS:[/] {dev.os_guess or 'N/A'}  "
            f"[bold #00ff00]Firmware:[/] {dev.firmware_version or 'N/A'}\n"
            f"[bold #00ff00]Risk Score:[/] [{risk_color}]{dev.risk_score:.1f}/10 "
            f"({dev.risk_level.upper()})[/]  "
            f"[bold #00ff00]Web:[/] {dev.web_interface or 'N/A'}"
        )
        self.query_one("#device-info", Static).update(info)

    def _render_ports(self) -> None:
        dev = self._device
        if not dev or not dev.open_ports:
            self.query_one("#ports-info", Static).update("[#888]No open ports[/]")
            return

        lines = []
        for port in dev.open_ports:
            svc = dev.services.get(port, {})
            name = svc.get("name", "")
            product = svc.get("product", "")
            version = svc.get("version", "")
            svc_str = f"{name} {product} {version}".strip()
            lines.append(f"  [#00aaff]{port:>5}[/]/tcp  {svc_str or 'unknown'}")

        self.query_one("#ports-info", Static).update("\n".join(lines))

    def _render_vulns(self) -> None:
        dev = self._device
        if not dev or not dev.vulnerabilities:
            self.query_one("#vuln-info", Static).update("[#888]No vulnerabilities found[/]")
            return

        lines = []
        for vuln in dev.vulnerabilities:
            color = {
                "critical": "#ff0000", "high": "#ff6600",
                "medium": "#ffaa00", "low": "#00aaff"
            }.get(vuln.severity, "#888")

            exploit_tag = " [bold #ff0000][EXPLOIT][/]" if vuln.exploit_available else ""
            lines.append(
                f"  [{color}]{vuln.cve_id}[/] — "
                f"CVSS [{color}]{vuln.cvss_score}[/] ({vuln.severity})"
                f"{exploit_tag}"
            )
            if vuln.description:
                desc = vuln.description[:120]
                lines.append(f"    [#888]{desc}[/]")

        self.query_one("#vuln-info", Static).update("\n".join(lines))

    def _render_creds(self) -> None:
        dev = self._device
        if not dev or not dev.default_creds:
            self.query_one("#creds-info", Static).update("[#888]No credentials tested[/]")
            return

        lines = []
        for cred in dev.default_creds:
            if cred.success:
                lines.append(
                    f"  [bold #ff0000]✓[/] [{cred.protocol}] "
                    f"[bold #ffaa00]{cred.username}[/]:[bold #ff4444]{cred.password}[/] "
                    f"[#888]{cred.url}[/]"
                )
            else:
                lines.append(
                    f"  [#666]✗ [{cred.protocol}] {cred.username}:{cred.password}[/]"
                )

        self.query_one("#creds-info", Static).update("\n".join(lines))

    def _render_rtsp(self) -> None:
        dev = self._device
        if not dev or not dev.rtsp_urls:
            self.query_one("#rtsp-info", Static).update("[#888]No RTSP streams found[/]")
            return

        lines = [f"  [#00aaff]{url}[/]" for url in dev.rtsp_urls]
        self.query_one("#rtsp-info", Static).update("\n".join(lines))

    def _render_onvif(self) -> None:
        dev = self._device
        if not dev or not dev.onvif_info:
            self.query_one("#onvif-info", Static).update("[#888]No ONVIF data[/]")
            return

        lines = []
        for key, value in dev.onvif_info.items():
            lines.append(f"  [#00ff00]{key}:[/] {value}")
        self.query_one("#onvif-info", Static).update("\n".join(lines))

    def _render_extra(self) -> None:
        dev = self._device
        if not dev or not dev.extra_info:
            self.query_one("#extra-info", Static).update("[#888]No additional info[/]")
            return

        lines = []
        for key, value in dev.extra_info.items():
            if isinstance(value, dict):
                lines.append(f"  [#00ff00]{key}:[/]")
                for k, v in value.items():
                    lines.append(f"    {k}: {v}")
            elif isinstance(value, list):
                lines.append(f"  [#00ff00]{key}:[/] ({len(value)} items)")
                for item in value[:5]:
                    if isinstance(item, dict):
                        lines.append(f"    {item.get('name', item)}")
                    else:
                        lines.append(f"    {item}")
            else:
                lines.append(f"  [#00ff00]{key}:[/] {value}")

        self.query_one("#extra-info", Static).update("\n".join(lines))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if not self._device:
            return

        action_map = {
            "btn-deepscan": "deep_scan",
            "btn-checkcreds": "check_creds",
            "btn-grabframe": "grab_frame",
            "btn-exploit": "exploit",
            "btn-findpoc": "find_poc",
            "btn-shodan": "shodan_lookup",
            "btn-back": "back",
        }

        action = action_map.get(btn_id, "")
        if action == "back":
            self.app.switch_screen("results")
        elif action:
            self.post_message(self.ActionRequested(self._device, action))

    def log_action(self, message: str) -> None:
        """Write to the action log."""
        try:
            log = self.query_one("#action-log", RichLog)
            log.write(message)
        except Exception:
            pass
