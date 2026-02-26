"""Device table widget for results display."""

from textual.widgets import DataTable
from textual.app import ComposeResult

from core.device import Device


class DeviceTable(DataTable):
    """Data table showing discovered devices."""

    COLUMNS = [
        ("IP", 16),
        ("MAC", 18),
        ("Vendor", 14),
        ("Type", 10),
        ("Brand", 12),
        ("Model", 14),
        ("Ports / Services", 28),
        ("Risk", 6),
        ("Status", 12),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        self._devices: list[Device] = []

    def on_mount(self) -> None:
        for col_name, _ in self.COLUMNS:
            self.add_column(col_name, key=col_name.lower())

    def load_devices(self, devices: list[Device]) -> None:
        """Load devices into the table."""
        self.clear()
        self._devices = devices

        for dev in sorted(devices, key=lambda d: d.risk_score, reverse=True):
            # Show port:service when service info is available (deep scan)
            if dev.services:
                port_parts = []
                for p in dev.open_ports[:5]:
                    svc = dev.services.get(p, {})
                    name = svc.get("name", "")
                    if name:
                        port_parts.append(f"{p}/{name}")
                    else:
                        port_parts.append(str(p))
                ports_str = ", ".join(port_parts)
                if len(dev.open_ports) > 5:
                    ports_str += f" (+{len(dev.open_ports) - 5})"
            else:
                ports_str = ", ".join(str(p) for p in dev.open_ports[:6])
                if len(dev.open_ports) > 6:
                    ports_str += f" (+{len(dev.open_ports) - 6})"

            risk_str = f"{dev.risk_score:.1f}"

            status_parts = []
            if dev.is_vulnerable:
                crit = sum(1 for v in dev.vulnerabilities if v.severity == "critical")
                if crit:
                    status_parts.append(f"{crit} CRIT")
                else:
                    status_parts.append(f"{len(dev.vulnerabilities)} CVE")
            if dev.has_default_creds:
                status_parts.append("CREDS")
            status = " | ".join(status_parts) if status_parts else "OK"

            self.add_row(
                dev.ip,
                dev.mac or "-",
                dev.vendor[:14] if dev.vendor else "-",
                dev.device_type,
                dev.brand or "-",
                dev.model[:14] if dev.model else "-",
                ports_str or "-",
                risk_str,
                status,
                key=dev.ip,
            )

    def filter_by_type(self, device_type: str) -> None:
        """Filter table to show only specific device type."""
        if device_type == "all":
            self.load_devices(self._devices)
        else:
            filtered = [d for d in self._devices if d.device_type == device_type]
            self.clear()
            self.load_devices(filtered)

    def get_selected_device(self) -> Device | None:
        """Get the currently selected device."""
        if self.cursor_row is not None and self.cursor_row < len(self._devices):
            row_key = self.get_row_at(self.cursor_row)
            # Find device by IP (row key)
            for dev in self._devices:
                if dev.ip == str(row_key):
                    return dev
        # Fallback: match by cursor position
        sorted_devs = sorted(self._devices, key=lambda d: d.risk_score, reverse=True)
        if self.cursor_row is not None and self.cursor_row < len(sorted_devs):
            return sorted_devs[self.cursor_row]
        return None
