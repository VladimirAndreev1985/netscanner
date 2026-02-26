"""Filter bar widget for device type filtering."""

from textual.widget import Widget
from textual.widgets import Button
from textual.containers import Horizontal
from textual.app import ComposeResult
from textual.message import Message

from core.i18n import t


class FilterBar(Horizontal):
    """Horizontal bar with filter buttons for device types."""

    class FilterChanged(Message):
        """Message sent when filter selection changes."""
        def __init__(self, filter_type: str) -> None:
            super().__init__()
            self.filter_type = filter_type

    # (i18n_key, filter_id)
    FILTER_KEYS = [
        ("all", "all"),
        ("cameras", "camera"),
        ("iot", "iot"),
        ("routers", "router"),
        ("pcs", "pc"),
        ("nvr_dvr", "nvr"),
        ("printers", "printer"),
        ("vulnerable", "vulnerable"),
        ("compromised", "compromised"),
    ]

    def __init__(self, **kwargs):
        super().__init__(id="filter-bar", **kwargs)
        self._active_filter = "all"

    def compose(self) -> ComposeResult:
        for i18n_key, filter_id in self.FILTER_KEYS:
            btn = Button(t(i18n_key), id=f"filter-{filter_id}", classes="filter-btn")
            if filter_id == "all":
                btn.add_class("active")
            yield btn

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if not btn_id.startswith("filter-"):
            return

        filter_type = btn_id.replace("filter-", "")

        # Update active state
        for btn in self.query("Button"):
            btn.remove_class("active")
        event.button.add_class("active")

        self._active_filter = filter_type
        self.post_message(self.FilterChanged(filter_type))

    @property
    def active_filter(self) -> str:
        return self._active_filter
