"""Scan progress widget."""

from textual.widgets import ProgressBar, Static
from textual.containers import Vertical
from textual.app import ComposeResult


class ScanProgress(Vertical):
    """Progress bar with status text for scan operations."""

    def __init__(self, **kwargs):
        super().__init__(id="scan-progress", **kwargs)

    def compose(self) -> ComposeResult:
        yield Static("Ready", id="progress-text")
        yield ProgressBar(id="progress-bar", total=100, show_eta=False)

    def update_progress(self, value: int, status: str = "") -> None:
        """Update progress bar and status text."""
        bar = self.query_one("#progress-bar", ProgressBar)
        text = self.query_one("#progress-text", Static)
        bar.progress = value
        if status:
            text.update(f"[#00ff41]{status}[/]")

    def reset(self) -> None:
        """Reset progress bar."""
        bar = self.query_one("#progress-bar", ProgressBar)
        text = self.query_one("#progress-text", Static)
        bar.progress = 0
        text.update("Ready")

    def complete(self, message: str = "Complete") -> None:
        """Mark as complete."""
        bar = self.query_one("#progress-bar", ProgressBar)
        text = self.query_one("#progress-text", Static)
        bar.progress = 100
        text.update(f"[bold #00ff41]{message}[/]")
