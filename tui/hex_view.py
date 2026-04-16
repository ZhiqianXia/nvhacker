"""Hex editor widget — edit instruction bytes in hex."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Input, Static


class HexEditor(Widget):
    """Hex input for the 128-bit instruction."""

    DEFAULT_CSS = """
    HexEditor {
        height: auto;
        width: 100%;
        padding: 1 2;
        border: solid $secondary;
    }
    .hex-label {
        color: $text-muted;
        height: 1;
    }
    #hex-input {
        width: 100%;
    }
    .hex-bytes {
        color: $text;
        height: 1;
    }
    """

    class HexChanged(Message):
        def __init__(self, hex_str: str) -> None:
            super().__init__()
            self.hex_str = hex_str

    def __init__(self, initial_hex: str = "0" * 32, **kwargs) -> None:
        super().__init__(**kwargs)
        self._hex = initial_hex

    def compose(self) -> ComposeResult:
        yield Static("Hex Encoding (128-bit little-endian)", classes="hex-label")
        yield Input(value=self._hex, placeholder="32 hex characters", id="hex-input", max_length=32)
        yield Static(self._format_bytes(self._hex), classes="hex-bytes", id="hex-bytes")

    def _format_bytes(self, hex_str: str) -> str:
        hex_str = hex_str.ljust(32, "0")
        return " ".join(hex_str[i : i + 2] for i in range(0, 32, 2))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        hex_str = event.value.strip().replace(" ", "").replace("0x", "")
        if len(hex_str) <= 32 and all(c in "0123456789abcdefABCDEF" for c in hex_str):
            hex_str = hex_str.ljust(32, "0")
            self._hex = hex_str
            self.query_one("#hex-bytes", Static).update(self._format_bytes(hex_str))
            self.post_message(self.HexChanged(hex_str))

    def on_input_changed(self, event: Input.Changed) -> None:
        hex_str = event.value.strip().replace(" ", "").replace("0x", "")
        if len(hex_str) == 32 and all(c in "0123456789abcdefABCDEF" for c in hex_str):
            self._hex = hex_str
            self.query_one("#hex-bytes", Static).update(self._format_bytes(hex_str))
            self.post_message(self.HexChanged(hex_str))

    def set_hex(self, hex_str: str) -> None:
        self._hex = hex_str
        try:
            inp = self.query_one("#hex-input", Input)
            inp.value = hex_str
            self.query_one("#hex-bytes", Static).update(self._format_bytes(hex_str))
        except Exception:
            pass
