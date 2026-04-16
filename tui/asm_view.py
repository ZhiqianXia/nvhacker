"""Assembly view widget — displays disassembly with diff highlighting."""

from __future__ import annotations

from textual.widget import Widget
from textual.widgets import Static


class AsmView(Widget):
    """Displays current and comparison disassembly."""

    DEFAULT_CSS = """
    AsmView {
        height: auto;
        width: 100%;
        padding: 1 2;
        border: solid $primary;
    }
    .asm-label {
        color: $text-muted;
        text-style: italic;
        height: 1;
    }
    .asm-current {
        color: $text;
        text-style: bold;
        height: 1;
    }
    .asm-flipped {
        color: $warning;
        height: 1;
    }
    .asm-diff {
        color: $error;
        height: 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._current_asm = ""
        self._flipped_asm = ""
        self._diff_info = ""
        self._hover_bit = -1

    def compose(self):
        yield Static("Assembly", classes="asm-label", id="asm-label")
        yield Static("(no instruction loaded)", classes="asm-current", id="asm-current")
        yield Static("", classes="asm-label", id="asm-flipped-label")
        yield Static("", classes="asm-flipped", id="asm-flipped")
        yield Static("", classes="asm-diff", id="asm-diff")

    def set_current(self, asm: str) -> None:
        self._current_asm = asm
        current = self.query_one("#asm-current", Static)
        current.update(asm or "(no instruction loaded)")

    def set_flipped(self, bit_pos: int, asm: str, diff: str = "") -> None:
        self._hover_bit = bit_pos
        self._flipped_asm = asm
        self._diff_info = diff

        label = self.query_one("#asm-flipped-label", Static)
        flipped = self.query_one("#asm-flipped", Static)
        diff_w = self.query_one("#asm-diff", Static)

        if bit_pos >= 0:
            label.update(f"Bit {bit_pos} flipped:")
            flipped.update(asm)
            diff_w.update(diff)
        else:
            label.update("")
            flipped.update("")
            diff_w.update("")
