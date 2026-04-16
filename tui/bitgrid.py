"""Bit grid widget — interactive 128-bit visualization."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

# Category → color mapping
CATEGORY_COLORS = {
    "opcode": "red",
    "modifier": "yellow",
    "operand": "cyan",
    "unused": "dim",
    "unknown": "magenta",
    "error": "bright_red",
    "default": "white",
}


class BitCell(Static):
    """A single clickable bit cell."""

    DEFAULT_CSS = """
    BitCell {
        width: 2;
        height: 1;
        content-align: center middle;
        text-style: bold;
    }
    BitCell:hover {
        background: $accent;
    }
    BitCell.bit-on {
        color: $text;
    }
    BitCell.bit-off {
        color: $text-muted;
    }
    BitCell.cursor {
        background: $accent;
        text-style: bold reverse;
    }
    BitCell.highlight {
        background: $warning-darken-2;
    }
    """

    class Clicked(Message):
        def __init__(self, pos: int) -> None:
            super().__init__()
            self.pos = pos

    class Hovered(Message):
        def __init__(self, pos: int) -> None:
            super().__init__()
            self.pos = pos

    def __init__(self, pos: int, val: int = 0, **kwargs) -> None:
        super().__init__(str(val), **kwargs)
        self.pos = pos
        self.val = val

    def on_click(self) -> None:
        self.post_message(self.Clicked(self.pos))

    def on_enter(self) -> None:
        self.post_message(self.Hovered(self.pos))

    def set_val(self, val: int) -> None:
        self.val = val
        self.update(str(val))
        self.remove_class("bit-on", "bit-off")
        self.add_class("bit-on" if val else "bit-off")

    def set_category_color(self, category: str) -> None:
        color = CATEGORY_COLORS.get(category, CATEGORY_COLORS["default"])
        self.styles.color = color


class BitGrid(Widget):
    """128-bit grid displayed as 8 rows × 16 cols (MSB top-left)."""

    DEFAULT_CSS = """
    BitGrid {
        height: auto;
        width: 100%;
        padding: 0 1;
    }
    .bit-row {
        height: 1;
        width: 100%;
    }
    .bit-row-label {
        width: 8;
        height: 1;
        color: $text-muted;
        content-align: right middle;
        padding-right: 1;
    }
    .bit-col-header {
        width: 2;
        height: 1;
        color: $text-muted;
        content-align: center middle;
    }
    .col-header-label {
        width: 8;
        height: 1;
    }
    """

    cursor_pos: reactive[int] = reactive(-1)

    class BitFlipped(Message):
        def __init__(self, pos: int, new_val: int) -> None:
            super().__init__()
            self.pos = pos
            self.new_val = new_val

    class BitHovered(Message):
        def __init__(self, pos: int) -> None:
            super().__init__()
            self.pos = pos

    def __init__(self, bits: list[int] | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._bits = bits or [0] * 128
        self._cells: dict[int, BitCell] = {}
        self._categories: dict[int, str] = {}

    def compose(self) -> ComposeResult:
        # Column headers
        with Horizontal(classes="bit-row"):
            yield Static("", classes="col-header-label")
            for col in range(15, -1, -1):
                yield Static(f"{col:X}", classes="bit-col-header")

        # 8 rows, each 16 bits, MSB (row 7) at top
        for row in range(7, -1, -1):
            with Horizontal(classes="bit-row"):
                start_bit = row * 16
                yield Static(f"{start_bit + 15:>3}-{start_bit:<3}", classes="bit-row-label")
                for col in range(15, -1, -1):
                    pos = row * 16 + col
                    cell = BitCell(pos, self._bits[pos], id=f"bit_{pos}")
                    self._cells[pos] = cell
                    yield cell

    def on_mount(self) -> None:
        self._refresh_cells()

    def _refresh_cells(self) -> None:
        for pos, cell in self._cells.items():
            cell.set_val(self._bits[pos])
            cat = self._categories.get(pos, "default")
            cell.set_category_color(cat)

    def update_bits(self, bits: list[int]) -> None:
        self._bits = list(bits)
        self._refresh_cells()

    def set_categories(self, categories: dict[int, str]) -> None:
        self._categories = categories
        self._refresh_cells()

    def highlight_bits(self, positions: set[int]) -> None:
        for pos, cell in self._cells.items():
            if pos in positions:
                cell.add_class("highlight")
            else:
                cell.remove_class("highlight")

    def on_bit_cell_clicked(self, event: BitCell.Clicked) -> None:
        pos = event.pos
        self._bits[pos] ^= 1
        self._cells[pos].set_val(self._bits[pos])
        self.post_message(self.BitFlipped(pos, self._bits[pos]))

    def on_bit_cell_hovered(self, event: BitCell.Hovered) -> None:
        # Move cursor
        old = self.cursor_pos
        if old >= 0 and old in self._cells:
            self._cells[old].remove_class("cursor")
        self.cursor_pos = event.pos
        self._cells[event.pos].add_class("cursor")
        self.post_message(self.BitHovered(event.pos))
