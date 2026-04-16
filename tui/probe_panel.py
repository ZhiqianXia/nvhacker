"""Probe info panel — shows details when hovering/selecting bits."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static

from ..core.bitfield import BitProbeResult, ProbeReport


class ProbePanel(Widget):
    """Shows probe results for the hovered/selected bit."""

    DEFAULT_CSS = """
    ProbePanel {
        height: auto;
        width: 100%;
        padding: 1 2;
        border: solid $accent;
    }
    .probe-title {
        color: $accent;
        text-style: bold;
        height: 1;
    }
    .probe-detail {
        color: $text;
        height: auto;
    }
    .probe-category {
        height: 1;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._report: ProbeReport | None = None

    def compose(self) -> ComposeResult:
        yield Static("Bit Probe", classes="probe-title", id="probe-title")
        yield Static("Hover over a bit to see probe info", classes="probe-detail", id="probe-detail")

    def set_report(self, report: ProbeReport) -> None:
        self._report = report

    def show_bit(self, pos: int) -> None:
        title = self.query_one("#probe-title", Static)
        detail = self.query_one("#probe-detail", Static)

        if self._report is None:
            title.update(f"Bit {pos}")
            detail.update("Run probe first (Ctrl+P)")
            return

        results = [r for r in self._report.bit_results if r.pos == pos]
        if not results:
            title.update(f"Bit {pos}")
            detail.update("Not probed")
            return

        r = results[0]
        title.update(f"Bit {pos} — {'CHANGED' if r.changed else 'no effect'}")

        lines = []
        if r.error:
            lines.append(f"Error: {r.error}")
        else:
            if r.mnemonic_changed:
                lines.append(f"Mnemonic changed!")
            if r.modifier_diff:
                lines.append(f"Modifiers: {' '.join(r.modifier_diff)}")
            if r.operand_changed:
                lines.append(f"Operands changed")
            if r.changed:
                lines.append(f"Original: {r.original_asm}")
                lines.append(f"Flipped:  {r.flipped_asm}")
            else:
                lines.append(f"Assembly: {r.original_asm}")

        detail.update("\n".join(lines) if lines else "No change")

    def show_summary(self) -> None:
        title = self.query_one("#probe-title", Static)
        detail = self.query_one("#probe-detail", Static)

        if self._report is None:
            title.update("Probe Summary")
            detail.update("No probe data. Press Ctrl+P to probe all bits.")
            return

        n_changed = len(self._report.changed_bits)
        n_opcode = len(self._report.opcode_bits)
        n_mod = len(self._report.modifier_bits)
        n_operand = len(self._report.operand_bits)

        groups_text = ""
        for g in self._report.groups:
            groups_text += f"\n  [{g.lo}:{g.hi}] {g.category}"

        lines = [
            f"Base: {self._report.base_disasm.full}",
            f"Changed bits: {n_changed}/128",
            f"  Opcode bits: {n_opcode}",
            f"  Modifier bits: {n_mod}",
            f"  Operand bits: {n_operand}",
            f"Field groups:{groups_text}",
        ]
        title.update("Probe Summary")
        detail.update("\n".join(lines))
