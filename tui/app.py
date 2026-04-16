"""NVHacker — NVIDIA instruction binary explorer TUI."""

from __future__ import annotations

import re
import subprocess

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Footer, Header, Static

from ..core.bitfield import ProbeReport, probe_all_bits, probe_bit
from ..core.control import control_bit_range, decode_control_fields
from ..core.disassembler import DisasmResult, disassemble, get_nvdisasm
from ..core.elf_patch import list_sections, read_instruction, write_instruction
from ..core.instruction import Instruction
from .asm_view import AsmView
from .bitgrid import BitGrid
from .hex_view import HexEditor
from .probe_panel import ProbePanel


_DISASM_PC_RE = re.compile(r"/\*\s*([0-9a-fA-F]+)\s*\*/")
_DISASM_TEXT_RE = re.compile(
    r"\s*/\*\s*[0-9a-fA-F]+\s*\*/\s+(.*?)\s*;\s*(?:/\*.*?\*/)?\s*$"
)


def _section_group_name(name: str, flags: str) -> str:
    if name.startswith(".text") or "X" in flags:
        return "Code"
    if name.startswith(".nv.info"):
        return "NV Info"
    if name.startswith(".nv.constant"):
        return "NV Constant"
    if name.startswith(".nv.shared"):
        return "NV Shared"
    if name.startswith(".nv.global"):
        return "NV Global"
    if name.startswith(".nv.relfatbin") or name.startswith(".nvFatBinSegment"):
        return "NV Fatbin"
    if name.startswith(".debug") or name.startswith(".line"):
        return "Debug"
    if name in {".symtab", ".strtab", ".shstrtab"} or name.startswith(".rela"):
        return "ELF Tables"
    return "Other"


class NVHackerApp(App):
    """Interactive NVIDIA instruction binary explorer."""

    TITLE = "NVHacker — NV Instruction Explorer"
    CSS = """
    Screen {
        layout: vertical;
    }
    #top-pane {
        height: auto;
        width: 100%;
    }
    #bottom-pane {
        height: auto;
        width: 100%;
    }
    #left-col {
        width: 2fr;
    }
    #right-col {
        width: 1fr;
    }
    #ctrl-fields {
        height: auto;
        width: 100%;
        border: solid $primary;
        padding: 1;
        color: $text;
    }
    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary-background;
        color: $text-muted;
        padding: 0 2;
    }
    #arch-label {
        width: auto;
        height: 1;
        color: $accent;
        padding: 0 2;
    }
    #list-pane {
        height: 1fr;
        width: 100%;
    }
    #list-split {
        height: 1fr;
        width: 100%;
    }
    #list-left {
        width: 1fr;
    }
    #list-right {
        width: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    #section-nav-title {
        color: $accent;
        height: 1;
        padding: 0 1;
    }
    #section-nav {
        border: solid $accent;
        padding: 1;
        height: 14;
    }
    .section-item {
        width: 100%;
        margin: 0 0 1 0;
        content-align: left middle;
    }
    .section-group {
        color: $accent;
        text-style: bold;
        margin: 1 0 0 0;
    }
    .section-chunk {
        color: $text;
        height: 1;
    }
    #list-header {
        color: $accent;
        padding: 0 2;
    }
    #list-disasm-title {
        color: $accent;
        height: 1;
        padding: 0 1;
    }
    #list-disasm-scroll {
        height: 1fr;
        width: 100%;
    }
    #list-disasm-content {
        height: auto;
        width: 100%;
    }
    #insn-list {
        border: solid $accent;
        padding: 1;
        height: 1fr;
    }
    .insn-item {
        width: 100%;
        margin: 0 0 1 0;
        content-align: left middle;
    }
    #editor-pane {
        height: 1fr;
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("escape", "back_to_list", "Back To List"),
        Binding("ctrl+p", "probe_all", "Probe All Bits"),
        Binding("ctrl+r", "reset", "Reset"),
        Binding("ctrl+s", "show_summary", "Summary"),
        Binding("f6", "show_summary", "Summary(F6)"),
        Binding("ctrl+w", "save_elf", "Write ELF"),
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+a", "cycle_arch", "Cycle Arch"),
        Binding("f7", "cycle_arch", "Cycle Arch(F7)"),
    ]

    ARCHITECTURES = ["SM100", "SM90", "SM89", "SM86", "SM80", "SM75"]

    def __init__(
        self,
        hex_str: str = "",
        arch: str = "SM100",
        elf_path: str = "",
        elf_section: str = "",
        elf_index: int = -1,
        out_elf_path: str = "",
        run_cmd: str = "",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._arch = arch
        self._arch_idx = self.ARCHITECTURES.index(arch) if arch in self.ARCHITECTURES else 0
        self._elf_path = elf_path
        self._elf_section = elf_section
        self._elf_index = elf_index
        self._out_elf_path = out_elf_path
        self._run_cmd = run_cmd
        if hex_str:
            self._insn = Instruction.from_hex(hex_str)
        else:
            self._insn = Instruction.zeros()
        self._base_disasm: DisasmResult | None = None
        self._report: ProbeReport | None = None
        self._list_mode = bool(self._elf_path and self._elf_section and self._elf_index < 0)
        self._list_loaded = False
        self._list_generation = 0
        self._cached_file_disasm: str | None = None
        self._cached_disasm_lines: list[str] = []
        self._cached_pc_line_map: dict[int, int] = {}
        self._selected_pc: int | None = None
        self._all_sections = []
        self._section_nav_generation = 0

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="list-pane"):
            with Horizontal(id="list-split"):
                with Vertical(id="list-left"):
                    yield Static("Instruction List (click one to edit)", id="list-header")
                    with VerticalScroll(id="insn-list"):
                        yield Static("Loading...", id="insn-loading")
                with Vertical(id="list-right"):
                    yield Static("Sections", id="section-nav-title")
                    with VerticalScroll(id="section-nav"):
                        yield Static("Loading sections...", id="section-nav-loading")
                    yield Static("Disassembly Reference (cached once)", id="list-disasm-title")
                    with VerticalScroll(id="list-disasm-scroll"):
                        yield Static("Loading full-file disassembly...", id="list-disasm-content")

        with Vertical(id="editor-pane"):
            with Vertical(id="top-pane"):
                yield Static(f"Arch: {self._arch}", id="arch-label")
                yield BitGrid(bits=self._insn.bits_le, id="bitgrid")
            with Horizontal(id="bottom-pane"):
                with Vertical(id="left-col"):
                    yield HexEditor(initial_hex=self._insn.hex, id="hex-editor")
                    yield AsmView(id="asm-view")
                with Vertical(id="right-col"):
                    yield Static("Control fields will appear here", id="ctrl-fields")
                    yield ProbePanel(id="probe-panel")

        yield Static("Ready. Enter hex or click bits. Ctrl+P to probe.", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        if self._list_mode:
            self._show_list_view()
            self.call_later(self._load_section_nav)
            self.call_later(self._load_instruction_list)
            self.call_later(self._load_cached_file_disasm)
            self._set_status("ELF list mode: click an instruction to open editor")
            return

        self._show_editor_view()
        self._do_disassemble()
        self._update_control_fields()
        if self._elf_path and self._elf_section and self._elf_index >= 0:
            self._set_status(
                f"ELF mode: {self._elf_section}[{self._elf_index}]  Esc to list, Ctrl+W to write patched ELF"
            )

    def _show_list_view(self) -> None:
        self._list_mode = True
        self.query_one("#list-pane", Vertical).styles.display = "block"
        self.query_one("#editor-pane", Vertical).styles.display = "none"

    def _show_editor_view(self) -> None:
        self._list_mode = False
        self.query_one("#list-pane", Vertical).styles.display = "none"
        self.query_one("#editor-pane", Vertical).styles.display = "block"

    def _load_instruction_list(self) -> None:
        if not (self._elf_path and self._elf_section):
            return

        container = self.query_one("#insn-list", VerticalScroll)
        for child in list(container.children):
            child.remove()

        self._list_generation += 1
        generation = self._list_generation

        sec = self._resolve_current_section()
        header = self.query_one("#list-header", Static)
        if "X" in sec.flags:
            header.update(
                f"Instruction List: {sec.name} ({sec.instruction_count} instructions)"
            )

            for idx in range(sec.instruction_count):
                ref = read_instruction(self._elf_path, sec.name, idx)
                # Keep list rendering lightweight: avoid nvdisasm per row.
                label = f"[{idx:4d}] pc=0x{ref.pc:06x}  hex={ref.instruction.hex}"
                container.mount(
                    Button(label, id=f"insn-btn-{generation}-{idx}", classes="insn-item")
                )

            self._feedback(
                f"Loaded {sec.instruction_count} instructions from {sec.name}"
            )
        else:
            header.update(
                f"Section View: {sec.name} size=0x{sec.size:x} flags={sec.flags}"
            )
            for line in self._read_section_preview_lines(sec):
                container.mount(Static(line, classes="section-chunk"))
            self._feedback(f"Loaded readonly section preview: {sec.name}")

        self._list_loaded = True
        self._update_reference_pane()

    def _load_section_nav(self) -> None:
        if not self._elf_path:
            return

        container = self.query_one("#section-nav", VerticalScroll)
        for child in list(container.children):
            child.remove()
        self._section_nav_generation += 1
        generation = self._section_nav_generation

        try:
            self._all_sections = [sec for sec in list_sections(self._elf_path) if sec.size > 0]
        except Exception as e:
            container.mount(Static(f"Failed to load sections: {e}"))
            self._feedback(f"Failed to load sections: {e}", severity="warning")
            return

        grouped: dict[str, list] = {}
        for sec in self._all_sections:
            grouped.setdefault(_section_group_name(sec.name, sec.flags), []).append(sec)

        group_order = [
            "Code",
            "NV Info",
            "NV Constant",
            "NV Shared",
            "NV Global",
            "NV Fatbin",
            "Debug",
            "ELF Tables",
            "Other",
        ]
        for group_name in group_order:
            sections = grouped.get(group_name, [])
            if not sections:
                continue
            container.mount(Static(group_name, classes="section-group"))
            for sec in sections:
                marker = "*" if sec.name == self._elf_section else " "
                desc = f"{sec.instruction_count} insn" if "X" in sec.flags else f"0x{sec.size:x} bytes"
                label = f"{marker} {sec.name}  ({desc})"
                container.mount(
                    Button(
                        label,
                        id=f"section-btn-{generation}-{sec.index}",
                        classes="section-item",
                    )
                )

    def _load_cached_file_disasm(self) -> None:
        if not self._elf_path:
            return

        widget = self.query_one("#list-disasm-content", Static)
        if self._cached_file_disasm is not None:
            self._update_reference_pane()
            return

        try:
            nvdisasm = get_nvdisasm()
            result = subprocess.run(
                [nvdisasm, "-hex", self._elf_path],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                text = f"nvdisasm failed (rc={result.returncode})\n{result.stderr.strip()}"
            else:
                text = result.stdout.strip() or "(empty disassembly output)"
            self._cached_file_disasm = text
            self._cached_disasm_lines = text.splitlines() if result.returncode == 0 else [text]
            self._cached_pc_line_map = self._build_pc_line_map(self._cached_disasm_lines)
            self._update_reference_pane()
            self._feedback("Cached full-file disassembly ready")
        except Exception as e:
            widget.update(f"Failed to load full-file disassembly: {e}")
            self._feedback(f"Failed to cache disassembly: {e}", severity="warning")

    def _build_pc_line_map(self, lines: list[str]) -> dict[int, int]:
        mapping: dict[int, int] = {}
        for idx, line in enumerate(lines):
            m = _DISASM_PC_RE.search(line)
            if m:
                mapping[int(m.group(1), 16)] = idx
        return mapping

    def _update_disasm_reference(self, target_pc: int | None) -> None:
        widget = self.query_one("#list-disasm-content", Static)
        if not self._cached_file_disasm:
            widget.update("Loading full-file disassembly...")
            return

        if target_pc is None or target_pc not in self._cached_pc_line_map:
            preview = self._cached_disasm_lines[:40]
            text = Text()
            text.append("Cached full-file disassembly\n", style="bold cyan")
            text.append("Open an instruction, then return to list to auto-jump here.\n\n", style="italic")
            if preview:
                text.append("\n".join(preview))
            else:
                text.append(self._cached_file_disasm)
            widget.update(text)
            return

        line_idx = self._cached_pc_line_map[target_pc]
        start = max(0, line_idx - 10)
        end = min(len(self._cached_disasm_lines), line_idx + 11)
        text = Text()
        text.append(f"Focused around pc=0x{target_pc:04x}\n\n", style="bold cyan")
        for idx in range(start, end):
            line = self._cached_disasm_lines[idx]
            if idx == line_idx:
                text.append(">>> ", style="bold yellow")
                text.append(line, style="bold black on yellow")
            else:
                text.append("    ", style="dim")
                text.append(line, style="white")
            if idx + 1 < end:
                text.append("\n")
        widget.update(text)

    def _update_reference_pane(self) -> None:
        sec = self._resolve_current_section()
        title = self.query_one("#list-disasm-title", Static)
        widget = self.query_one("#list-disasm-content", Static)

        if "X" in sec.flags:
            title.update(f"Instruction Reference: {sec.name}")
            if not self._cached_file_disasm:
                widget.update("Loading full-file disassembly...")
            else:
                widget.update(self._build_instruction_reference_table(sec))
            return

        title.update(f"Section Reference: {sec.name}")
        lines = self._read_section_preview_lines(sec, max_bytes=16 * 40)
        text = Text()
        text.append(f"Readonly section preview for {sec.name}\n\n", style="bold cyan")
        text.append("\n".join(lines))
        widget.update(text)

    def _build_instruction_reference_table(self, sec) -> Text:
        text = Text()
        text.append(
            f"Instruction table for {sec.name} ({sec.instruction_count} instructions)\n\n",
            style="bold cyan",
        )

        header = " idx   pc        instruction"
        text.append(header + "\n", style="bold")

        for idx in range(sec.instruction_count):
            ref = read_instruction(self._elf_path, sec.name, idx)
            asm = self._lookup_cached_asm(ref.pc)
            prefix = ">>> " if self._selected_pc == ref.pc else "    "
            line = f"{prefix}[{idx:4d}] pc=0x{ref.pc:06x}  {asm}"
            if self._selected_pc == ref.pc:
                text.append(line, style="bold black on yellow")
            else:
                text.append(line, style="white")
            if idx + 1 < sec.instruction_count:
                text.append("\n")

        return text

    def _lookup_cached_asm(self, pc: int) -> str:
        line_idx = self._cached_pc_line_map.get(pc)
        if line_idx is None:
            return "<asm not found in cache>"
        raw_line = self._cached_disasm_lines[line_idx]
        match = _DISASM_TEXT_RE.match(raw_line)
        if match:
            return match.group(1).strip()
        return raw_line.strip()

    def _open_elf_instruction(self, index: int) -> None:
        if not (self._elf_path and self._elf_section):
            return

        sec = self._resolve_current_section()
        if "X" not in sec.flags:
            self._feedback(
                f"Section {sec.name} is readonly metadata; instruction editor is only for executable sections",
                severity="warning",
            )
            return

        ref = read_instruction(self._elf_path, self._elf_section, index)
        self._elf_index = index
        self._selected_pc = ref.pc
        self._insn = ref.instruction.copy()
        self._report = None
        panel = self.query_one("#probe-panel", ProbePanel)
        panel.set_report(None)
        panel.show_summary()
        if self._cached_file_disasm is not None:
            self._update_reference_pane()
        self._update_views()
        self._show_editor_view()
        self._set_status(
            f"Editing {self._elf_section}[{self._elf_index}] pc=0x{ref.pc:x}. Esc to return list"
        )

    def _switch_section(self, section_index: int) -> None:
        if not self._all_sections:
            self._load_section_nav()
        target = None
        for sec in self._all_sections:
            if sec.index == section_index:
                target = sec
                break
        if target is None:
            self._feedback(f"Section index {section_index} not found", severity="warning")
            return

        self._elf_section = target.name
        self._elf_index = -1
        self._selected_pc = None
        self._list_loaded = False
        self._show_list_view()
        self._load_section_nav()
        self._load_instruction_list()
        self._update_reference_pane()
        self._feedback(f"Switched to section: {target.name}")

    def _resolve_current_section(self):
        if not self._all_sections:
            self._all_sections = [sec for sec in list_sections(self._elf_path) if sec.size > 0]
        for sec in self._all_sections:
            if sec.name == self._elf_section:
                return sec
        raise ValueError(f"Section not found: {self._elf_section}")

    def _read_section_preview_lines(self, sec, max_bytes: int = 16 * 128) -> list[str]:
        lines = [
            f"section={sec.name} offset=0x{sec.offset:x} addr=0x{sec.addr:x} size=0x{sec.size:x}",
            "",
        ]
        preview_size = min(sec.size, max_bytes)
        with open(self._elf_path, "rb") as f:
            f.seek(sec.offset)
            data = f.read(preview_size)

        for chunk_idx in range(0, len(data), 16):
            chunk = data[chunk_idx:chunk_idx + 16]
            hex_bytes = chunk.hex()
            grouped = " ".join(hex_bytes[i:i + 2] for i in range(0, len(hex_bytes), 2))
            lines.append(
                f"[{chunk_idx // 16:4d}] file+0x{sec.offset + chunk_idx:06x}  {grouped}"
            )

        if sec.size > preview_size:
            lines.append("")
            lines.append(f"... truncated, showing first 0x{preview_size:x} bytes of 0x{sec.size:x}")
        return lines

    def _do_disassemble(self) -> None:
        try:
            self._base_disasm = disassemble(self._insn, arch=self._arch)
            asm_view = self.query_one("#asm-view", AsmView)
            asm_view.set_current(self._base_disasm.full)
            self._set_status(f"Disassembled: {self._base_disasm.full}")
        except Exception as e:
            self._base_disasm = None
            asm_view = self.query_one("#asm-view", AsmView)
            asm_view.set_current(f"Error: {e}")
            self._set_status(f"Disassembly error: {e}")

    def _update_views(self) -> None:
        grid = self.query_one("#bitgrid", BitGrid)
        grid.update_bits(self._insn.bits_le)
        hex_ed = self.query_one("#hex-editor", HexEditor)
        hex_ed.set_hex(self._insn.hex)
        self._do_disassemble()
        self._update_control_fields()

    def _update_control_fields(self) -> None:
        ctrl = decode_control_fields(self._insn, arch=self._arch)
        lo, hi = control_bit_range(self._arch)
        self.query_one("#ctrl-fields", Static).update(
            "Control Fields (Editor)\n"
            f"stall={ctrl.stall}  yield={ctrl.yield_flag}  "
            f"write_barrier={ctrl.write_barrier}  read_barrier={ctrl.read_barrier}\n"
            f"barrier_mask={ctrl.barrier_mask_bits}  reuse={ctrl.reuse_bits}  unused={ctrl.unused_bits}\n"
            f"control_bit_range=[{lo}..{hi}]"
        )

    def _update_control_fields_hover(self, bit_pos: int) -> None:
        lo, hi = control_bit_range(self._arch)
        base = decode_control_fields(self._insn, arch=self._arch)
        probe = self._insn.copy()
        probe.flip_bit(bit_pos)
        flipped = decode_control_fields(probe, arch=self._arch)

        def mark(before: object, after: object) -> str:
            return "*" if before != after else " "

        self.query_one("#ctrl-fields", Static).update(
            "Control Fields (Hover Preview)\n"
            f"bit={bit_pos}  in_control_range={'yes' if lo <= bit_pos <= hi else 'no'}\n"
            f"{mark(base.stall, flipped.stall)} stall: {base.stall} -> {flipped.stall}\n"
            f"{mark(base.yield_flag, flipped.yield_flag)} yield: {base.yield_flag} -> {flipped.yield_flag}\n"
            f"{mark(base.write_barrier, flipped.write_barrier)} write_barrier: {base.write_barrier} -> {flipped.write_barrier}\n"
            f"{mark(base.read_barrier, flipped.read_barrier)} read_barrier: {base.read_barrier} -> {flipped.read_barrier}\n"
            f"{mark(base.barrier_mask_bits, flipped.barrier_mask_bits)} barrier_mask: {base.barrier_mask_bits} -> {flipped.barrier_mask_bits}\n"
            f"{mark(base.reuse_bits, flipped.reuse_bits)} reuse: {base.reuse_bits} -> {flipped.reuse_bits}\n"
            f"{mark(base.unused_bits, flipped.unused_bits)} unused: {base.unused_bits} -> {flipped.unused_bits}\n"
            f"control_bit_range=[{lo}..{hi}]"
        )

    def _set_status(self, msg: str) -> None:
        self.query_one("#status-bar", Static).update(msg)

    def _feedback(self, msg: str, severity: str = "information") -> None:
        self._set_status(msg)
        # Show a visible popup notification when supported by the Textual version.
        if hasattr(self, "notify"):
            try:
                self.notify(msg, severity=severity, timeout=3)
            except Exception:
                pass

    # ── event handlers ──────────────────────────────────────────────
    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""
        if btn_id.startswith("insn-btn-"):
            try:
                idx = int(btn_id.rsplit("-", 1)[-1])
            except ValueError:
                return
            self._open_elf_instruction(idx)
            return

        if btn_id.startswith("section-btn-"):
            try:
                section_index = int(btn_id.rsplit("-", 1)[-1])
            except ValueError:
                return
            self._switch_section(section_index)

    def on_bit_grid_bit_flipped(self, event: BitGrid.BitFlipped) -> None:
        if self._list_mode:
            return
        before = decode_control_fields(self._insn, arch=self._arch)
        self._insn.set_bit(event.pos, event.new_val)
        hex_ed = self.query_one("#hex-editor", HexEditor)
        hex_ed.set_hex(self._insn.hex)
        self._do_disassemble()
        self._update_control_fields()
        after = decode_control_fields(self._insn, arch=self._arch)
        lo, hi = control_bit_range(self._arch)
        changed = before != after
        if changed:
            self._set_status(f"Bit {event.pos} → {event.new_val} (control fields changed)")
        elif lo <= event.pos <= hi:
            self._set_status(f"Bit {event.pos} → {event.new_val} (control range, value unchanged)")
        else:
            self._set_status(
                f"Bit {event.pos} → {event.new_val} (outside control range [{lo}..{hi}])"
            )

    def on_bit_grid_bit_hovered(self, event: BitGrid.BitHovered) -> None:
        if self._list_mode:
            return
        pos = event.pos
        if self._base_disasm is None:
            return

        # Quick single-bit probe on hover
        try:
            result = probe_bit(self._insn, pos, self._base_disasm, arch=self._arch)
            asm_view = self.query_one("#asm-view", AsmView)
            diff = " ".join(result.modifier_diff) if result.modifier_diff else ""
            if result.mnemonic_changed:
                diff = f"OPCODE CHANGED  {diff}"
            if result.error:
                diff = f"Error: {result.error}"
            asm_view.set_flipped(pos, result.flipped_asm, diff)
        except Exception:
            pass

        # Live control preview while hovering (like asm preview behavior).
        try:
            self._update_control_fields_hover(pos)
        except Exception:
            pass

        # Update probe panel if we have a full report
        if self._report:
            panel = self.query_one("#probe-panel", ProbePanel)
            panel.show_bit(pos)

    def on_hex_editor_hex_changed(self, event: HexEditor.HexChanged) -> None:
        if self._list_mode:
            return
        try:
            self._insn = Instruction.from_hex(event.hex_str)
            grid = self.query_one("#bitgrid", BitGrid)
            grid.update_bits(self._insn.bits_le)
            self._do_disassemble()
            self._update_control_fields()
            self._report = None
            self._set_status("Instruction updated from hex")
        except ValueError as e:
            self._set_status(f"Invalid hex: {e}")

    # ── actions ─────────────────────────────────────────────────────
    def action_back_to_list(self) -> None:
        if not (self._elf_path and self._elf_section):
            return
        self._show_list_view()
        self._load_section_nav()
        if not self._list_loaded:
            self.call_later(self._load_instruction_list)
        if self._cached_file_disasm is None:
            self.call_later(self._load_cached_file_disasm)
        else:
            self._update_reference_pane()
        self._set_status("Instruction list view")

    def action_probe_all(self) -> None:
        if self._list_mode:
            self._set_status("Open one instruction first, then run probe")
            return
        sec = self._resolve_current_section()
        if "X" not in sec.flags:
            self._feedback("Probe is only available for executable instruction sections", severity="warning")
            return
        self._set_status("Probing all 128 bits... (this calls nvdisasm 128 times)")
        self.call_later(self._run_probe)

    def _run_probe(self) -> None:
        try:
            self._report = probe_all_bits(self._insn, arch=self._arch)
            # Color the grid by category
            categories = {}
            for r in self._report.bit_results:
                if r.error:
                    categories[r.pos] = "error"
                elif r.mnemonic_changed:
                    categories[r.pos] = "opcode"
                elif r.modifier_diff:
                    categories[r.pos] = "modifier"
                elif r.operand_changed:
                    categories[r.pos] = "operand"
                elif not r.changed:
                    categories[r.pos] = "unused"
                else:
                    categories[r.pos] = "unknown"

            grid = self.query_one("#bitgrid", BitGrid)
            grid.set_categories(categories)

            panel = self.query_one("#probe-panel", ProbePanel)
            panel.set_report(self._report)
            panel.show_summary()

            self._set_status(
                f"Probe complete: {len(self._report.changed_bits)}/128 bits affect output"
            )
        except Exception as e:
            self._set_status(f"Probe error: {e}")

    def action_reset(self) -> None:
        if self._list_mode:
            self._set_status("Open one instruction first, then reset")
            return
        self._insn = Instruction.zeros()
        self._report = None
        self._update_views()
        panel = self.query_one("#probe-panel", ProbePanel)
        panel.set_report(None)
        panel.show_summary()
        self._set_status("Reset to zero")

    def action_show_summary(self) -> None:
        if self._list_mode:
            self._feedback("Summary is available in editor page only", severity="warning")
            return
        panel = self.query_one("#probe-panel", ProbePanel)
        panel.show_summary()
        self._feedback("Summary updated")

    def action_cycle_arch(self) -> None:
        self._arch_idx = (self._arch_idx + 1) % len(self.ARCHITECTURES)
        self._arch = self.ARCHITECTURES[self._arch_idx]
        self.query_one("#arch-label", Static).update(f"Arch: {self._arch}")
        self._report = None
        if self._list_mode:
            # List rows are architecture-agnostic (index/pc/hex), no heavy reload needed.
            self._feedback(f"Architecture: {self._arch} (applies when opening instruction)")
        else:
            self._do_disassemble()
            self._update_control_fields()
            self._feedback(f"Architecture: {self._arch}")

    def action_save_elf(self) -> None:
        if self._list_mode:
            self._feedback("Open one instruction first, then write ELF", severity="warning")
            return
        sec = self._resolve_current_section()
        if "X" not in sec.flags:
            self._feedback("Write ELF is only supported for executable instruction sections", severity="warning")
            return
        if not (self._elf_path and self._elf_section and self._elf_index >= 0):
            self._feedback("Write ELF is only available in --elf mode", severity="warning")
            return
        if not self._out_elf_path:
            self._feedback("Set --out-elf to enable writing patched ELF", severity="warning")
            return

        try:
            write_instruction(
                src_elf=self._elf_path,
                dst_elf=self._out_elf_path,
                section_name=self._elf_section,
                index=self._elf_index,
                instruction=self._insn,
            )

            # Verify the write by reading back the just-patched instruction.
            patched_ref = read_instruction(self._out_elf_path, self._elf_section, self._elf_index)
            if patched_ref.instruction.hex != self._insn.hex:
                self._feedback(
                    "Write completed but verify mismatch; please re-open and check instruction.",
                    severity="warning",
                )
                return

            # Make patched file the active source so list/reload shows latest content.
            self._elf_path = self._out_elf_path
            self._list_loaded = False
            self._cached_file_disasm = None
            self._cached_disasm_lines = []
            self._cached_pc_line_map = {}
            self._feedback(
                f"Patched ELF written and activated: {self._out_elf_path}",
                severity="information",
            )
        except Exception as e:
            self._feedback(f"Write ELF failed: {e}", severity="error")
            return

        if self._run_cmd:
            cmd = self._run_cmd.replace("{elf}", self._out_elf_path)
            rc = subprocess.run(cmd, shell=True, check=False).returncode
            level = "information" if rc == 0 else "error"
            self._feedback(f"Run done (rc={rc}): {cmd}", severity=level)
