"""Bitfield analysis — probe each bit to discover its effect on assembly."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .disassembler import DisasmResult, disassemble
from .instruction import Instruction


@dataclass
class BitProbeResult:
    """Result of flipping a single bit."""

    pos: int
    original_asm: str
    flipped_asm: str
    changed: bool
    mnemonic_changed: bool
    predicate_changed: bool
    modifier_diff: list[str]  # modifiers added/removed
    operand_changed: bool
    error: Optional[str] = None


@dataclass
class BitFieldGroup:
    """A contiguous range of bits with similar effect."""

    lo: int
    hi: int  # inclusive
    label: str
    category: str  # "opcode", "predicate", "modifier", "operand", "unused", "unknown"


@dataclass
class ProbeReport:
    """Full probe report for an instruction."""

    instruction: Instruction
    arch: str
    base_disasm: DisasmResult
    bit_results: list[BitProbeResult] = field(default_factory=list)
    groups: list[BitFieldGroup] = field(default_factory=list)

    @property
    def changed_bits(self) -> list[int]:
        return [r.pos for r in self.bit_results if r.changed]

    @property
    def modifier_bits(self) -> list[int]:
        return [r.pos for r in self.bit_results if r.modifier_diff]

    @property
    def opcode_bits(self) -> list[int]:
        return [r.pos for r in self.bit_results if r.mnemonic_changed]

    @property
    def predicate_bits(self) -> list[int]:
        return [r.pos for r in self.bit_results if r.predicate_changed]

    @property
    def operand_bits(self) -> list[int]:
        return [
            r.pos
            for r in self.bit_results
            if r.operand_changed and not r.mnemonic_changed and not r.predicate_changed
        ]


def probe_bit(insn: Instruction, pos: int, base: DisasmResult, arch: str = "SM100") -> BitProbeResult:
    """Flip a single bit and compare with base disassembly."""
    flipped = insn.copy()
    flipped.flip_bit(pos)

    try:
        result = disassemble(flipped, arch=arch)
    except Exception as e:
        return BitProbeResult(
            pos=pos,
            original_asm=base.full,
            flipped_asm="",
            changed=True,
            mnemonic_changed=False,
            predicate_changed=False,
            modifier_diff=[],
            operand_changed=False,
            error=str(e),
        )

    changed = result.full != base.full
    mnemonic_changed = result.mnemonic != base.mnemonic
    predicate_changed = result.predicate != base.predicate

    # Compute modifier diff
    orig_mods = set(base.modifiers)
    new_mods = set(result.modifiers)
    added = new_mods - orig_mods
    removed = orig_mods - new_mods
    modifier_diff = [f"+{m}" for m in sorted(added)] + [f"-{m}" for m in sorted(removed)]

    operand_changed = result.operands != base.operands

    return BitProbeResult(
        pos=pos,
        original_asm=base.full,
        flipped_asm=result.full,
        changed=changed,
        mnemonic_changed=mnemonic_changed,
        predicate_changed=predicate_changed,
        modifier_diff=modifier_diff,
        operand_changed=operand_changed,
    )


def probe_all_bits(insn: Instruction, arch: str = "SM100") -> ProbeReport:
    """Probe all 128 bits of an instruction."""
    base = disassemble(insn, arch=arch)
    report = ProbeReport(instruction=insn, arch=arch, base_disasm=base)

    for pos in range(128):
        result = probe_bit(insn, pos, base, arch=arch)
        report.bit_results.append(result)

    report.groups = _infer_groups(report)
    return report


def probe_range(insn: Instruction, lo: int, hi: int, arch: str = "SM100") -> ProbeReport:
    """Probe a range of bits [lo, hi] inclusive."""
    base = disassemble(insn, arch=arch)
    report = ProbeReport(instruction=insn, arch=arch, base_disasm=base)

    for pos in range(lo, hi + 1):
        result = probe_bit(insn, pos, base, arch=arch)
        report.bit_results.append(result)

    return report


def _infer_groups(report: ProbeReport) -> list[BitFieldGroup]:
    """Infer bitfield groups from probe results using simple heuristics."""
    groups: list[BitFieldGroup] = []

    def _category(r: BitProbeResult) -> str:
        if r.error:
            return "error"
        if r.mnemonic_changed:
            return "opcode"
        if r.predicate_changed:
            return "predicate"
        if r.modifier_diff:
            return "modifier"
        if r.operand_changed:
            return "operand"
        if not r.changed:
            return "unused"
        return "unknown"

    prev_cat = None
    group_start = 0

    for r in report.bit_results:
        cat = _category(r)
        if cat != prev_cat:
            if prev_cat is not None:
                groups.append(BitFieldGroup(
                    lo=group_start,
                    hi=r.pos - 1,
                    label=prev_cat,
                    category=prev_cat,
                ))
            group_start = r.pos
            prev_cat = cat

    if prev_cat is not None:
        groups.append(BitFieldGroup(
            lo=group_start,
            hi=report.bit_results[-1].pos,
            label=prev_cat,
            category=prev_cat,
        ))

    return groups
