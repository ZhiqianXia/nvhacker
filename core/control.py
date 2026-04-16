"""Decode NVIDIA per-instruction scheduling control fields.

This module provides a small, architecture-aware decoder for control bits such as
stall / yield / barriers / reuse. The bit layout can vary by architecture, so we
keep profiles explicit and easy to adjust.
"""

from __future__ import annotations

from dataclasses import dataclass

from .instruction import Instruction


@dataclass(frozen=True)
class ControlFields:
    stall: int
    yield_flag: int
    write_barrier: int
    read_barrier: int
    barrier_mask: int
    reuse: int
    unused: int

    @property
    def barrier_mask_bits(self) -> str:
        return f"{self.barrier_mask:06b}"

    @property
    def reuse_bits(self) -> str:
        return f"{self.reuse:04b}"

    @property
    def unused_bits(self) -> str:
        return f"{self.unused:03b}"


# Common Volta+ style control-word split (total 24 bits):
# [base+0 : base+3 ] stall
# [base+4 : base+4 ] yield
# [base+5 : base+7 ] write barrier
# [base+8 : base+10] read barrier
# [base+11: base+16] barrier mask
# [base+17: base+20] reuse
# [base+21: base+23] unused/reserved
#
# For SM80/SM90/SM100 this profile is a practical default and can be tuned later.
_ARCH_BASE_BIT = {
    "SM75": 104,
    "SM80": 104,
    "SM86": 104,
    "SM89": 104,
    "SM90": 104,
    "SM100": 104,
}


def control_bit_range(arch: str = "SM100") -> tuple[int, int]:
    """Return inclusive control-bit range for the architecture profile."""
    base = _ARCH_BASE_BIT.get(arch.upper(), 104)
    if base + 23 > 127:
        base = 127 - 23
    return base, base + 23


def decode_control_fields(insn: Instruction, arch: str = "SM100") -> ControlFields:
    base, _ = control_bit_range(arch)
    return ControlFields(
        stall=insn.get_field(base + 0, base + 3),
        yield_flag=insn.get_field(base + 4, base + 4),
        write_barrier=insn.get_field(base + 5, base + 7),
        read_barrier=insn.get_field(base + 8, base + 10),
        barrier_mask=insn.get_field(base + 11, base + 16),
        reuse=insn.get_field(base + 17, base + 20),
        unused=insn.get_field(base + 21, base + 23),
    )
