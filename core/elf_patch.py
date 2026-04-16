"""ELF instruction patching utilities.

This module provides a lightweight workflow for:
1) locating executable text sections in an ELF binary,
2) reading one 128-bit instruction by index,
3) writing a modified instruction back into a copied ELF.
"""

from __future__ import annotations

import shutil
import subprocess
import re
from dataclasses import dataclass
from pathlib import Path

from .instruction import Instruction


@dataclass
class ElfSection:
    """Metadata for one ELF section."""

    index: int
    name: str
    addr: int
    offset: int
    size: int
    flags: str

    @property
    def instruction_count(self) -> int:
        return self.size // 16


@dataclass
class ElfInstructionRef:
    """Reference to one instruction in an ELF section."""

    elf_path: str
    section: ElfSection
    index: int
    file_offset: int
    instruction: Instruction

    @property
    def pc(self) -> int:
        return self.section.addr + self.index * 16


def _parse_hex_or_zero(value: str) -> int:
    value = value.strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value, 16)


def list_sections(elf_path: str) -> list[ElfSection]:
    """List ELF sections by parsing `readelf -W -S` output."""
    result = subprocess.run(
        ["readelf", "-W", "-S", elf_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"readelf failed: {result.stderr.strip()}")

    # Example line:
    # [12] .text.foo PROGBITS 0000000000000000 000700 000180 00 AX 3 8 128
    line_re = re.compile(
        r"^\s*\[\s*(\d+)\]\s+"  # section index
        r"(\S+)\s+"  # name
        r"\S+\s+"  # type
        r"([0-9a-fA-F]+)\s+"  # address
        r"([0-9a-fA-F]+)\s+"  # file offset
        r"([0-9a-fA-F]+)\s+"  # size
        r"\S+\s+"  # entry size
        r"(\S+)\s+"  # flags
        r"\d+\s+\d+\s+\d+\s*$"  # link/info/align
    )

    sections: list[ElfSection] = []
    for raw_line in result.stdout.splitlines():
        m = line_re.match(raw_line)
        if not m:
            continue

        sec_index = int(m.group(1))
        name = m.group(2)
        addr = _parse_hex_or_zero(m.group(3))
        off = _parse_hex_or_zero(m.group(4))
        size = _parse_hex_or_zero(m.group(5))
        flags = m.group(6)

        sections.append(
            ElfSection(
                index=sec_index,
                name=name,
                addr=addr,
                offset=off,
                size=size,
                flags=flags,
            )
        )

    if not sections:
        raise RuntimeError("Failed to parse ELF sections from readelf output")
    return sections


def list_executable_sections(elf_path: str) -> list[ElfSection]:
    """Return executable sections (flag contains X) with non-zero size."""
    sections = list_sections(elf_path)
    return [s for s in sections if "X" in s.flags and s.size > 0]


def select_section(elf_path: str, section_name: str | None = None) -> ElfSection:
    """Select a section by name or choose the first executable text section."""
    exec_secs = list_executable_sections(elf_path)
    if not exec_secs:
        raise RuntimeError("No executable sections found in ELF")

    if section_name:
        for sec in exec_secs:
            if sec.name == section_name:
                return sec
        names = ", ".join(sec.name for sec in exec_secs)
        raise ValueError(f"Section '{section_name}' not found. Available: {names}")

    # Prefer .text* by default
    for sec in exec_secs:
        if sec.name.startswith(".text"):
            return sec
    return exec_secs[0]


def read_instruction(elf_path: str, section_name: str, index: int) -> ElfInstructionRef:
    """Read one 128-bit instruction from section[index]."""
    sec = select_section(elf_path, section_name)
    if index < 0 or index >= sec.instruction_count:
        raise IndexError(
            f"Instruction index {index} out of range [0, {sec.instruction_count})"
        )

    file_offset = sec.offset + index * 16
    with open(elf_path, "rb") as f:
        f.seek(file_offset)
        raw = f.read(16)

    if len(raw) != 16:
        raise RuntimeError(
            f"Failed to read 16 bytes at file offset 0x{file_offset:x}"
        )

    return ElfInstructionRef(
        elf_path=elf_path,
        section=sec,
        index=index,
        file_offset=file_offset,
        instruction=Instruction.from_bytes(raw),
    )


def write_instruction(
    src_elf: str,
    dst_elf: str,
    section_name: str,
    index: int,
    instruction: Instruction,
) -> ElfInstructionRef:
    """Copy src ELF to dst ELF and overwrite one instruction in-place."""
    src = Path(src_elf)
    dst = Path(dst_elf)
    if src.resolve() == dst.resolve():
        raise ValueError("src_elf and dst_elf must be different to avoid destructive overwrite")

    shutil.copy2(src, dst)

    ref = read_instruction(str(dst), section_name, index)
    with open(dst, "r+b") as f:
        f.seek(ref.file_offset)
        f.write(instruction.bytes)

    return read_instruction(str(dst), section_name, index)


def flip_bits_in_instruction(
    src_elf: str,
    dst_elf: str,
    section_name: str,
    index: int,
    bit_positions: list[int],
) -> ElfInstructionRef:
    """Flip one or more bit positions in section[index], then write to dst ELF."""
    if not bit_positions:
        raise ValueError("bit_positions cannot be empty")

    ref = read_instruction(src_elf, section_name, index)
    patched = ref.instruction.copy()
    for pos in bit_positions:
        patched.flip_bit(pos)

    return write_instruction(src_elf, dst_elf, section_name, index, patched)
