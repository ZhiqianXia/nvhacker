"""Wrapper around nvdisasm for disassembling raw instruction binaries."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from .instruction import Instruction

# Search order for nvdisasm
_NVDISASM_SEARCH = [
    "/usr/local/cuda/bin/nvdisasm",
    "/usr/local/cuda-13.2/bin/nvdisasm",
    "/usr/local/cuda-13/bin/nvdisasm",
]


def _find_nvdisasm() -> str:
    # prefer newest CUDA toolkit first
    for path in _NVDISASM_SEARCH:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    found = shutil.which("nvdisasm")
    if found:
        return found
    raise FileNotFoundError(
        "nvdisasm not found. Install CUDA Toolkit or set NVDISASM_PATH."
    )


_nvdisasm_path: Optional[str] = None


def get_nvdisasm() -> str:
    global _nvdisasm_path
    if _nvdisasm_path is None:
        _nvdisasm_path = os.environ.get("NVDISASM_PATH") or _find_nvdisasm()
    return _nvdisasm_path


@dataclass
class DisasmResult:
    """Result of a single disassembly."""

    asm: str  # raw assembly text from nvdisasm
    mnemonic: str  # opcode mnemonic, e.g. "FFMA"
    modifiers: list[str]  # modifier tokens, e.g. [".FTZ", ".SAT"]
    operands: str  # operand string
    raw: str  # full raw line
    predicate: str = ""  # e.g. "@P6", "@!PT"

    @property
    def full(self) -> str:
        """Predicate + mnemonic + modifiers + operands."""
        mods = "".join(self.modifiers)
        pred = f"{self.predicate} " if self.predicate else ""
        return f"{pred}{self.mnemonic}{mods} {self.operands}".strip()


_ASM_LINE_RE = re.compile(
    r"\s*/\*\s*[0-9a-fA-F]+\s*\*/\s+"  # offset comment (with leading whitespace)
    r"(.*?)"  # instruction
    r"\s*;"  # trailing semicolon
    r"(?:\s*/\*.*?\*/)?"  # optional hex encoding comment
    r"\s*$"
)

_PRED_RE = re.compile(r"^(@!?P[0-7T])\s+")

_MNEMONIC_RE = re.compile(
    r"^([A-Z][A-Z0-9_]*)"  # base mnemonic
    r"((?:\.[A-Z0-9_.]+)*)"  # dot-prefixed modifiers
    r"(?:\s+(.*))?$"  # operands
)


def _parse_asm_line(line: str) -> Optional[DisasmResult]:
    """Parse one nvdisasm output line into a DisasmResult."""
    m = _ASM_LINE_RE.match(line)
    if not m:
        return None
    instr_text = m.group(1).strip()
    predicate = ""
    pm = _PRED_RE.match(instr_text)
    if pm:
        predicate = pm.group(1)
        instr_text = instr_text[pm.end():]
    mm = _MNEMONIC_RE.match(instr_text)
    if not mm:
        return DisasmResult(
            asm=instr_text, mnemonic=instr_text, modifiers=[], operands="",
            raw=line, predicate=predicate,
        )
    mnemonic = mm.group(1)
    mod_str = mm.group(2) or ""
    operands = mm.group(3) or ""
    modifiers = [tok for tok in mod_str.split(".") if tok]
    modifiers = [f".{tok}" for tok in modifiers]
    return DisasmResult(
        asm=instr_text,
        mnemonic=mnemonic,
        modifiers=modifiers,
        operands=operands,
        raw=line,
        predicate=predicate,
    )


def disassemble(
    insn: Instruction,
    arch: str = "SM100",
    nvdisasm: Optional[str] = None,
) -> DisasmResult:
    """Disassemble a single 128-bit instruction.

    Returns a DisasmResult with parsed fields.
    Raises subprocess.CalledProcessError on nvdisasm failure.
    """
    nvdisasm = nvdisasm or get_nvdisasm()
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(insn.bytes)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [nvdisasm, "-b", arch, "-hex", tmp_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
    finally:
        os.unlink(tmp_path)

    if result.returncode != 0:
        raise RuntimeError(
            f"nvdisasm failed (rc={result.returncode}): {result.stderr.strip()}"
        )

    for line in result.stdout.splitlines():
        parsed = _parse_asm_line(line)
        if parsed:
            return parsed

    return DisasmResult(
        asm=result.stdout.strip(),
        mnemonic="???",
        modifiers=[],
        operands="",
        raw=result.stdout.strip(),
    )


def disassemble_raw(
    data: bytes,
    arch: str = "SM100",
    nvdisasm: Optional[str] = None,
) -> str:
    """Disassemble raw bytes and return full nvdisasm output."""
    nvdisasm = nvdisasm or get_nvdisasm()
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        tmp_path = f.name

    try:
        result = subprocess.run(
            [nvdisasm, "-b", arch, "-hex", tmp_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
    finally:
        os.unlink(tmp_path)

    if result.returncode != 0:
        raise RuntimeError(
            f"nvdisasm failed (rc={result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout
