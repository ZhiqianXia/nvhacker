"""NV instruction model — 128-bit binary encoding."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Instruction:
    """A single 128-bit NVIDIA GPU instruction."""

    _data: bytearray = field(default_factory=lambda: bytearray(16))

    # ── constructors ────────────────────────────────────────────────
    @classmethod
    def from_hex(cls, hex_str: str) -> "Instruction":
        """Create from hex string, e.g. '000000000000000000000000000003c0'."""
        hex_str = hex_str.replace(" ", "").replace("0x", "")
        if len(hex_str) != 32:
            raise ValueError(f"Expected 32 hex chars (128 bits), got {len(hex_str)}")
        return cls(_data=bytearray.fromhex(hex_str))

    @classmethod
    def from_bytes(cls, data: bytes | bytearray) -> "Instruction":
        if len(data) != 16:
            raise ValueError(f"Expected 16 bytes, got {len(data)}")
        return cls(_data=bytearray(data))

    @classmethod
    def zeros(cls) -> "Instruction":
        return cls()

    # ── properties ──────────────────────────────────────────────────
    @property
    def bytes(self) -> bytes:
        return bytes(self._data)

    @property
    def hex(self) -> str:
        return self._data.hex()

    @property
    def hex_spaced(self) -> str:
        """Hex with spaces every 4 bytes (32 bits)."""
        h = self.hex
        return " ".join(h[i : i + 8] for i in range(0, 32, 8))

    @property
    def bits_le(self) -> list[int]:
        """All 128 bits in little-endian bit order (bit 0 = LSB of byte 0)."""
        bits = []
        for byte_val in self._data:
            for bit_idx in range(8):
                bits.append((byte_val >> bit_idx) & 1)
        return bits

    # ── bit manipulation ────────────────────────────────────────────
    def get_bit(self, pos: int) -> int:
        """Get bit at position (0 = LSB of the instruction)."""
        if not 0 <= pos < 128:
            raise IndexError(f"Bit position {pos} out of range [0, 128)")
        byte_idx = pos // 8
        bit_idx = pos % 8
        return (self._data[byte_idx] >> bit_idx) & 1

    def set_bit(self, pos: int, val: int) -> None:
        """Set bit at position to 0 or 1."""
        if not 0 <= pos < 128:
            raise IndexError(f"Bit position {pos} out of range [0, 128)")
        byte_idx = pos // 8
        bit_idx = pos % 8
        if val:
            self._data[byte_idx] |= 1 << bit_idx
        else:
            self._data[byte_idx] &= ~(1 << bit_idx)

    def flip_bit(self, pos: int) -> None:
        """Toggle bit at position."""
        self.set_bit(pos, 1 - self.get_bit(pos))

    def get_field(self, lo: int, hi: int) -> int:
        """Extract integer value from bit range [lo, hi] inclusive."""
        if lo > hi:
            lo, hi = hi, lo
        val = 0
        for i, pos in enumerate(range(lo, hi + 1)):
            val |= self.get_bit(pos) << i
        return val

    def set_field(self, lo: int, hi: int, val: int) -> None:
        """Set integer value into bit range [lo, hi] inclusive."""
        if lo > hi:
            lo, hi = hi, lo
        width = hi - lo + 1
        if val < 0 or val >= (1 << width):
            raise ValueError(f"Value {val} does not fit in {width} bits")
        for i, pos in enumerate(range(lo, hi + 1)):
            self.set_bit(pos, (val >> i) & 1)

    def copy(self) -> "Instruction":
        return Instruction(_data=bytearray(self._data))

    def __repr__(self) -> str:
        return f"Instruction(0x{self.hex})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Instruction):
            return NotImplemented
        return self._data == other._data
