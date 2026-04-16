#!/usr/bin/env python3
"""NVHacker — NVIDIA instruction binary explorer.

Usage:
    python -m nvhacker                          # start with zero instruction
    python -m nvhacker <hex>                    # start with hex-encoded instruction
    python -m nvhacker <hex> --arch SM90        # specify architecture
    python -m nvhacker --probe <hex>            # CLI probe mode (no TUI)
"""

import argparse
import os
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NVHacker — NVIDIA instruction binary explorer"
    )
    parser.add_argument(
        "hex",
        nargs="?",
        default="",
        help="128-bit instruction as 32 hex chars",
    )
    parser.add_argument(
        "--arch",
        default="SM100",
        help="GPU architecture (default: SM100)",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Run probe in CLI mode (no TUI)",
    )
    parser.add_argument(
        "--nvdisasm",
        default=None,
        help="Path to nvdisasm binary",
    )
    parser.add_argument("--elf", default="", help="Input ELF file path")
    parser.add_argument("--section", default="", help="ELF section name (e.g. .text.foo)")
    parser.add_argument("--index", type=int, default=-1, help="Instruction index in section")
    parser.add_argument(
        "--list-sections",
        action="store_true",
        help="List executable ELF sections",
    )
    parser.add_argument(
        "--list-insn",
        action="store_true",
        help="List instructions from selected section",
    )
    parser.add_argument("--limit", type=int, default=16, help="List/probe output limit")
    parser.add_argument(
        "--flip-bit",
        action="append",
        type=int,
        default=[],
        help="Bit index [0..127] to flip (repeatable)",
    )
    parser.add_argument("--out-elf", default="", help="Output patched ELF path")
    parser.add_argument(
        "--run-cmd",
        default="",
        help="Optional command to run after patch; use {elf} placeholder",
    )

    args = parser.parse_args()

    if args.nvdisasm:
        os.environ["NVDISASM_PATH"] = args.nvdisasm

    if args.elf:
        _handle_elf_mode(args)
        return

    if args.probe:
        _cli_probe(args.hex, args.arch)
    else:
        _run_tui(args.hex, args.arch)


def _run_tui(hex_str: str, arch: str) -> None:
    from .tui.app import NVHackerApp

    app = NVHackerApp(hex_str=hex_str, arch=arch)
    app.run()


def _cli_probe(hex_str: str, arch: str) -> None:
    from .core.bitfield import probe_all_bits
    from .core.instruction import Instruction

    if not hex_str:
        print("Error: hex argument required for --probe mode", file=sys.stderr)
        sys.exit(1)

    insn = Instruction.from_hex(hex_str)
    print(f"Instruction: 0x{insn.hex}")
    print(f"Architecture: {arch}")
    print(f"Probing all 128 bits...\n")

    report = probe_all_bits(insn, arch=arch)

    print(f"Base disassembly: {report.base_disasm.full}")
    print(f"  Mnemonic:   {report.base_disasm.mnemonic}")
    print(f"  Modifiers:  {report.base_disasm.modifiers}")
    print(f"  Operands:   {report.base_disasm.operands}")
    print()

    print(f"Changed bits: {len(report.changed_bits)}/128")
    print(f"  Opcode bits:   {report.opcode_bits}")
    print(f"  Modifier bits: {report.modifier_bits}")
    print(f"  Operand bits:  {report.operand_bits}")
    print()

    print("Field groups:")
    for g in report.groups:
        print(f"  [{g.lo:3d}:{g.hi:3d}] {g.category:<10s} {g.label}")
    print()

    print("Detailed bit changes:")
    for r in report.bit_results:
        if r.changed:
            mod = " ".join(r.modifier_diff) if r.modifier_diff else ""
            flag = ""
            if r.mnemonic_changed:
                flag = " [OPCODE]"
            elif r.modifier_diff:
                flag = " [MODIFIER]"
            elif r.operand_changed:
                flag = " [OPERAND]"
            print(f"  bit {r.pos:3d}: {r.flipped_asm}{flag} {mod}")


def _handle_elf_mode(args: argparse.Namespace) -> None:
    from .core.disassembler import disassemble
    from .core.elf_patch import (
        flip_bits_in_instruction,
        list_executable_sections,
        read_instruction,
        select_section,
    )
    from .core.instruction import Instruction

    elf_path = args.elf
    if not os.path.exists(elf_path):
        print(f"Error: ELF not found: {elf_path}", file=sys.stderr)
        sys.exit(1)

    if args.list_sections:
        sections = list_executable_sections(elf_path)
        print(f"ELF: {elf_path}")
        print("Executable sections:")
        for sec in sections:
            print(
                f"  {sec.name:<28s} off=0x{sec.offset:06x} size=0x{sec.size:06x} "
                f"insn={sec.instruction_count:5d} flags={sec.flags}"
            )
        return

    section_name = args.section or select_section(elf_path).name

    if args.list_insn:
        sec = select_section(elf_path, section_name)
        n = min(sec.instruction_count, max(1, args.limit))
        print(f"ELF: {elf_path}")
        print(f"Section: {sec.name} ({sec.instruction_count} instructions)")
        for idx in range(n):
            ref = read_instruction(elf_path, sec.name, idx)
            try:
                asm = disassemble(ref.instruction, arch=args.arch).full
            except Exception as e:
                asm = f"<disasm error: {e}>"
            print(f"  [{idx:4d}] pc=0x{ref.pc:06x} hex={ref.instruction.hex}  {asm}")
        return

    if args.index < 0:
        # List-first TUI flow: browse all instructions then click one to edit.
        from .tui.app import NVHackerApp

        app = NVHackerApp(
            hex_str="",
            arch=args.arch,
            elf_path=elf_path,
            elf_section=section_name,
            elf_index=-1,
            out_elf_path=args.out_elf or "",
            run_cmd=args.run_cmd or "",
        )
        app.run()
        return

    ref = read_instruction(elf_path, section_name, args.index)
    print(f"ELF: {elf_path}")
    print(f"Section: {ref.section.name}")
    print(f"Index: {ref.index}")
    print(f"PC: 0x{ref.pc:x}")
    print(f"File offset: 0x{ref.file_offset:x}")
    print(f"Instruction hex: {ref.instruction.hex}")
    try:
        base = disassemble(ref.instruction, arch=args.arch)
        print(f"Assembly: {base.full}")
    except Exception as e:
        print(f"Assembly: <disasm error: {e}>")

    # Launch TUI directly on selected ELF instruction if no patch request.
    if not args.flip_bit:
        from .tui.app import NVHackerApp

        app = NVHackerApp(
            hex_str=ref.instruction.hex,
            arch=args.arch,
            elf_path=elf_path,
            elf_section=ref.section.name,
            elf_index=ref.index,
            out_elf_path=args.out_elf or "",
            run_cmd=args.run_cmd or "",
        )
        app.run()
        return

    if not args.out_elf:
        print("Error: --out-elf is required when using --flip-bit", file=sys.stderr)
        sys.exit(1)

    patched = flip_bits_in_instruction(
        src_elf=elf_path,
        dst_elf=args.out_elf,
        section_name=ref.section.name,
        index=ref.index,
        bit_positions=args.flip_bit,
    )
    print(f"Patched ELF written: {args.out_elf}")
    print(f"Patched instruction: {patched.instruction.hex}")
    try:
        pdis = disassemble(patched.instruction, arch=args.arch)
        print(f"Patched assembly: {pdis.full}")
    except Exception as e:
        print(f"Patched assembly: <disasm error: {e}>")

    if args.run_cmd:
        cmd = args.run_cmd.replace("{elf}", args.out_elf)
        print(f"Running: {cmd}")
        rc = subprocess.run(cmd, shell=True, check=False).returncode
        print(f"Command exit code: {rc}")


if __name__ == "__main__":
    main()
