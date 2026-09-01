"""Find x86 instructions using selected immediates/displacements in memory."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--base", type=number, required=True)
    parser.add_argument("--size", type=number, required=True)
    parser.add_argument("--immediate", action="append", type=number)
    parser.add_argument(
        "--displacement",
        action="append",
        type=number,
        help="Memory-operand displacement to find (repeatable)",
    )
    parser.add_argument(
        "--mnemonic",
        action="append",
        help="Optional instruction mnemonic filter (repeatable)",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON output path")
    args = parser.parse_args()
    if not args.immediate and not args.displacement:
        parser.error("at least one --immediate or --displacement is required")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, args.pid
    )
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer = ctypes.create_string_buffer(args.size)
        transferred = ctypes.c_size_t()
        if not kernel32.ReadProcessMemory(
            process,
            ctypes.c_void_p(args.base),
            buffer,
            args.size,
            ctypes.byref(transferred),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        code = buffer.raw[: transferred.value]
    finally:
        kernel32.CloseHandle(process)

    immediate_targets = {
        value & 0xFFFFFFFF for value in (args.immediate or [])
    }
    displacement_targets = {
        value & 0xFFFFFFFF for value in (args.displacement or [])
    }
    mnemonics = {value.lower() for value in args.mnemonic} if args.mnemonic else None
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    disassembler.skipdata = True
    rows = []
    for instruction in disassembler.disasm(code, args.base):
        if instruction.id == 0:
            continue
        if mnemonics is not None and instruction.mnemonic.lower() not in mnemonics:
            continue
        immediate_matches = sorted(
            {
                operand.imm & 0xFFFFFFFF
                for operand in instruction.operands
                if operand.type == CS_OP_IMM
                and (operand.imm & 0xFFFFFFFF) in immediate_targets
            }
        )
        displacement_matches = sorted(
            {
                operand.mem.disp & 0xFFFFFFFF
                for operand in instruction.operands
                if operand.type == CS_OP_MEM
                and (operand.mem.disp & 0xFFFFFFFF) in displacement_targets
            }
        )
        if not immediate_matches and not displacement_matches:
            continue
        labels = [f"imm=0x{value:X}" for value in immediate_matches]
        labels.extend(f"disp=0x{value:X}" for value in displacement_matches)
        values = ",".join(labels)
        encoded = instruction.bytes.hex(" ").ljust(29)
        rows.append(
            {
                "address": instruction.address,
                "immediates": immediate_matches,
                "displacements": displacement_matches,
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "opStr": instruction.op_str,
            }
        )
        print(
            f"0x{instruction.address:08X} [{values}] {encoded} "
            f"{instruction.mnemonic} {instruction.op_str}"
        )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
