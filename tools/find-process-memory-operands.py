"""Find x86 instructions using selected memory displacements in a live process."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_MEM


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--base", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True)
    parser.add_argument(
        "--displacement",
        action="append",
        type=lambda value: int(value, 0),
        required=True,
    )
    args = parser.parse_args()

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

    targets = set(args.displacement)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    disassembler.skipdata = True
    for instruction in disassembler.disasm(code, args.base):
        if instruction.id == 0:
            continue
        matches = sorted(
            {
                operand.mem.disp
                for operand in instruction.operands
                if operand.type == CS_OP_MEM and operand.mem.disp in targets
            }
        )
        if matches:
            displacements = ",".join(f"0x{value:X}" for value in matches)
            print(
                f"0x{instruction.address:08X} [{displacements}] "
                f"{instruction.mnemonic} {instruction.op_str}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
