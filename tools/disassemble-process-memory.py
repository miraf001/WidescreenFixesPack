"""Disassemble x86 code directly from readable memory of a Windows process."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument(
        "--address", action="append", type=lambda value: int(value, 0), required=True
    )
    parser.add_argument("--size", type=lambda value: int(value, 0), default=0x200)
    args = parser.parse_args()
    if not 1 <= args.size <= 0x10000:
        raise RuntimeError("size must be between 1 and 0x10000 bytes.")

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

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    try:
        for address in args.address:
            buffer = ctypes.create_string_buffer(args.size)
            transferred = ctypes.c_size_t()
            if not kernel32.ReadProcessMemory(
                process,
                ctypes.c_void_p(address),
                buffer,
                args.size,
                ctypes.byref(transferred),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            code = buffer.raw[: transferred.value]
            print(f"address=0x{address:08X} size=0x{len(code):X}")
            for instruction in disassembler.disasm(code, address):
                encoded = instruction.bytes.hex(" ").ljust(29)
                print(
                    f"  {instruction.address:08X}  {encoded}  "
                    f"{instruction.mnemonic:<9} {instruction.op_str}"
                )
    finally:
        kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
