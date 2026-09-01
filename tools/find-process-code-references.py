"""Find x86 relative CALL/JMP and absolute references in a live process module."""

from __future__ import annotations

import argparse
import ctypes
import struct
from ctypes import wintypes


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--base", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--target", action="append", type=lambda value: int(value, 0), required=True)
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
        data = buffer.raw[: transferred.value]

        for target in args.target:
            print(f"target=0x{target:08X}")
            for offset in range(0, max(0, len(data) - 4)):
                opcode = data[offset]
                if opcode in (0xE8, 0xE9):
                    displacement = struct.unpack_from("<i", data, offset + 1)[0]
                    destination = args.base + offset + 5 + displacement
                    if destination == target:
                        kind = "call" if opcode == 0xE8 else "jmp"
                        print(f"  {kind} 0x{args.base + offset:08X}")

            needle = struct.pack("<I", target)
            start = 0
            while True:
                offset = data.find(needle, start)
                if offset < 0:
                    break
                print(f"  absolute 0x{args.base + offset:08X}")
                start = offset + 1
    finally:
        kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
