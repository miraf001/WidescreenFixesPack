"""Dump process memory around one or more addresses as bytes, dwords, and floats."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import struct


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--address", action="append", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--before", type=lambda value: int(value, 0), default=0x80)
    parser.add_argument("--after", type=lambda value: int(value, 0), default=0x100)
    args = parser.parse_args()
    if args.before < 0 or args.after <= 0 or args.before + args.after > 0x10000:
        raise RuntimeError("Invalid dump range (maximum total size is 0x10000 bytes).")

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
        for requested_address in args.address:
            start = requested_address - args.before
            size = args.before + args.after
            buffer = ctypes.create_string_buffer(size)
            transferred = ctypes.c_size_t()
            if not kernel32.ReadProcessMemory(
                process,
                ctypes.c_void_p(start),
                buffer,
                size,
                ctypes.byref(transferred),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            data = buffer.raw[: transferred.value]
            print(
                f"address=0x{requested_address:08X} range=0x{start:08X}-"
                f"0x{start + len(data):08X} marker=+0x{args.before:X}"
            )
            for offset in range(0, len(data), 16):
                row = data[offset : offset + 16]
                hex_bytes = " ".join(f"{byte:02X}" for byte in row).ljust(47)
                ascii_text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in row)
                padded = row.ljust(16, b"\0")
                dwords = " ".join(f"{value:08X}" for value in struct.unpack("<4I", padded))
                floats = " ".join(f"{value:10.4g}" for value in struct.unpack("<4f", padded))
                marker = " >" if offset <= args.before < offset + 16 else "  "
                print(
                    f"{marker} {start + offset:08X}  {hex_bytes}  {ascii_text:<16}  "
                    f"{dwords}  {floats}"
                )
    finally:
        kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
