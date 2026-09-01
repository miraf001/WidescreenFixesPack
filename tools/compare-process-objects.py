"""Compare aligned 32-bit fields of two objects in a live process."""

from __future__ import annotations

import argparse
import ctypes
import struct
from ctypes import wintypes


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def read_memory(kernel32, process, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    transferred = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(transferred),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[: transferred.value]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--left", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--right", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True)
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
        left = read_memory(kernel32, process, args.left, args.size)
        right = read_memory(kernel32, process, args.right, args.size)
    finally:
        kernel32.CloseHandle(process)

    for offset in range(0, min(len(left), len(right)) - 3, 4):
        left_value = struct.unpack_from("<I", left, offset)[0]
        right_value = struct.unpack_from("<I", right, offset)[0]
        marker = "=" if left_value == right_value else "!"
        print(
            f"+0x{offset:03X} {marker} "
            f"0x{left_value:08X} 0x{right_value:08X}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
