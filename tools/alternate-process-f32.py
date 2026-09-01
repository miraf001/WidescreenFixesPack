"""Temporarily alternate one 32-bit float in another Windows process."""

from __future__ import annotations

import argparse
import ctypes
import struct
import time
from ctypes import wintypes


PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400


def transfer(kernel32, function, process, address: int, buffer, size: int) -> None:
    transferred = ctypes.c_size_t()
    if not function(
        process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(transferred),
    ) or transferred.value != size:
        raise ctypes.WinError(ctypes.get_last_error())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--address", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--expected", type=float, required=True)
    parser.add_argument("--value-a", type=float, required=True)
    parser.add_argument("--value-b", type=float, required=True)
    parser.add_argument("--seconds", type=float, default=45.0)
    parser.add_argument("--interval-ms", type=float, default=16.667)
    args = parser.parse_args()

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = kernel32.ReadProcessMemory.argtypes
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE,
        False,
        args.pid,
    )
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    original = struct.pack("<f", args.expected)
    read_buffer = ctypes.create_string_buffer(4)
    try:
        transfer(
            kernel32,
            kernel32.ReadProcessMemory,
            process,
            args.address,
            read_buffer,
            4,
        )
        if read_buffer.raw != original:
            actual = struct.unpack("<f", read_buffer.raw)[0]
            raise RuntimeError(
                f"0x{args.address:08X}: expected {args.expected:g}, found {actual:g}"
            )

        values = (
            ctypes.create_string_buffer(struct.pack("<f", args.value_a)),
            ctypes.create_string_buffer(struct.pack("<f", args.value_b)),
        )
        print(
            f"Alternating 0x{args.address:08X} between {args.value_a:g} and "
            f"{args.value_b:g} for {args.seconds:g}s.",
            flush=True,
        )
        deadline = time.perf_counter() + args.seconds
        next_tick = time.perf_counter()
        index = 0
        while time.perf_counter() < deadline:
            transfer(
                kernel32,
                kernel32.WriteProcessMemory,
                process,
                args.address,
                values[index],
                4,
            )
            index ^= 1
            next_tick += args.interval_ms / 1000.0
            remaining = next_tick - time.perf_counter()
            if remaining > 0:
                time.sleep(remaining)
    finally:
        try:
            original_buffer = ctypes.create_string_buffer(original)
            transfer(
                kernel32,
                kernel32.WriteProcessMemory,
                process,
                args.address,
                original_buffer,
                4,
            )
            print(f"Restored 0x{args.address:08X} to {args.expected:g}.", flush=True)
        finally:
            kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
