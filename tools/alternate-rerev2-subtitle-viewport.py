"""Temporarily alternate the rendered TextVoice subtitle between both viewports."""

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


def read_bytes(kernel32, process, address: int, size: int) -> bytes:
    buffer = ctypes.create_string_buffer(size)
    transferred = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(transferred),
    ) or transferred.value != size:
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw


def write_bytes(kernel32, process, address: int, data: bytes) -> None:
    buffer = ctypes.create_string_buffer(data)
    transferred = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(
        process,
        ctypes.c_void_p(address),
        buffer,
        len(data),
        ctypes.byref(transferred),
    ) or transferred.value != len(data):
        raise ctypes.WinError(ctypes.get_last_error())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--globals", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--primary", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--clone", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--interval-ms", type=float, default=16.667)
    args = parser.parse_args()

    if args.seconds <= 0 or args.interval_ms <= 0:
        parser.error("--seconds and --interval-ms must be positive")

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

    access = (
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
    )
    process = kernel32.OpenProcess(access, False, args.pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    original = struct.pack("<II", args.primary, args.clone)
    try:
        actual = read_bytes(kernel32, process, args.globals, len(original))
        if actual != original:
            found_primary, found_clone = struct.unpack("<II", actual)
            raise RuntimeError(
                f"controller globals changed: expected "
                f"0x{args.primary:08X}/0x{args.clone:08X}, found "
                f"0x{found_primary:08X}/0x{found_clone:08X}"
            )

        # Keep gTextVoiceCloneController pointing at the visible primary. Then
        # one aligned pointer controls classification: primary means Left and
        # clone means Right. Only one 32-bit field changes during the loop.
        write_bytes(
            kernel32,
            process,
            args.globals,
            struct.pack("<II", args.primary, args.primary),
        )
        print(
            f"Alternating for {args.seconds:g}s every {args.interval_ms:g}ms; "
            "the original controller pair will be restored.",
            flush=True,
        )

        deadline = time.perf_counter() + args.seconds
        next_tick = time.perf_counter()
        show_right = False
        while time.perf_counter() < deadline:
            selected = args.clone if show_right else args.primary
            write_bytes(kernel32, process, args.globals, struct.pack("<I", selected))
            show_right = not show_right
            next_tick += args.interval_ms / 1000.0
            remaining = next_tick - time.perf_counter()
            if remaining > 0:
                time.sleep(remaining)
    finally:
        try:
            write_bytes(kernel32, process, args.globals, original)
            print("Restored the original controller pair.", flush=True)
        finally:
            kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
