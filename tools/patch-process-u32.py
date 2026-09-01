"""Compare-and-write selected 32-bit values in a Windows process.

Every write includes the value expected at the address. All expectations are
checked before anything is changed, which makes runtime experiments repeatable
and avoids applying offsets to a stale game object.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass


PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400


@dataclass(frozen=True)
class Patch:
    address: int
    expected: int
    value: int


def parse_number(value: str) -> int:
    return int(value, 0)


def parse_patch(specification: str) -> Patch:
    try:
        address_text, values = specification.split("=", 1)
        expected_text, value_text = values.split(":", 1)
        return Patch(
            parse_number(address_text),
            parse_number(expected_text) & 0xFFFFFFFF,
            parse_number(value_text) & 0xFFFFFFFF,
        )
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected ADDRESS=EXPECTED:VALUE (numbers may use the 0x prefix)"
        ) from error


def read_u32(kernel32, process, address: int) -> int:
    value = wintypes.DWORD()
    transferred = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        ctypes.byref(value),
        ctypes.sizeof(value),
        ctypes.byref(transferred),
    ) or transferred.value != ctypes.sizeof(value):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(value.value)


def write_u32(kernel32, process, address: int, value: int) -> None:
    native_value = wintypes.DWORD(value)
    transferred = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(
        process,
        ctypes.c_void_p(address),
        ctypes.byref(native_value),
        ctypes.sizeof(native_value),
        ctypes.byref(transferred),
    ) or transferred.value != ctypes.sizeof(native_value):
        raise ctypes.WinError(ctypes.get_last_error())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Atomically validate and patch aligned 32-bit process fields."
    )
    parser.add_argument("--pid", type=parse_number, required=True)
    parser.add_argument(
        "--write",
        type=parse_patch,
        action="append",
        required=True,
        metavar="ADDRESS=EXPECTED:VALUE",
    )
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

    access = (
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
    )
    process = kernel32.OpenProcess(access, False, args.pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        originals: list[int] = []
        for patch in args.write:
            actual = read_u32(kernel32, process, patch.address)
            if actual != patch.expected:
                raise RuntimeError(
                    f"0x{patch.address:08X}: expected 0x{patch.expected:08X}, "
                    f"found 0x{actual:08X}; nothing was changed"
                )
            originals.append(actual)

        completed = 0
        try:
            for patch in args.write:
                write_u32(kernel32, process, patch.address, patch.value)
                completed += 1
        except Exception:
            for patch, original in zip(args.write[:completed], originals[:completed]):
                write_u32(kernel32, process, patch.address, original)
            raise

        for patch in args.write:
            actual = read_u32(kernel32, process, patch.address)
            if actual != patch.value:
                raise RuntimeError(
                    f"0x{patch.address:08X}: verification failed; "
                    f"read back 0x{actual:08X}"
                )
            print(
                f"0x{patch.address:08X}: "
                f"0x{patch.expected:08X} -> 0x{patch.value:08X}"
            )
    finally:
        kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
