"""Write explicitly addressed float values in a Windows process and verify them."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes


PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400


def parse_assignment(value: str) -> tuple[int, float]:
    try:
        address_text, number_text = value.split("=", 1)
        address = int(address_text, 0)
        number = float(number_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "assignment must use ADDRESS=FLOAT, for example 0x12345678=300"
        ) from exc
    if not 0x10000 <= address <= 0x7FFFFFFB:
        raise argparse.ArgumentTypeError(f"address is outside the 32-bit user range: 0x{address:X}")
    return address, number


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument(
        "--write",
        action="append",
        type=parse_assignment,
        required=True,
        metavar="ADDRESS=FLOAT",
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Perform the writes. Without this switch the command is a dry run.",
    )
    args = parser.parse_args()

    addresses = [address for address, _ in args.write]
    if len(addresses) != len(set(addresses)):
        raise RuntimeError("Each address may be specified only once.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.LPVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPCVOID,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    if args.commit:
        access |= PROCESS_VM_OPERATION | PROCESS_VM_WRITE
    process = kernel32.OpenProcess(access, False, args.pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    def read_float(address: int) -> float:
        result = ctypes.c_float()
        transferred = ctypes.c_size_t()
        if not kernel32.ReadProcessMemory(
            process,
            ctypes.c_void_p(address),
            ctypes.byref(result),
            ctypes.sizeof(result),
            ctypes.byref(transferred),
        ) or transferred.value != ctypes.sizeof(result):
            raise ctypes.WinError(ctypes.get_last_error())
        return float(result.value)

    def write_float(address: int, number: float) -> None:
        value = ctypes.c_float(number)
        transferred = ctypes.c_size_t()
        if not kernel32.WriteProcessMemory(
            process,
            ctypes.c_void_p(address),
            ctypes.byref(value),
            ctypes.sizeof(value),
            ctypes.byref(transferred),
        ) or transferred.value != ctypes.sizeof(value):
            raise ctypes.WinError(ctypes.get_last_error())

    try:
        originals = {address: read_float(address) for address in addresses}
        for address, number in args.write:
            print(f"0x{address:08X}: {originals[address]:g} -> {number:g}")

        if not args.commit:
            print("Dry run only; add --commit to write.")
            return 0

        for address, number in args.write:
            write_float(address, number)
        for address, number in args.write:
            actual = read_float(address)
            if actual != ctypes.c_float(number).value:
                raise RuntimeError(
                    f"verification failed at 0x{address:08X}: expected {number:g}, got {actual:g}"
                )
            print(f"verified 0x{address:08X}={actual:g}")
    finally:
        kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
