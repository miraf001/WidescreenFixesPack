"""Sweep one PDB-resolved float in a running process and freeze it with F6."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import time


SYMOPT_CASE_INSENSITIVE = 0x00000001
SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEFERRED_LOADS = 0x00000004
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
VK_F6 = 0x75
VK_F7 = 0x76


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_uint64 * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_uint64),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_uint64),
        ("Address", ctypes.c_uint64),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", wintypes.WCHAR * 1),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--base", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--symbol", required=True)
    parser.add_argument("--values", type=float, nargs="+", required=True)
    parser.add_argument("--interval-ms", type=int, default=150)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()

    if not 50 <= args.interval_ms <= 5000:
        raise RuntimeError("interval-ms must be between 50 and 5000.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    symbol_process = kernel32.GetCurrentProcess()

    dbghelp.SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS)
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymInitializeW.restype = wintypes.BOOL
    dbghelp.SymLoadModuleExW.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
        ctypes.c_uint64, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
    ]
    dbghelp.SymLoadModuleExW.restype = ctypes.c_uint64
    dbghelp.SymFromNameW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, ctypes.POINTER(SYMBOL_INFOW)
    ]
    dbghelp.SymFromNameW.restype = wintypes.BOOL
    dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    if not dbghelp.SymInitializeW(symbol_process, None, False):
        raise ctypes.WinError(ctypes.get_last_error())

    target_process = None
    original_value = None
    frozen = False
    try:
        loaded_base = dbghelp.SymLoadModuleExW(
            symbol_process, None, args.image, None, args.base, args.size, None, 0
        )
        if not loaded_base:
            raise ctypes.WinError(ctypes.get_last_error())

        max_name = 1024
        storage = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + (max_name * 2))
        symbol = ctypes.cast(storage, ctypes.POINTER(SYMBOL_INFOW)).contents
        symbol.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
        symbol.MaxNameLen = max_name
        if not dbghelp.SymFromNameW(symbol_process, args.symbol, ctypes.byref(symbol)):
            raise ctypes.WinError(ctypes.get_last_error())
        address = int(symbol.Address)

        target_process = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            False,
            args.pid,
        )
        if not target_process:
            raise ctypes.WinError(ctypes.get_last_error())

        def read_float() -> float:
            value = ctypes.c_float()
            transferred = ctypes.c_size_t()
            if not kernel32.ReadProcessMemory(
                target_process, ctypes.c_void_p(address), ctypes.byref(value),
                ctypes.sizeof(value), ctypes.byref(transferred)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            return float(value.value)

        def write_float(number: float) -> None:
            value = ctypes.c_float(number)
            transferred = ctypes.c_size_t()
            if not kernel32.WriteProcessMemory(
                target_process, ctypes.c_void_p(address), ctypes.byref(value),
                ctypes.sizeof(value), ctypes.byref(transferred)
            ):
                raise ctypes.WinError(ctypes.get_last_error())

        original_value = read_float()
        deadline = time.monotonic() + args.timeout_seconds
        index = 0
        print(
            f"Sweeping {args.symbol} at 0x{address:08X}; original={original_value:g}. "
            "F6 freezes the current value, F7 restores the original.",
            flush=True,
        )
        while time.monotonic() < deadline:
            current = args.values[index]
            write_float(current)
            step_deadline = time.monotonic() + (args.interval_ms / 1000.0)
            while time.monotonic() < step_deadline:
                if user32.GetAsyncKeyState(VK_F6) & 1:
                    frozen = True
                    print(f"Frozen: {args.symbol}={current:g}", flush=True)
                    return 0
                if user32.GetAsyncKeyState(VK_F7) & 1:
                    write_float(original_value)
                    print(f"Restored: {args.symbol}={original_value:g}", flush=True)
                    return 0
                time.sleep(0.005)
            index = (index + 1) % len(args.values)

        print("Sweep timed out; restoring the original value.", flush=True)
        return 2
    finally:
        if target_process:
            if original_value is not None and not frozen:
                value = ctypes.c_float(original_value)
                transferred = ctypes.c_size_t()
                kernel32.WriteProcessMemory(
                    target_process, ctypes.c_void_p(address), ctypes.byref(value),
                    ctypes.sizeof(value), ctypes.byref(transferred)
                )
            kernel32.CloseHandle(target_process)
        dbghelp.SymCleanup(symbol_process)


if __name__ == "__main__":
    raise SystemExit(main())
