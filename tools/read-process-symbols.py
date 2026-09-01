"""Resolve PDB symbols for a loaded module and read float values from a process."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes


SYMOPT_CASE_INSENSITIVE = 0x00000001
SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEFERRED_LOADS = 0x00000004
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


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


def resolve_symbol(dbghelp, symbol_process, name: str) -> tuple[int, str]:
    max_name = 1024
    storage = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + (max_name * 2))
    info = ctypes.cast(storage, ctypes.POINTER(SYMBOL_INFOW)).contents
    info.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
    info.MaxNameLen = max_name
    if not dbghelp.SymFromNameW(symbol_process, name, ctypes.byref(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    resolved_name = ctypes.wstring_at(ctypes.addressof(info) + SYMBOL_INFOW.Name.offset, info.NameLen)
    return int(info.Address), resolved_name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--base", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True)
    parser.add_argument("symbols", nargs="+")
    args = parser.parse_args()

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    symbol_process = kernel32.GetCurrentProcess()

    dbghelp.SymSetOptions(
        SYMOPT_CASE_INSENSITIVE | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS
    )
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymInitializeW.restype = wintypes.BOOL
    dbghelp.SymLoadModuleExW.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_uint64,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    dbghelp.SymLoadModuleExW.restype = ctypes.c_uint64
    dbghelp.SymFromNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        ctypes.POINTER(SYMBOL_INFOW),
    ]
    dbghelp.SymFromNameW.restype = wintypes.BOOL
    dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]

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
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    if not dbghelp.SymInitializeW(symbol_process, None, False):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        loaded_base = dbghelp.SymLoadModuleExW(
            symbol_process, None, args.image, None, args.base, args.size, None, 0
        )
        if not loaded_base:
            raise ctypes.WinError(ctypes.get_last_error())

        target_process = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, args.pid
        )
        if not target_process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            for requested_name in args.symbols:
                address, resolved_name = resolve_symbol(dbghelp, symbol_process, requested_name)
                value = ctypes.c_float()
                bytes_read = ctypes.c_size_t()
                if not kernel32.ReadProcessMemory(
                    target_process,
                    ctypes.c_void_p(address),
                    ctypes.byref(value),
                    ctypes.sizeof(value),
                    ctypes.byref(bytes_read),
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                print(f"{resolved_name} address=0x{address:08X} float={value.value:.9g}")
        finally:
            kernel32.CloseHandle(target_process)
    finally:
        dbghelp.SymCleanup(symbol_process)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
