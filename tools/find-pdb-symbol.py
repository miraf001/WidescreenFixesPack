"""Resolve wildcarded private PDB symbols for a PE image with Windows DbgHelp."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEFERRED_LOADS = 0x00000004
SYMOPT_LOAD_LINES = 0x00000010


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_ulonglong * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", ctypes.c_wchar * 1),
    ]


def parse_number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=parse_number, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--base", type=parse_number, required=True)
    parser.add_argument("--mask", default="*")
    args = parser.parse_args()

    image = args.image.resolve(strict=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
    dbghelp.SymSetOptions.restype = wintypes.DWORD
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymInitializeW.restype = wintypes.BOOL
    dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
    dbghelp.SymCleanup.restype = wintypes.BOOL
    dbghelp.SymLoadModuleExW.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_ulonglong,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong

    callback_type = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        ctypes.POINTER(SYMBOL_INFOW),
        wintypes.ULONG,
        ctypes.c_void_p,
    )
    dbghelp.SymEnumSymbolsW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_ulonglong,
        wintypes.LPCWSTR,
        callback_type,
        ctypes.c_void_p,
    ]
    dbghelp.SymEnumSymbolsW.restype = wintypes.BOOL

    process = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, args.pid
    )
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    initialized = False
    try:
        dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES)
        if not dbghelp.SymInitializeW(process, str(image.parent), False):
            raise ctypes.WinError(ctypes.get_last_error())
        initialized = True

        loaded_base = dbghelp.SymLoadModuleExW(
            process, None, str(image), None, args.base, 0, None, 0
        )
        if not loaded_base:
            raise ctypes.WinError(ctypes.get_last_error())

        matches: list[tuple[str, int, int]] = []

        @callback_type
        def collect(symbol, size, context):
            info = symbol.contents
            name_address = ctypes.addressof(info) + SYMBOL_INFOW.Name.offset
            name = ctypes.wstring_at(name_address, info.NameLen)
            matches.append((name, int(info.Address), int(info.Size)))
            return True

        if not dbghelp.SymEnumSymbolsW(process, loaded_base, args.mask, collect, None):
            error = ctypes.get_last_error()
            if error:
                raise ctypes.WinError(error)

        for name, address, size in sorted(matches):
            print(f"0x{address:08X} size=0x{size:X} {name}")
        return 0 if matches else 2
    finally:
        if initialized:
            dbghelp.SymCleanup(process)
        kernel32.CloseHandle(process)


if __name__ == "__main__":
    raise SystemExit(main())
