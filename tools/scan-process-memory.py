"""Find text or raw byte patterns in readable memory of a Windows process."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
CHUNK_SIZE = 1024 * 1024


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


@dataclass(frozen=True)
class Region:
    base: int
    size: int
    allocation_base: int
    protect: int
    kind: int


def readable_regions(kernel32, process) -> list[Region]:
    regions: list[Region] = []
    address = 0
    maximum = 0x1_0000_0000
    info = MEMORY_BASIC_INFORMATION()
    while address < maximum:
        result = kernel32.VirtualQueryEx(
            process, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
        )
        if not result:
            break
        base = int(info.BaseAddress or 0)
        size = int(info.RegionSize)
        base_protect = int(info.Protect) & 0xFF
        if (
            info.State == MEM_COMMIT
            and base_protect in READABLE_PROTECTIONS
            and not (info.Protect & PAGE_GUARD)
            and not (info.Protect & PAGE_NOACCESS)
        ):
            regions.append(
                Region(
                    base=base,
                    size=size,
                    allocation_base=int(info.AllocationBase or 0),
                    protect=int(info.Protect),
                    kind=int(info.Type),
                )
            )
        next_address = base + size
        if next_address <= address:
            break
        address = next_address
    return regions


def scan_region(kernel32, process, region: Region, pattern: bytes) -> list[int]:
    hits: list[int] = []
    overlap = max(0, len(pattern) - 1)
    offset = 0
    carry = b""
    while offset < region.size:
        requested = min(CHUNK_SIZE, region.size - offset)
        buffer = ctypes.create_string_buffer(requested)
        transferred = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(
            process,
            ctypes.c_void_p(region.base + offset),
            buffer,
            requested,
            ctypes.byref(transferred),
        )
        if not ok and transferred.value == 0:
            offset += requested
            carry = b""
            continue
        data = carry + buffer.raw[: transferred.value]
        search_from = 0
        while True:
            index = data.find(pattern, search_from)
            if index < 0:
                break
            absolute = region.base + offset - len(carry) + index
            if not hits or hits[-1] != absolute:
                hits.append(absolute)
            search_from = index + 1
        carry = data[-overlap:] if overlap else b""
        offset += requested
    return hits


def scan(kernel32, process, regions: list[Region], pattern: bytes) -> list[tuple[int, Region]]:
    results: list[tuple[int, Region]] = []
    for region in regions:
        results.extend((address, region) for address in scan_region(kernel32, process, region, pattern))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--text", help="Text to search for as UTF-8 and UTF-16LE.")
    parser.add_argument("--hex", dest="hex_pattern", help="Raw hexadecimal bytes to search for.")
    parser.add_argument(
        "--references",
        action="store_true",
        help="Also search for 32-bit pointers to every direct match.",
    )
    args = parser.parse_args()
    if bool(args.text) == bool(args.hex_pattern):
        parser.error("Specify exactly one of --text or --hex.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
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
        regions = readable_regions(kernel32, process)
        if args.text:
            patterns = [
                ("utf8", args.text.encode("utf-8")),
                ("utf16le", args.text.encode("utf-16le")),
            ]
        else:
            patterns = [("hex", bytes.fromhex(args.hex_pattern))]

        all_matches: list[tuple[int, Region]] = []
        for label, pattern in patterns:
            matches = scan(kernel32, process, regions, pattern)
            print(f"{label}: {len(matches)} match(es)")
            for address, region in matches:
                print(
                    f"  0x{address:08X} region=0x{region.base:08X}+0x{region.size:X} "
                    f"allocation=0x{region.allocation_base:08X} "
                    f"protect=0x{region.protect:X} type=0x{region.kind:X}"
                )
            all_matches.extend(matches)

        if args.references:
            seen_addresses: set[int] = set()
            for target, _ in all_matches:
                if target in seen_addresses or target > 0xFFFFFFFF:
                    continue
                seen_addresses.add(target)
                pointer = target.to_bytes(4, "little")
                references = scan(kernel32, process, regions, pointer)
                print(f"references to 0x{target:08X}: {len(references)} match(es)")
                for address, region in references:
                    print(
                        f"  0x{address:08X} region=0x{region.base:08X}+0x{region.size:X} "
                        f"allocation=0x{region.allocation_base:08X}"
                    )
    finally:
        kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
