"""Snapshot known RE:Rev2 gameplay GUI controller transforms from process memory."""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import struct
from ctypes import wintypes
from pathlib import Path


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
CHUNK_SIZE = 1024 * 1024


# Values in dllmain.cpp point 0x58 bytes past the object vtable.
CONTROLLERS = {
    "uGUIActionIcon": 0x01391608 - 0x58,
    "uGUIActionIcon2": 0x013919C8 - 0x58,
    "uGUICommandBase": 0x0139AA40 - 0x58,
    "uGUICommandFar": 0x0139AB98 - 0x58,
    "uGUICommandNear": 0x0139ACF8 - 0x58,
    "uGUIEquip": 0x0139AE78 - 0x58,
    "uGUIEquipShortcut": 0x0139B008 - 0x58,
    "uGUIFlash": 0x0139B5B0 - 0x58,
    "uGUIHeal": 0x0139B9F0 - 0x58,
    "uGUIHealNum": 0x0139BB48 - 0x58,
    "uGUIIndicatorFar": 0x0139C718 - 0x58,
    "uGUIIndicatorNear": 0x0139C860 - 0x58,
    # Verified from the native destructor/type-accessor/update slots. The old
    # dllmain.cpp enum mislabeled this draw slot as Campaign::cCompose.
    "uGUIInventoryCampaign": 0x0139CCC8,
    "uGUIReticleBase": 0x013A38C0 - 0x58,
    "uGUIReticleNatalia": 0x013A3A68 - 0x58,
    "uGUIReticleScope": 0x013A3BC8 - 0x58,
    "uGUIReticleThrow": 0x013A3D00 - 0x58,
    "uGUIVitalityMe": 0x0139C2E0 - 0x58,
    "uGUIVitalityPartner": 0x0139C430 - 0x58,
}


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


def read_memory(kernel32, process, address: int, size: int) -> bytes | None:
    buffer = ctypes.create_string_buffer(size)
    transferred = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(transferred),
    )
    if not ok or transferred.value != size:
        return None
    return buffer.raw


def clean_float(value: float) -> float | None:
    if not math.isfinite(value) or abs(value) > 1_000_000:
        return None
    return round(value, 5)


def transform_fields(data: bytes) -> dict[str, object]:
    u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
    f32 = lambda offset: clean_float(struct.unpack_from("<f", data, offset)[0])
    return {
        "position": [f32(0x40), f32(0x44)],
        "scale": [f32(0x60), f32(0x64)],
        "links": [f"0x{u32(0x14):08X}", f"0x{u32(0x18):08X}"],
        "renderPointers": [f"0x{u32(0xF0):08X}", f"0x{u32(0xF4):08X}"],
        "flags": f"0x{u32(0x148):X}",
        "cachedRectangle": list(struct.unpack_from("<4i", data, 0x168)),
        "anchorPairs": [
            [f32(0x178 + i * 8), f32(0x17C + i * 8)] for i in range(10)
        ],
        "scalePairs": [
            [f32(0x1C8 + i * 8), f32(0x1CC + i * 8)] for i in range(11)
        ],
    }


def node_fields(data: bytes) -> dict[str, object]:
    # A GUI tree node is NOT a GUI controller. These offsets are verified from
    # native setters E690F0/E69120 (position) and E69520/E69550 (scale).
    u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
    f32 = lambda offset: clean_float(struct.unpack_from("<f", data, offset)[0])
    return {
        "owner": f"0x{u32(0x6C):08X}",
        "localPosition": [f32(0xA0), f32(0xA4)],
        "localScale": [f32(0xB0), f32(0xB4)],
        "flags": f"0x{u32(0x54):08X}",
        "layoutFlags": f"0x{u32(0x80):08X}",
        # The explicit selector wins; the upper nibble is only the fallback.
        "scaleMode": ((u32(0x80) >> 16) & 0xF) or ((u32(0x80) >> 20) & 0xF),
        "explicitScaleMode": (u32(0x80) >> 16) & 0xF,
        "fallbackScaleMode": (u32(0x80) >> 20) & 0xF,
        "matrixScale": [f32(0x10), f32(0x24)],
        "matrixPosition": [f32(0x40), f32(0x44)],
        "firstChild": f"0x{u32(0x60):08X}",
        "nextSibling": f"0x{u32(0x64):08X}",
    }


def item_preview_fields(kernel32, process, controller: int) -> dict:
    """Read the separate uItemDraw object; never interpret it as a GUI node."""
    link = read_memory(kernel32, process, controller + 0x2CC, 4)
    address = struct.unpack("<I", link)[0] if link else 0
    result = {"address": f"0x{address:08X}"}
    data = read_memory(kernel32, process, address, 0x108) if address else None
    if data is None or struct.unpack_from("<I", data)[0] != 0x13BF4D0:
        result["verifiedItemDraw"] = False
        return result
    u32 = lambda offset: struct.unpack_from("<I", data, offset)[0]
    rect = struct.unpack_from("<4i", data, 0xA4)
    result.update({"verifiedItemDraw": True, "state": u32(0x80),
                   "requestedScreenView": u32(0x84), "activeScreenView": u32(0x88),
                   "drawView": u32(0x8C), "overlay": bool(data[0x90]),
                   "currentItem": u32(0x94), "requestedItem": u32(0x9C),
                   "destinationRectangle": rect,
                   "destinationSize": [rect[2] - rect[0], rect[3] - rect[1]],
                   "camera": f"0x{u32(0xE0):08X}",
                   "compositeObject": f"0x{u32(0x100):08X}"})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--class-name", choices=tuple(CONTROLLERS), action="append",
                        help="Limit this read-only scan to specific controller classes")
    parser.add_argument("--output", type=Path, help="Save snapshot JSON to a NEW file (never overwrite)")
    args = parser.parse_args()

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

    patterns = {
        struct.pack("<I", vtable): (name, vtable)
        for name, vtable in CONTROLLERS.items()
        if not args.class_name or name in args.class_name
    }
    hits: list[tuple[int, str, int]] = []
    try:
        info = MEMORY_BASIC_INFORMATION()
        address = 0
        while address < 0x1_0000_0000:
            result = kernel32.VirtualQueryEx(
                process, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
            )
            if not result:
                break
            base = int(info.BaseAddress or 0)
            size = int(info.RegionSize)
            protection = int(info.Protect) & 0xFF
            if (
                info.State == MEM_COMMIT
                and info.Type == MEM_PRIVATE
                and protection in READABLE_PROTECTIONS
                and not (info.Protect & PAGE_GUARD)
            ):
                offset = 0
                while offset < size:
                    requested = min(CHUNK_SIZE, size - offset)
                    data = read_memory(kernel32, process, base + offset, requested)
                    if data is not None:
                        for pattern, (name, vtable) in patterns.items():
                            start = 0
                            while True:
                                index = data.find(pattern, start)
                                if index < 0:
                                    break
                                candidate = base + offset + index
                                if candidate % 4 == 0:
                                    hits.append((candidate, name, vtable))
                                start = index + 1
                    offset += requested
            next_address = base + size
            if next_address <= address:
                break
            address = next_address

        rows = []
        for object_address, name, vtable in sorted(hits):
            data = read_memory(kernel32, process, object_address, 0x220)
            if data is None or struct.unpack_from("<I", data)[0] != vtable:
                continue
            root_address = struct.unpack_from("<I", data, 0xF4)[0]
            if not root_address or root_address % 4:
                continue
            root = read_memory(kernel32, process, root_address, 0xC0)
            # Avoid reporting an incidental vtable pattern as a live controller.
            # Only include loaded GUI trees with a matching owner backlink.
            if root is None or struct.unpack_from("<I", root, 0x6C)[0] != object_address:
                continue
            row = {
                "class": name,
                "object": f"0x{object_address:08X}",
                **transform_fields(data),
            }
            row["renderRoot"] = {
                "address": f"0x{root_address:08X}",
                **node_fields(root),
            }
            if name == "uGUIInventoryCampaign":
                row["itemPreview"] = item_preview_fields(kernel32, process, object_address)
            rows.append(row)
        report = {
            "pid": args.pid, "nonAtomicSnapshot": True,
            "selection": "aligned vtable plus loaded root owner backlink",
            "controllers": rows,
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, indent=2)
        print(json.dumps(report, indent=2))
    finally:
        kernel32.CloseHandle(process)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
