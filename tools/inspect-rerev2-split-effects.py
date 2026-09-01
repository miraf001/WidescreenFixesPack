"""Read RE:Rev2 split state and bullet-mark state without injecting or pausing.

Offsets are verified against the local x86 executable, not portable signatures.
Raw flags are diagnostic evidence, NOT presumed graphics-quality switches.
Each sample is non-atomic: the game may update between individual reads.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import struct
import time
from ctypes import wintypes


class Reader:
    def __init__(self, pid: int):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel.ReadProcessMemory.restype = wintypes.BOOL
        # Deliberately no VM_WRITE, VM_OPERATION, debugger or suspension rights.
        self.handle = self.kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        self.kernel.CloseHandle(self.handle)

    def read(self, address: int, length: int) -> bytes:
        buffer = ctypes.create_string_buffer(length)
        transferred = ctypes.c_size_t()
        if not self.kernel.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), buffer, length,
            ctypes.byref(transferred),
        ) or transferred.value != length:
            raise RuntimeError(f"Cannot read 0x{address:08X}+0x{length:X}")
        return buffer.raw

    def u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]


def snapshot(reader: Reader) -> dict:
    # Fail closed for unsupported/unmapped executable code.
    if reader.read(0x886DF0, 7) != bytes.fromhex("8b81f4080000c3"):
        raise RuntimeError("Unsupported executable: split-state accessor mismatch")
    mode = reader.u32(0x157AE00)
    mode_fields = struct.unpack("<2I", reader.read(mode + 0x8F0, 8)) if mode else None
    renderer = reader.u32(0x15DE88C)
    cached_split = reader.u32(renderer + 0xCE0) if renderer else None
    gate = reader.read(0xA7C3B9, 6)
    filter_code = reader.read(0xA85C7A, 8)
    native_filter = filter_code == bytes.fromhex("ba060000000f44ca")
    disabled_filter = filter_code == bytes.fromhex("ba000000000f44ca")
    native_gate = gate == bytes.fromhex("0f841d470000")
    bypassed_gate = gate == b"\x90" * 6
    manager = reader.u32(0x158111C)
    result = {
        "modeObject": f"0x{mode:08X}",
        "modeFields8F0_8F4": mode_fields,
        "guiSplitPredicate9553D0": mode_fields == (1, 1),
        "cachedRenderSplitModeCE0": cached_split,
        "bulletMarkGateBytes": gate.hex(),
        "bulletMarkCreationGate": (
            "native" if native_gate else "bypassed" if bypassed_gate else "unknown"
        ),
        "creationBlockedBySplitGate": (
            cached_split == 1 if native_gate else False if bypassed_gate else None
        ),
        "bulletMarkManager": f"0x{manager:08X}",
        "coopEffectFilterCode": (
            "native" if native_filter else "disabled" if disabled_filter else "unknown"
        ),
        "nonAtomicSample": True,
    }
    effects_manager = reader.u32(0x15DF97C)
    result["effectsManager"] = None
    if effects_manager:
        if reader.u32(effects_manager) != 0x13D7E48:
            raise RuntimeError("sBioEffect vtable mismatch; refusing stale offsets")
        # Name verified in native reflection at C6EDD3 / string 1410758.
        # DECE20 rejects a component when its trait overlaps this mask (ORed
        # with a local mask). This does not identify the human-visible effect.
        exclusion = reader.u32(effects_manager + 0x228)
        result["effectsManager"] = {
            "address": f"0x{effects_manager:08X}",
            "exclusionTraitMask": f"0x{exclusion:08X}",
            "excludesTrait2": bool(exclusion & 2),
            "excludesTrait4": bool(exclusion & 4),
        }
    if not manager:
        result["bulletMarks"] = None
        return result
    if reader.u32(manager) != 0x13D7AAC:
        raise RuntimeError("Bullet-mark manager vtable mismatch; refusing stale offsets")
    # Constructor allocates 64 entries, each 0xC70 bytes; update counts active entries.
    capacity, last_update_count = struct.unpack("<2I", reader.read(manager + 0x20, 8))
    if capacity != 64:
        raise RuntimeError(f"Unexpected bullet-mark capacity: {capacity}")
    slots = reader.read(manager + 0x30, 64 * 0xC70)
    active = [i for i in range(64) if slots[i * 0xC70 + 4] != 0]
    render_object, resource, raw_state = struct.unpack(
        "<3I", reader.read(manager + 0x31C30, 12)
    )
    marks = {
        "capacity": capacity,
        "lastUpdateActiveCount": last_update_count,
        "activeSlotIndices": active,
        "renderObject": f"0x{render_object:08X}",
        "resource": f"0x{resource:08X}",
        "rawManager31C38": f"0x{raw_state:08X}",
    }
    if render_object:
        raw = reader.read(render_object, 0x14)
        vtable = struct.unpack_from("<I", raw)[0]
        marks["renderVtableMatches"] = vtable == 0x13D7A68
        if vtable == 0x13D7A68:
            marks["rawRenderFlags0C"] = f"0x{struct.unpack_from('<I', raw, 0xC)[0]:08X}"
            marks["rawRenderField10"] = struct.unpack_from("<I", raw, 0x10)[0]
    # 0xA7C1F0 clears all marks if 0x8876C0 returns true. That function checks
    # these three bits, NOT the split-state predicate. Their meaning is unknown.
    system = reader.u32(0x15DE6F8)
    if system:
        clear_flags = reader.u32(system + 0x285B8)
        marks["rawClearFlags285B8"] = f"0x{clear_flags:08X}"
        marks["clearPredicate8876C0"] = bool(clear_flags & 0x01C00000)
    result["bulletMarks"] = marks
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--label", default="unlabelled")
    parser.add_argument("--seconds", type=float, default=0)
    args = parser.parse_args()
    if not 0 <= args.seconds <= 300:
        parser.error("--seconds must be between 0 and 300")
    reader = Reader(args.pid)
    started = time.monotonic()
    previous = None
    try:
        while True:
            state = snapshot(reader)
            if state != previous:
                print(json.dumps({
                    "pid": args.pid, "label": args.label,
                    "elapsed": round(time.monotonic() - started, 3), **state,
                }), flush=True)
                previous = state
            if time.monotonic() - started >= args.seconds:
                break
            time.sleep(0.25)
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
