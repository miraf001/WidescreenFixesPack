"""Reversible, build-pinned live SP-layout test for Equip/Heal/HealNum only.

No debugger, per-frame Python/JS callback, global split-mode change, or disk ASI
replacement. Three layout-only TEST AL,AL instructions become XOR AL,AL. Each
class's aligned draw-vtable slot temporarily points to a tiny native thunk that
uses the loaded ASI's unadjusted transform in MP, its normal path in SP. Counters
prove whether the per-class draw path actually runs; zero counters are NOT a
successful rendering test. Restarting co-op may be needed to recreate the UI.

Optional stretch/unstretch changes the native per-node explicit scale selector
from uniform-fit (5) to independent X/Y (2), only in these controllers' loaded
trees. It preserves native SP positions, animation scales and all other flags.
The first test is instance-local: recreated trees require a new plan/stretch.

Optional aspect/unaspect separates geometry scale from placement for those same
backed-up nodes. Geometry follows viewport height uniformly, anchor positions
retain independent X/Y scaling. This is still an instance-local visual test.

Restore reinstates exact original code/slots. The 8-KiB thunk allocation is kept
until process exit so an in-flight return/jump cannot use freed executable memory.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from contextlib import contextmanager, nullcontext
import hashlib
import json
from pathlib import Path
import struct


# The full hash is deliberately pinned to the deployed 2026-08-30 Debug build.
ASI_HASH = "78de97a3363b74cce8d1f955029b6f08c929e65800db789790a5693aafefbd94"
CORE_RVA = 0x1C40
RESCALE_RVA = 0x2F00
DRAW_ENTRY = 0xE18040
GEOMETRY_X_LOAD = 0xE6308A
GEOMETRY_X_BYTES = bytes.fromhex("f3 0f 10 8c c8 c8 01 00 00")
MODE_POINTER = 0x157AE00
DEFINITIONS = (
    # class, vtable, verified update-vtable entry, predicate call, call bytes, nodes
    ("uGUIEquip", 0x139AE20, 0x8E4020, 0x8E4062, "e869130700", (0, 4)),
    ("uGUIHeal", 0x139B998, 0x8E9980, 0x8E99CC, "e8ffb90600", (3, 4)),
    ("uGUIHealNum", 0x139BAF0, 0x8E9E70, 0x8E9E9E, "e82db50600", (0,)),
)


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def make_thunk(address: int, counter: int, core: int) -> bytes:
    """x86 __thiscall -> loaded __fastcall core(this, mode=0, same stack arg)."""
    code = bytearray(b"\x50\xa1" + u32(MODE_POINTER) + b"\x85\xc0")
    fixups = []
    for condition in (b"\x74", b"\x75", b"\x75"):
        if len(fixups) == 1:
            code += bytes.fromhex("83 b8 f0 08 00 00 01")
        elif len(fixups) == 2:
            code += bytes.fromhex("83 b8 f4 08 00 00 01")
        code += condition + b"\x00"
        fixups.append(len(code) - 1)
    code += b"\x58\xf0\xff\x05" + u32(counter) + b"\x31\xd2"
    code += b"\xe9" + u32((core - (address + len(code) + 5)) & 0xFFFFFFFF)
    fallback = len(code)
    code += b"\x58\xe9" + u32((DRAW_ENTRY - (address + len(code) + 6)) & 0xFFFFFFFF)
    for operand in fixups:
        code[operand] = fallback - (operand + 1)
    return bytes(code)


def scale_update_address(allocation: int, index: int) -> int:
    return allocation + 0x400 + index * 0x200


def make_scale_update_thunk(address: int, counter: int, updater: int, indices: tuple[int, ...]) -> bytes:
    """Call original thiscall update, then keep only its own nodes on mode 2 in MP.

    Native animation can rewrite the selector every frame. This bounded native
    post-update wrapper avoids an external polling writer or render-thread JS.
    EAX return value and nonvolatile EBX/ESI are preserved; no SSE registers used.
    On return to SP, nodes we switched to 2 are put back on their original 5.
    """
    code, labels, fixups = bytearray(), {}, []

    def emit(encoded):
        code.extend(bytes.fromhex(encoded))

    def jump(opcode, label):
        emit(opcode)
        fixups.append((len(code), label))
        code.extend(b"\x00" * 4)

    emit("56 53 8b f1 b8")  # preserve ESI/EBX, ESI=this, call original updater
    code.extend(u32(updater))
    emit("ff d0 50 ba")  # preserve return EAX; default selector 5 for SP
    code.extend(u32(0x50000))
    emit("a1")
    code.extend(u32(MODE_POINTER))
    emit("85 c0")
    jump("0f 84", "select_nodes")
    emit("83 b8 f0 08 00 00 01")
    jump("0f 85", "select_nodes")
    emit("83 b8 f4 08 00 00 01")
    jump("0f 85", "select_nodes")
    emit("ba")
    code.extend(u32(0x20000))
    labels["select_nodes"] = len(code)
    emit("8b 8e f8 00 00 00 85 c9")
    jump("0f 84", "done")
    for index in indices:
        next_node, change = f"next_{index}", f"change_{index}"
        emit("8b 81")
        code.extend(u32(index * 4))
        emit("85 c0")
        jump("0f 84", next_node)
        emit("39 70 6c")  # node.owner must equal this controller
        jump("0f 85", next_node)
        emit("8b 98 80 00 00 00 81 e3 00 00 0f 00 39 d3")
        jump("0f 84", next_node)
        emit("81 fb 00 00 05 00")
        jump("0f 84", change)
        emit("81 fb 00 00 02 00")
        jump("0f 85", next_node)
        labels[change] = len(code)
        emit("81 a0 80 00 00 00 ff ff f0 ff 09 90 80 00 00 00")
        emit("81 48 54 00 00 01 00 f0 ff 05")
        code.extend(u32(counter))
        labels[next_node] = len(code)
    labels["done"] = len(code)
    emit("58 5b 5e c3")
    for offset, label in fixups:
        struct.pack_into("<i", code, offset, labels[label] - (offset + 4))
    if len(code) > 0x200:
        raise RuntimeError("Scale update thunk exceeds its reserved slot")
    return bytes(code)


def make_aspect_thunk(address: int, counter: int, stretch: dict, fallback: int | None = None) -> bytes:
    """Change only the final geometry X multiplier, never anchor translation.

    E6308A is ONE complete nine-byte MOVSS. EAX=owner, ECX=effective
    selector, ESI=node. Preserve EFLAGS/all GPRs and all SSE except native
    destination XMM1. Mode 2 + MP + exact backed-up tree/node identity only.
    Shape scale follows viewport height; position keeps independent X/Y.
    """
    code, labels, fixups = bytearray(), {}, []

    def emit(encoded):
        code.extend(bytes.fromhex(encoded))

    def jump(opcode, label):
        emit(opcode)
        fixups.append((len(code), label))
        code.extend(bytes(4))

    emit("9c 52 83 f9 02")  # pushfd, push edx; cmp ecx,2
    jump("0f 85", "native")
    emit("8b 15")
    code.extend(u32(MODE_POINTER))
    emit("85 d2")
    jump("0f 84", "native")
    for offset in (0x8F0, 0x8F4):
        emit("83 ba")
        code.extend(u32(offset))
        emit("01")
        jump("0f 85", "native")
    for index, tree in enumerate(stretch["trees"]):
        next_tree = f"tree_{index + 1}"
        emit("3d")
        code.extend(u32(tree["controller"]))
        jump("0f 85", next_tree)
        emit("81 38")
        code.extend(u32(tree["vtable"]))
        jump("0f 85", "native")
        for offset, key in ((0xF0, "resource"), (0xF4, "root")):
            emit("81 b8")
            code.extend(u32(offset) + u32(tree[key]))
            jump("0f 85", "native")
        for node in stretch["nodes"]:
            if node["owner"] != tree["controller"]:
                continue
            next_node = f"node_{node['node']:x}"
            emit("81 fe")
            code.extend(u32(node["node"]))
            jump("0f 85", next_node)
            emit("81 3e")
            code.extend(u32(node["vtable"]))
            jump("0f 84", "uniform")
            jump("e9", "native")
            labels[next_node] = len(code)
        jump("e9", "native")
        labels[next_tree] = len(code)
    jump("e9", "native")
    labels["uniform"] = len(code)
    emit("f0 ff 05")
    code.extend(u32(counter))
    emit("f3 0f 10 8c c8 cc 01 00 00")  # X uses the Y factor of SAME pair
    jump("e9", "return")
    labels["native"] = len(code)
    if fallback is not None:
        # Optional separately backed-up extension: unmatched nodes delegate to
        # the previous aspect hook with original registers/flags and stack.
        emit("5a 9d e9")
        code.extend(u32((fallback - (address + len(code) + 4)) & 0xFFFFFFFF))
    else:
        code.extend(GEOMETRY_X_BYTES)
    labels["return"] = len(code)
    emit("5a 9d e9")
    code.extend(u32((GEOMETRY_X_LOAD + len(GEOMETRY_X_BYTES) - (address + len(code) + 4)) & 0xFFFFFFFF))
    for offset, label in fixups:
        struct.pack_into("<i", code, offset, labels[label] - offset - 4)
    if len(code) > 4096:
        raise RuntimeError("Aspect thunk exceeds one executable page")
    return bytes(code)


def aspect_redirect(allocation: int) -> bytes:
    return b"\xe9" + u32((allocation - GEOMETRY_X_LOAD - 5) & 0xFFFFFFFF) + b"\x90" * 4


class Process:
    def __init__(self, pid: int, write: bool):
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.n = ctypes.WinDLL("ntdll")
        signatures = {
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "ReadProcessMemory": ([wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)], wintypes.BOOL),
            "WriteProcessMemory": ([wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)], wintypes.BOOL),
            "VirtualAllocEx": ([wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                wintypes.DWORD, wintypes.DWORD], ctypes.c_void_p),
            "VirtualProtectEx": ([wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                  wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            "FlushInstructionCache": ([wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t], wintypes.BOOL),
            "QueryFullProcessImageNameW": ([wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            "GetProcessTimes": ([wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            method = getattr(self.k, name)
            method.argtypes, method.restype = args, result
        for name in ("NtSuspendProcess", "NtResumeProcess"):
            method = getattr(self.n, name)
            method.argtypes, method.restype = [wintypes.HANDLE], wintypes.LONG
        self.handle = self.k.OpenProcess(0x410 | (0x828 if write else 0), False, pid)
        self.check(self.handle)

    @staticmethod
    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        self.k.CloseHandle(self.handle)

    def read(self, address: int, size: int) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        transferred = ctypes.c_size_t()
        self.check(self.k.ReadProcessMemory(self.handle, address, buffer, size, ctypes.byref(transferred)))
        if transferred.value != size:
            raise RuntimeError("Partial process read")
        return buffer.raw

    def integer(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def expect(self, address: int, value: bytes):
        actual = self.read(address, len(value))
        if actual != value:
            raise RuntimeError(f"Unexpected memory at 0x{address:X}: {actual.hex()} != {value.hex()}")

    def protect(self, address: int, size: int, protection: int) -> int:
        old = wintypes.DWORD()
        self.check(self.k.VirtualProtectEx(self.handle, address, size, protection, ctypes.byref(old)))
        return old.value

    def write(self, address: int, value: bytes):
        buffer = ctypes.create_string_buffer(value)
        transferred = ctypes.c_size_t()
        self.check(self.k.WriteProcessMemory(self.handle, address, buffer, len(value), ctypes.byref(transferred)))
        if transferred.value != len(value):
            raise RuntimeError("Partial process write")

    def patch(self, address: int, value: bytes):
        old = self.protect(address, len(value), 0x40)
        try:
            self.write(address, value)
            self.expect(address, value)
            self.check(self.k.FlushInstructionCache(self.handle, address, len(value)))
        finally:
            self.protect(address, len(value), old)

    def identity(self) -> dict:
        name = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(name))
        self.check(self.k.QueryFullProcessImageNameW(self.handle, 0, name, ctypes.byref(size)))
        if Path(name.value).name.lower() != "rerev2.exe":
            raise RuntimeError("Target is not rerev2.exe")
        times = [wintypes.FILETIME() for _ in range(4)]
        self.check(self.k.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in times)))
        created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        return {"image": name.value, "created": created}

    @contextmanager
    def suspended(self):
        status = self.n.NtSuspendProcess(self.handle)
        if status < 0:
            raise RuntimeError(f"NtSuspendProcess failed: {status & 0xFFFFFFFF:X}")
        try:
            yield
        finally:
            status = self.n.NtResumeProcess(self.handle)
            if status < 0:
                raise RuntimeError(f"NtResumeProcess failed: {status & 0xFFFFFFFF:X}; resume game immediately")


def validate_build(process: Process, identity: dict, state=None, geometry_override: bytes | None = None) -> int:
    image = Path(identity["image"]).parent / "scripts/ResidentEvilRevelations2.FusionFix.asi"
    if hashlib.sha256(image.read_bytes()).hexdigest() != ASI_HASH:
        raise RuntimeError("This live test only supports the pinned deployed Debug ASI")
    jump = process.read(DRAW_ENTRY, 5)
    if jump[0] != 0xE9:
        raise RuntimeError("Expected the existing ASI render redirect")
    base = DRAW_ENTRY + 5 + struct.unpack("<i", jump[1:])[0] - RESCALE_RVA
    process.expect(base, b"MZ")
    process.expect(base + CORE_RVA, bytes.fromhex("55 89 e5 53 57 56 81 ec ec 01 00 00 8b 45 08"))
    hook_status = (state or {}).get("stretch", {}).get("updateHookStatus")
    for index, (_, vtable, updater, _, _, indices) in enumerate(DEFINITIONS):
        actual = process.integer(vtable + 0x24)
        if hook_status in ("applied", "prepared"):
            allocation = state["allocation"]
            hook = scale_update_address(allocation, index)
            if actual == hook:
                process.expect(hook, make_scale_update_thunk(hook, allocation + 0x1020 + index * 4, updater, indices))
                continue
            if hook_status == "applied":
                raise RuntimeError("Active scale-update hook was unexpectedly replaced")
        process.expect(vtable + 0x24, u32(updater))
    aspect = (state or {}).get("aspect", {})
    actual = process.read(GEOMETRY_X_LOAD, len(GEOMETRY_X_BYTES))
    if aspect.get("status") in ("prepared", "applied"):
        allocation = aspect["allocation"]
        process.expect(allocation, make_aspect_thunk(allocation, allocation + 4096, state["stretch"]))
        if geometry_override is not None:
            # Caller must independently validate its extension code and state.
            process.expect(GEOMETRY_X_LOAD, geometry_override)
            return base + CORE_RVA
        if actual == aspect_redirect(allocation):
            return base + CORE_RVA
        if aspect["status"] == "applied":
            raise RuntimeError("Active aspect hook was unexpectedly replaced")
    process.expect(GEOMETRY_X_LOAD, GEOMETRY_X_BYTES)
    return base + CORE_RVA


def patch_set(allocation: int) -> list[tuple[int, bytes, bytes]]:
    patches = []
    for index, (_, vtable, _, call, _, _) in enumerate(DEFINITIONS):
        patches += [(call + 5, b"\x84", b"\x30"),
                    (vtable + 0x58, u32(DRAW_ENTRY), u32(allocation + index * 0x100))]
    return patches


def transact(process: Process, patches, restore=False, guards=(), dirty_nodes=(), suspend=True):
    changes = [(address, after, before) if restore else (address, before, after)
               for address, before, after in patches]
    # No filesystem I/O, scanning, debugger, or waiting while suspended.
    with process.suspended() if suspend else nullcontext():
        for address, expected in guards:
            process.expect(address, expected)
        for address, expected, _ in changes:
            process.expect(address, expected)
        # Only invalidate native caches; do not restore stale animation flags.
        for node in dirty_nodes:
            flags = process.integer(node + 0x54)
            changes.append((node + 0x54, u32(flags), u32(flags | 0x10000)))
        attempted = []
        try:
            for address, expected, value in changes:
                attempted.append((address, expected))
                process.patch(address, value)
        except BaseException:
            errors = []
            for address, expected in reversed(attempted):
                try:
                    process.patch(address, expected)
                except BaseException as error:
                    errors.append(str(error))
            if errors:
                raise RuntimeError("Rollback errors: " + "; ".join(errors))
            raise


def stretch_flags(flags: int) -> int:
    # E62A44/E63072 select bits 16..19 first; bits 20..23 are the fallback.
    # Both the position and matrix scale use the selected controller scale pair.
    if (flags >> 16) & 0xF != 5:
        raise ValueError("Only explicit native uniform-fit selector 5 is supported")
    return (flags & ~0xF0000) | 0x20000


def plan_stretch(process: Process, controllers: list[int], definitions=DEFINITIONS) -> dict:
    definitions = {d[1]: d for d in definitions}
    records, trees = [], []
    for controller in controllers:
        vtable = process.integer(controller)
        if vtable not in definitions:
            raise RuntimeError(f"Stale/unexpected controller 0x{controller:X}; resnapshot first")
        root = process.integer(controller + 0xF4)
        resource = process.integer(controller + 0xF0)
        process.expect(root + 0x6C, u32(controller))
        bounds = struct.unpack("<4i", process.read(controller + 0x168, 16))
        source = struct.unpack("<2I", process.read(resource + 0x78, 8))
        sx, sy = struct.unpack("<2f", process.read(controller + 0x1D8, 8))
        if min(source) == 0 or min(bounds[2] - bounds[0], bounds[3] - bounds[1]) <= 0:
            raise RuntimeError("Invalid source or target rectangle")
        expected = ((bounds[2] - bounds[0]) / source[0], (bounds[3] - bounds[1]) / source[1])
        if any(abs(actual - desired) > 0.00001 for actual, desired in zip((sx, sy), expected)):
            raise RuntimeError("Native independent-axis scale table does not match viewport dimensions")
        tree = {"controller": controller, "class": definitions[vtable][0], "vtable": vtable,
                "root": root, "resource": resource, "bounds": bounds, "source": source,
                "independentScale": [sx, sy], "visited": 0, "changed": 0}
        pending, visited = [root], set()
        while pending:
            node = pending.pop()
            if node in visited:
                raise RuntimeError("Cycle/shared node in GUI tree; refusing uncertain ownership")
            if len(visited) >= 2048:
                raise RuntimeError("Unexpectedly large GUI tree")
            visited.add(node)
            data = process.read(node, 0x84)
            field = lambda offset: struct.unpack_from("<I", data, offset)[0]
            owner, flags = field(0x6C), field(0x80)
            if owner not in (0, controller):
                raise RuntimeError("Nested foreign GUI owner; refusing to alter this tree")
            if owner == controller and ((flags >> 16) & 0xF) == 5:
                records.append({"node": node, "owner": owner, "vtable": field(0),
                                "before": flags, "after": stretch_flags(flags)})
                tree["changed"] += 1
            child, sibling = field(0x60), field(0x64)
            if child:
                pending.append(child)
            if node != root and sibling:
                pending.append(sibling)
        tree["visited"] = len(visited)
        trees.append(tree)
    if not records:
        raise RuntimeError("No explicit uniform-fit nodes found; nothing will be changed")
    return {"trees": trees, "nodes": records}


def stretch_transaction_inputs(stretch: dict):
    guards, patches, dirty = [], [], []
    for tree in stretch["trees"]:
        controller = tree["controller"]
        guards += [(controller, u32(tree["vtable"])),
                   (controller + 0xF0, u32(tree["resource"]) + u32(tree["root"])),
                   (tree["root"] + 0x6C, u32(controller))]
    for node in stretch["nodes"]:
        address = node["node"]
        guards += [(address, u32(node["vtable"])), (address + 0x6C, u32(node["owner"]))]
        patches.append((address + 0x80, u32(node["before"]), u32(node["after"])))
        dirty.append(address)
    return guards, patches, dirty


def maintain_stretch(process: Process, state: dict, state_path: Path):
    stretch = state.get("stretch", {})
    if stretch.get("status") != "applied" or stretch.get("updateHookStatus") in ("applied", "prepared"):
        raise RuntimeError("Expected an applied stretch test without an active update hook")
    patches = []
    allocation = state["allocation"]
    for index, (_, vtable, updater, _, _, indices) in enumerate(DEFINITIONS):
        hook = scale_update_address(allocation, index)
        code = make_scale_update_thunk(hook, allocation + 0x1020 + index * 4, updater, indices)
        process.expect(vtable + 0x24, u32(updater))
        current = process.read(hook, len(code))
        if current not in (bytes(len(code)), code):
            raise RuntimeError("Reserved scale-update slot contains unexpected code")
        if current != code:
            process.patch(hook, code)  # new, unreferenced slots; old thunks unchanged
        patches.append((vtable + 0x24, u32(updater), u32(hook)))
    stretch["updateHookStatus"] = "prepared"
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    transact(process, patches)
    stretch["updateHookStatus"] = "applied"
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def restore_stretch(process: Process, state: dict):
    stretch = state["stretch"]
    guards, _, dirty = stretch_transaction_inputs(stretch)
    with process.suspended():
        # Native animation may have already restored 5. Restore only our selector
        # bits, preserving any later native changes to unrelated layout flags.
        for address, expected in guards:
            process.expect(address, expected)
        patches = []
        for node in stretch["nodes"]:
            address = node["node"] + 0x80
            actual = process.integer(address)
            selector = (actual >> 16) & 15
            if selector not in (2, 5):
                raise RuntimeError("Unexpected layout selector during restore")
            restored = (actual & ~0xF0000) | (node["before"] & 0xF0000)
            patches.append((address, u32(actual), u32(restored)))
        if stretch.get("updateHookStatus") in ("applied", "prepared"):
            for index, (_, vtable, updater, _, _, _) in enumerate(DEFINITIONS):
                actual = process.integer(vtable + 0x24)
                if actual not in (updater, scale_update_address(state["allocation"], index)):
                    raise RuntimeError("Unexpected update hook during restore")
                patches.append((vtable + 0x24, u32(actual), u32(updater)))
        transact(process, patches, guards=guards, dirty_nodes=dirty, suspend=False)
    stretch["status"] = "restored"
    stretch["updateHookStatus"] = "restored"


def refresh_stretch(process: Process, state: dict):
    stretch = state.get("stretch", {})
    if stretch.get("status") != "applied":
        raise RuntimeError("No applied independent-axis test")
    guards, _, _ = stretch_transaction_inputs(stretch)
    # E170F8 compares this cached right edge, then the native E1A240 walk
    # invalidates the full GUI subtree. This is not the actual viewport edge.
    with process.suspended():
        patches = []
        for tree in stretch["trees"]:
            address = tree["controller"] + 0x170
            patches.append((address, process.read(address, 4), u32(0xFFFFFFFF)))
        transact(process, patches, guards=guards, suspend=False)


def apply_aspect(process: Process, state: dict, state_path: Path):
    stretch = state.get("stretch", {})
    if (state.get("status") != "applied" or stretch.get("status") != "applied"
            or stretch.get("updateHookStatus") != "applied"):
        raise RuntimeError("Aspect test requires the maintained independent-axis SP-layout test")
    if state.get("aspect", {}).get("status") in ("prepared", "applied"):
        raise RuntimeError("An aspect test is already active")
    guards, _, _ = stretch_transaction_inputs(stretch)
    for address, expected in guards:
        process.expect(address, expected)
    for address, _, expected in patch_set(state["allocation"]):
        process.expect(address, expected)
    process.expect(GEOMETRY_X_LOAD, GEOMETRY_X_BYTES)
    allocation = process.k.VirtualAllocEx(process.handle, None, 8192, 0x3000, 0x04)
    process.check(allocation)
    if allocation + 8192 > 0x100000000:
        raise RuntimeError("Aspect allocation outside the 32-bit address space")
    code = make_aspect_thunk(allocation, allocation + 4096, stretch)
    process.write(allocation, code)
    process.protect(allocation, 4096, 0x20)
    process.check(process.k.FlushInstructionCache(process.handle, allocation, len(code)))
    state["aspect"] = {"status": "prepared", "allocation": allocation,
                       "before": snapshot(process, state["controllers"]),
                       "scalePolicy": "height-uniform-geometry-independent-position"}
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    # Entire replaced region is a single native instruction. Suspended threads
    # can resume at its start or end; the thunk returns after all nine bytes.
    transact(process, [(GEOMETRY_X_LOAD, GEOMETRY_X_BYTES, aspect_redirect(allocation))], guards=guards)
    state["aspect"]["status"] = "applied"
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    refresh_stretch(process, state)


def restore_aspect(process: Process, state: dict, state_path: Path | None = None):
    aspect = state.get("aspect", {})
    if aspect.get("status") not in ("prepared", "applied"):
        return
    actual = process.read(GEOMETRY_X_LOAD, len(GEOMETRY_X_BYTES))
    if actual not in (GEOMETRY_X_BYTES, aspect_redirect(aspect["allocation"])):
        raise RuntimeError("Unexpected geometry instruction during restore")
    transact(process, [(GEOMETRY_X_LOAD, actual, GEOMETRY_X_BYTES)])
    aspect["status"] = "restored"
    if state_path is not None:
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    # Keep code/counter pages allocated for any in-flight native thunk.
    try:
        refresh_stretch(process, state)
    except (OSError, RuntimeError) as error:
        # A recreated tree must not prevent removal of our code hook. Never
        # refresh stale nodes, and persist the actual restored code state.
        aspect["cacheRefreshWarning"] = str(error)
    if state_path is not None:
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def snapshot(process: Process, controllers: list[int], definitions=DEFINITIONS) -> list[dict]:
    definitions = {d[1]: d for d in definitions}
    result = []
    for address in controllers:
        try:
            definition = definitions.get(process.integer(address))
            if definition is None:
                result.append({"object": hex(address), "stale": True})
                continue
            name, _, _, _, _, indices = definition
            table = process.integer(address + 0xF8)
            row = {"class": name, "object": hex(address),
                   "player": process.integer(address + 0x2AC), "nodes": []}
            for index in indices:
                node = process.integer(table + index * 4)
                row["nodes"].append({"index": index, "address": hex(node),
                                     "position": struct.unpack("<2f", process.read(node + 0xA0, 8)),
                                     "scale": struct.unpack("<3f", process.read(node + 0xB0, 12)),
                                     "layoutFlags": hex(process.integer(node + 0x80)),
                                     "matrixScale": [struct.unpack("<f", process.read(node + offset, 4))[0]
                                                     for offset in (0x10, 0x24)],
                                     "matrixPosition": struct.unpack("<2f", process.read(node + 0x40, 8))})
            result.append(row)
        except OSError:
            result.append({"object": hex(address), "unreadable": True})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--mode", choices=("inspect", "apply", "restore", "plan-stretch", "stretch", "maintain-stretch", "refresh-stretch", "unstretch", "aspect", "unaspect"), default="inspect")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--controller", type=lambda x: int(x, 0), action="append", default=[])
    args = parser.parse_args()
    process = Process(args.pid, args.mode not in ("inspect", "plan-stretch"))
    try:
        identity = process.identity()
        state = json.loads(args.state.read_text()) if args.state.exists() else None
        if state is not None and (state["identity"] != identity or state["pid"] != args.pid):
            raise RuntimeError("State belongs to another process instance; refusing stale addresses")
        core = validate_build(process, identity, state)
        if args.mode == "apply":
            if state is not None:
                raise RuntimeError("Use a new state path for each test; existing backup will not be overwritten")
            for _, vtable, _, call, encoded, _ in DEFINITIONS:
                process.expect(call, bytes.fromhex(encoded) + b"\x84\xc0")
                process.expect(vtable + 0x58, u32(DRAW_ENTRY))
            allocation = process.k.VirtualAllocEx(process.handle, None, 8192, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 8192 > 0x100000000:
                raise RuntimeError("Allocation is outside the 32-bit address space")
            for index in range(len(DEFINITIONS)):
                address, counter = allocation + index * 0x100, allocation + 4096 + index * 4
                process.write(address, make_thunk(address, counter, core))
            process.protect(allocation, 4096, 0x20)
            process.check(process.k.FlushInstructionCache(process.handle, allocation, 4096))
            state = {"pid": args.pid, "identity": identity, "allocation": allocation,
                     "core": core, "status": "prepared", "controllers": args.controller,
                     "before": snapshot(process, args.controller),
                     "patches": [{"address": hex(a), "before": b.hex(), "after": c.hex()}
                                 for a, b, c in patch_set(allocation)]}
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            transact(process, patch_set(allocation))
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode in ("plan-stretch", "stretch"):
            if state is None or state["status"] != "applied":
                raise RuntimeError("Apply the SP-layout/draw test before the independent-axis test")
            if state.get("stretch", {}).get("status") in ("applied", "prepared"):
                raise RuntimeError("An independent-axis test already exists; inspect/unstretch it first")
            for address, _, expected in patch_set(state["allocation"]):
                process.expect(address, expected)
            mode_object = process.integer(MODE_POINTER)
            process.expect(mode_object + 0x8F0, u32(1) + u32(1))
            stretch = plan_stretch(process, args.controller or state["controllers"])
            if args.mode == "plan-stretch":
                print(json.dumps(stretch, indent=2))
                return 0
            stretch["status"] = "prepared"
            state["stretch"] = stretch
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            guards, patches, dirty = stretch_transaction_inputs(stretch)
            transact(process, patches, guards=guards, dirty_nodes=dirty)
            stretch["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "maintain-stretch":
            if state is None or state["status"] != "applied":
                raise RuntimeError("An applied SP-layout test is required")
            maintain_stretch(process, state, args.state)
            refresh_stretch(process, state)
        elif args.mode == "refresh-stretch":
            if state is None or state["status"] != "applied":
                raise RuntimeError("An applied SP-layout test is required")
            refresh_stretch(process, state)
        elif args.mode == "aspect":
            if state is None:
                raise RuntimeError("An existing live-layout state is required")
            apply_aspect(process, state, args.state)
        elif args.mode == "unaspect":
            if state is None or state.get("aspect", {}).get("status") not in ("applied", "prepared"):
                raise RuntimeError("No active aspect test")
            restore_aspect(process, state, args.state)
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode in ("restore", "unstretch"):
            if state is None or state["status"] not in ("applied", "prepared"):
                raise RuntimeError("No active test state to restore")
            restore_aspect(process, state, args.state)
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            stretch = state.get("stretch", {})
            if stretch.get("status") in ("applied", "prepared"):
                restore_stretch(process, state)
                args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            elif args.mode == "unstretch":
                raise RuntimeError("No active independent-axis test to restore")
        if args.mode == "restore":
            allocation = state["allocation"]
            for index in range(len(DEFINITIONS)):
                address = allocation + index * 0x100
                process.expect(address, make_thunk(address, allocation + 4096 + index * 4, core))
            transact(process, patch_set(allocation), restore=True)
            state["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        result = {"pid": args.pid, "status": state["status"] if state else "native",
                  "core": hex(core), "classes": [], "nonAtomicSnapshot": True,
                  "stretchStatus": (state or {}).get("stretch", {}).get("status", "not-applied"),
                  "scaleUpdateHookStatus": (state or {}).get("stretch", {}).get("updateHookStatus", "not-applied")}
        aspect = (state or {}).get("aspect", {})
        result["aspectStatus"] = aspect.get("status", "not-applied")
        if aspect:
            result["uniformGeometryRecomputes"] = process.integer(aspect["allocation"] + 4096)
        for index, (name, vtable, _, call, _, _) in enumerate(DEFINITIONS):
            row = {"class": name, "layoutTestBytes": process.read(call + 5, 2).hex(),
                   "drawTarget": hex(process.integer(vtable + 0x58))}
            if state:
                row["coopUnadjustedDrawCalls"] = process.integer(state["allocation"] + 4096 + index * 4)
                row["scaleSelectorReapplications"] = process.integer(state["allocation"] + 0x1020 + index * 4)
            result["classes"].append(row)
        result["controllers"] = snapshot(process, args.controller or (state or {}).get("controllers", []))
        print(json.dumps(result, indent=2))
    finally:
        process.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
