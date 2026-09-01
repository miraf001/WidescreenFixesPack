"""Reversible MP-only Tab repair in the native ChangeCharacter handler.

sub_A16F90 is build-pinned as ChangeCharacter: its keyboard branch queries
action index 0x29, matching ChangeCharacter's ordered config.ini entry, while
its controller branch selects gameplay mask 0x1000.  Both branches converge at
0xA170FC before the game's own SP/MP behavior split.

This hook replaces only the keyboard branch's post-query jump.  In active
split-screen for the assigned P1 actor it supplies a rising VK_TAB edge; in SP
it forwards Capcom's original AL result exactly.  No mouse query, global input
mask, XInput state, action output or actor field is modified.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
from ctypes import wintypes


spec = importlib.util.spec_from_file_location(
    "hud", Path(__file__).with_name("test-rerev2-sp-hud-live.py")
)
hud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hud)


SITE = 0x00A17038
ORIGINAL = bytes.fromhex("E9 BF 00 00 00")
CONTINUATION = 0x00A170FC
MODE_POINTER = 0x0157AE00
ACTOR_MANAGER = 0x01567EAC
VK_TAB = 0x09
VERSION = 1
SUPPORTED_ASI_HASH = (
    "8e527e0b43f6c7358082ad14c07db5bd79b336bf7a0ddd657ab121254e9fd592"
)

GUARDS = (
    (
        0x00A1700B,
        bytes.fromhex(
            "56 57 8B CB C6 44 24 14 00 E8 A7 DE FF FF 84 C0 74 20 "
            "6A 02 6A 29 C7 83 64 0A 00 00 00 00 00 00 8B 0D 18 E9 5D 01 "
            "6A 03 E8 A8 71 F8 FF"
        ),
    ),
    (
        CONTINUATION,
        bytes.fromhex(
            "84 C0 0F 84 83 00 00 00 8B 0D 00 AE 57 01 E8 51 07 E7 FF"
        ),
    ),
    (
        0x00A1703D,
        bytes.fromhex(
            "8B 35 00 AE 57 01 55 6A 01 8B CF 33 ED E8 61 5D CE FF"
        ),
    ),
)


def redirect(site: int, target: int, size: int) -> bytes:
    return b"\xE9" + hud.u32((target - site - 5) & 0xFFFFFFFF) + b"\x90" * (size - 5)


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    )


def target_get_async_key_state(pid: int, process) -> tuple[int, int]:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel.Module32FirstW.restype = wintypes.BOOL
    kernel.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel.Module32NextW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(0x08 | 0x10, pid)
    if snapshot == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel.Module32FirstW(snapshot, ctypes.byref(entry)):
            raise ctypes.WinError(ctypes.get_last_error())
        user32 = None
        while True:
            if entry.szModule.lower() == "user32.dll":
                user32 = int(entry.modBaseAddr)
                break
            if not kernel.Module32NextW(snapshot, ctypes.byref(entry)):
                break
        if user32 is None:
            raise RuntimeError("USER32.dll is not loaded in the target")
    finally:
        kernel.CloseHandle(snapshot)
    function = user32 + 0x99F90
    process.expect(function, b"\xE9")
    return user32, function


def make_thunk(address: int, data: int, get_async_key_state: int) -> bytes:
    previous_down = data
    calls = data + 4
    eligible = data + 8
    edges = data + 12
    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str]] = []

    def emit(value: str | bytes) -> None:
        code.extend(bytes.fromhex(value) if isinstance(value, str) else value)

    def imm(value: int) -> None:
        emit(hud.u32(value))

    def label(name: str) -> None:
        labels[name] = len(code)

    def branch(opcode: str, target: str) -> None:
        emit(opcode)
        fixups.append((len(code), target))
        emit(bytes(4))

    # Preserve every register/flag and XMM register across USER32.  Saved EAX
    # at [esp+0x9c] contains Capcom's keyboard-query result; only its AL byte is
    # replaced in the eligible MP branch.
    emit("9C 60 81 EC 80 00 00 00")
    emit("F3 0F 7F 04 24")
    for register in range(1, 8):
        emit(bytes((0xF3, 0x0F, 0x7F, 0x44 | (register << 3), 0x24, register * 0x10)))
    emit("F0 FF 05"); imm(calls)

    emit("A1"); imm(MODE_POINTER)
    emit("85 C0"); branch("0F 84", "inactive")
    emit("83 B8 F0 08 00 00 01"); branch("0F 85", "inactive")
    emit("83 B8 F4 08 00 00 01"); branch("0F 85", "inactive")
    emit("8B 90 F8 08 00 00 83 FA 08"); branch("0F 83", "done")
    emit("8B 0D"); imm(ACTOR_MANAGER)
    emit("85 C9"); branch("0F 84", "done")
    emit("8B 9C 24 80 00 00 00")  # saved EDI = actor in sub_A16F90
    emit("3B 5C 91 20"); branch("0F 85", "done")
    emit("F0 FF 05"); imm(eligible)

    emit("6A"); emit(bytes((VK_TAB,)))
    emit("B8"); imm(get_async_key_state)
    emit("FF D0")
    emit("66 A9 00 80"); branch("0F 84", "released")
    emit("80 3D"); imm(previous_down); emit("00")
    emit("C6 05"); imm(previous_down); emit("01")
    branch("0F 85", "not_edge")
    emit("C6 84 24 9C 00 00 00 01")
    emit("F0 FF 05"); imm(edges)
    branch("E9", "done")

    label("not_edge")
    emit("C6 84 24 9C 00 00 00 00")
    branch("E9", "done")
    label("released")
    emit("C6 05"); imm(previous_down); emit("00")
    emit("C6 84 24 9C 00 00 00 00")
    branch("E9", "done")
    label("inactive")
    # Outside MP, preserve Capcom's AL and only clear our private edge latch.
    emit("C6 05"); imm(previous_down); emit("00")
    label("done")

    emit("F3 0F 6F 04 24")
    for register in range(1, 8):
        emit(bytes((0xF3, 0x0F, 0x6F, 0x44 | (register << 3), 0x24, register * 0x10)))
    emit("81 C4 80 00 00 00 61 9D E9")
    imm((CONTINUATION - (address + len(code) + 4)) & 0xFFFFFFFF)

    for offset, target in fixups:
        struct.pack_into("<i", code, offset, labels[target] - offset - 4)
    if len(code) > 4096:
        raise RuntimeError("ChangeCharacter Tab thunk exceeds one page")
    return bytes(code)


def game_state(process) -> dict:
    mode = process.integer(MODE_POINTER)
    manager = process.integer(ACTOR_MANAGER)
    assignments = [process.integer(mode + 0x8F8), process.integer(mode + 0x8FC)] if mode else None
    actors = []
    if manager:
        for slot in range(8):
            actor = process.integer(manager + 0x20 + slot * 4)
            if actor:
                actors.append({"slot": slot, "pointer": actor, "id": process.read(actor + 0x790C, 1)[0]})
    return {
        "pointer": mode,
        "splitMode": process.integer(mode + 0x8F0) if mode else None,
        "splitState": process.integer(mode + 0x8F4) if mode else None,
        "playerAssignment": assignments,
        "actors": actors,
    }


def validate(process, identity: dict) -> str:
    asi = Path(identity["image"]).parent / "scripts" / "ResidentEvilRevelations2.FusionFix.asi"
    asi_hash = hashlib.sha256(asi.read_bytes()).hexdigest()
    if asi_hash != SUPPORTED_ASI_HASH:
        raise RuntimeError(f"Unsupported deployed ASI {asi_hash}")
    for target, expected in GUARDS:
        process.expect(target, expected)
    return asi_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mode", choices=("apply", "inspect", "restore"), default="inspect")
    args = parser.parse_args()
    state = json.loads(args.state.read_text(encoding="utf-8")) if args.state.exists() else None
    process = hud.Process(args.pid, args.mode != "inspect")
    try:
        identity = process.identity()
        if state and (state["pid"] != args.pid or state["identity"] != identity or state.get("version") != VERSION):
            raise RuntimeError("State belongs to a different process or test version")
        asi_hash = validate(process, identity)

        if args.mode == "apply":
            if state:
                raise RuntimeError("Use a fresh state path; backups are never overwritten")
            process.expect(SITE, ORIGINAL)
            current = game_state(process)
            if current["splitMode"] != 1 or current["splitState"] != 1:
                raise RuntimeError("Apply only while split-screen is active")
            primary = current["playerAssignment"][0]
            if not any(a["slot"] == primary and a["id"] == primary for a in current["actors"]):
                raise RuntimeError("Primary actor assignment has not been verified")
            user32, get_key = target_get_async_key_state(args.pid, process)
            allocation = process.k.VirtualAllocEx(process.handle, None, 8192, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 8192 > 0x1_0000_0000:
                raise RuntimeError("Allocation is outside x86 address space")
            data = allocation + 4096
            code = make_thunk(allocation, data, get_key)
            patched = redirect(SITE, allocation, len(ORIGINAL))
            state = {
                "pid": args.pid,
                "identity": identity,
                "version": VERSION,
                "status": "prepared",
                "asiHash": asi_hash,
                "allocation": allocation,
                "data": data,
                "code": code.hex(),
                "user32": {"base": user32, "GetAsyncKeyState": get_key},
                "patch": {"address": SITE, "before": ORIGINAL.hex(), "after": patched.hex()},
                "policy": (
                    "Only sub_A16F90 ChangeCharacter keyboard result: active split P1 uses "
                    "rising VK_TAB; SP forwards native config-query AL; all other input untouched"
                ),
                "before": current,
            }
            process.write(allocation, code)
            process.expect(allocation, code)
            process.protect(allocation, 4096, 0x20)
            process.check(process.k.FlushInstructionCache(process.handle, allocation, len(code)))
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            hud.transact(process, [(SITE, ORIGINAL, patched)], guards=GUARDS)
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")

        elif args.mode == "restore":
            if not state or state["status"] not in ("prepared", "applied"):
                raise RuntimeError("No active ChangeCharacter Tab experiment")
            patched = bytes.fromhex(state["patch"]["after"])
            actual = process.read(SITE, len(ORIGINAL))
            if actual not in (ORIGINAL, patched):
                raise RuntimeError("Unexpected patch-site bytes; no writes performed")
            hud.transact(process, [(SITE, actual, ORIGINAL)], guards=GUARDS)
            state["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")

        counters = None
        if state:
            process.expect(int(state["allocation"]), bytes.fromhex(state["code"]))
            patched = bytes.fromhex(state["patch"]["after"])
            process.expect(SITE, patched if state["status"] == "applied" else ORIGINAL)
            counters = dict(zip(("previousDown", "handlerCalls", "eligibleP1", "tabEdges"), struct.unpack("<4I", process.read(int(state["data"]), 16))))
        print(json.dumps({
            "pid": args.pid,
            "status": state["status"] if state else "native",
            "site": process.read(SITE, len(ORIGINAL)).hex(),
            "counters": counters,
            "gameState": game_state(process),
            "asiHash": asi_hash,
        }, indent=2))
    finally:
        process.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
