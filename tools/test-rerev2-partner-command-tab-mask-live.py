"""Reversible MP-only Tab -> native partner-command gameplay-mask test.

Clean traces established that physical gamepad Y (0x8000) reaches the common
per-actor action dispatcher as gameplay input bit 0x1000.  Keyboard Tab has no
equivalent MP query.  This hook runs immediately before that dispatcher and,
only for the assigned P1 actor in active split-screen, adds a one-frame 0x1000
pulse on the rising edge of VK_TAB.

Single-player never calls GetAsyncKeyState here and retains Capcom's native Tab
character switch.  Mouse queries, XInput state, device selection and P2 input
are untouched.
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


SITE = 0x00A16C6F
ORIGINAL = bytes.fromhex("F3 0F 10 84 24 8C 00 00 00")
CONTINUATION = SITE + len(ORIGINAL)
MODE_POINTER = 0x0157AE00
ACTOR_MANAGER = 0x01567EAC
KEYBOARD_OWNER_GATE = 0x00A186E6
VK_TAB = 0x09
PARTNER_COMMAND = 0x00001000
VERSION = 1
SUPPORTED_ASI_HASH = (
    "8e527e0b43f6c7358082ad14c07db5bd79b336bf7a0ddd657ab121254e9fd592"
)

GUARDS = (
    (0x00A16C60, bytes.fromhex("87 84 0A 00 00 00 00 00 00 EB 04 8B 44 24 28")),
    (
        CONTINUATION,
        bytes.fromhex(
            "83 EC 08 8B CF F3 0F 11 44 24 04 F3 0F 10 44 24 60 "
            "F3 0F 11 04 24"
        ),
    ),
    (
        0x00A16D56,
        bytes.fromhex(
            "FF 74 24 44 8B CF FF 74 24 28 FF 74 24 30 56 "
            "E8 26 19 00 00"
        ),
    ),
)


def redirect(site: int, target: int, size: int) -> bytes:
    if size < 5:
        raise RuntimeError("Redirect requires at least five bytes")
    return b"\xE9" + hud.u32((target - site - 5) & 0xFFFFFFFF) + b"\x90" * (size - 5)


def make_thunk(address: int, data: int, get_async_key_state: int) -> bytes:
    """Preserve the complete CPU context and pulse the common input mask.

    At SITE, original ESP+0x28 is the input-mask local later passed as arg1 to
    every child action handler.  PUSHAD records (original ESP-4) at its saved
    ESP slot because PUSHFD precedes it; therefore saved_esp+0x2c addresses the
    original mask.  XMM0..7 are explicitly preserved across USER32.
    """

    previous_down = data
    calls = data + 4
    eligible = data + 8
    edges = data + 12
    injected = data + 16
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

    emit("9C 60 81 EC 80 00 00 00")  # PUSHFD, PUSHAD, reserve XMM save area
    # movdqu [esp+n],xmm0..7
    emit("F3 0F 7F 04 24")
    for register in range(1, 8):
        emit(bytes((0xF3, 0x0F, 0x7F, 0x44 | (register << 3), 0x24, register * 0x10)))

    emit("F0 FF 05"); imm(calls)
    emit("A1"); imm(MODE_POINTER)
    emit("85 C0"); branch("0F 84", "inactive")
    emit("83 B8 F0 08 00 00 01"); branch("0F 85", "inactive")
    emit("83 B8 F4 08 00 00 01"); branch("0F 85", "inactive")

    emit("8B 90 F8 08 00 00 83 FA 08")
    branch("0F 83", "not_primary")
    emit("8B 0D"); imm(ACTOR_MANAGER)
    emit("85 C9"); branch("0F 84", "not_primary")
    emit("8B 9C 24 84 00 00 00")  # saved ESI = current actor
    emit("3B 5C 91 20"); branch("0F 85", "not_primary")

    emit("F0 FF 05"); imm(eligible)
    emit("6A"); emit(bytes((VK_TAB,)))
    emit("B8"); imm(get_async_key_state)
    emit("FF D0")
    emit("66 A9 00 80"); branch("0F 84", "released")
    emit("80 3D"); imm(previous_down); emit("00")
    emit("C6 05"); imm(previous_down); emit("01")
    branch("0F 85", "done")
    emit("F0 FF 05"); imm(edges)
    emit("8B 9C 24 8C 00 00 00")  # saved ESP immediately after PUSHFD
    emit("81 4B 2C"); imm(PARTNER_COMMAND)
    emit("F0 FF 05"); imm(injected)
    branch("E9", "done")

    label("released")
    emit("C6 05"); imm(previous_down); emit("00")
    branch("E9", "done")

    label("inactive")
    # Avoid carrying a stale held state across an MP/SP transition.  This does
    # not inspect or consume Tab in SP.
    emit("C6 05"); imm(previous_down); emit("00")
    label("not_primary")
    label("done")

    # movdqu xmm0..7,[esp+n]
    emit("F3 0F 6F 04 24")
    for register in range(1, 8):
        emit(bytes((0xF3, 0x0F, 0x6F, 0x44 | (register << 3), 0x24, register * 0x10)))
    emit("81 C4 80 00 00 00 61 9D")
    emit(ORIGINAL)
    emit("E9")
    imm((CONTINUATION - (address + len(code) + 4)) & 0xFFFFFFFF)

    for offset, target in fixups:
        struct.pack_into("<i", code, offset, labels[target] - offset - 4)
    if len(code) > 4096:
        raise RuntimeError("Tab gameplay-mask thunk exceeds one page")
    return bytes(code)


def game_state(process) -> dict:
    mode = process.integer(MODE_POINTER)
    manager = process.integer(ACTOR_MANAGER)
    assignments = (
        [process.integer(mode + 0x8F8), process.integer(mode + 0x8FC)] if mode else None
    )
    actors = []
    if manager:
        for slot in range(8):
            actor = process.integer(manager + 0x20 + slot * 4)
            if actor:
                actors.append(
                    {
                        "slot": slot,
                        "pointer": actor,
                        "id": process.read(actor + 0x790C, 1)[0],
                    }
                )
    return {
        "pointer": mode,
        "splitMode": process.integer(mode + 0x8F0) if mode else None,
        "splitState": process.integer(mode + 0x8F4) if mode else None,
        "playerAssignment": assignments,
        "actors": actors,
    }


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


def target_user32(pid: int, process) -> tuple[int, int]:
    """Resolve GetAsyncKeyState from the running target's 32-bit USER32.

    Its build-pinned RVA is guarded by executable bytes in the target.  The
    module base itself is obtained from the target process rather than assuming
    a fixed ASLR address.
    """

    # On this supported Windows build, the x86 export RVA is 0x99F90.  Resolve
    # USER32's target-process base with Toolhelp so ASLR is never assumed.
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
        user32_base = None
        while True:
            if entry.szModule.lower() == "user32.dll":
                user32_base = int(entry.modBaseAddr)
                break
            if not kernel.Module32NextW(snapshot, ctypes.byref(entry)):
                break
        if user32_base is None:
            raise RuntimeError("USER32.dll is not loaded in the target")
    finally:
        kernel.CloseHandle(snapshot)
    function = user32_base + 0x99F90
    process.expect(function, bytes.fromhex("E9"))
    return user32_base, function


def validate(process, identity: dict) -> str:
    asi = (
        Path(identity["image"]).parent
        / "scripts"
        / "ResidentEvilRevelations2.FusionFix.asi"
    )
    asi_hash = hashlib.sha256(asi.read_bytes()).hexdigest()
    if asi_hash != SUPPORTED_ASI_HASH:
        raise RuntimeError(f"Unsupported deployed ASI {asi_hash}")
    for target, expected in GUARDS:
        process.expect(target, expected)
    owner_gate = process.read(KEYBOARD_OWNER_GATE, 7)
    if owner_gate[0] != 0xE9 or owner_gate[-2:] != b"\x90\x90":
        raise RuntimeError("Permanent keyboard-owner gate is not active")
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
        if state and (
            state["pid"] != args.pid
            or state["identity"] != identity
            or state.get("version") != VERSION
        ):
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

            user32_base, get_async_key_state = target_user32(args.pid, process)
            allocation = process.k.VirtualAllocEx(process.handle, None, 8192, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 8192 > 0x1_0000_0000:
                raise RuntimeError("Allocation is outside x86 address space")
            data = allocation + 4096
            code = make_thunk(allocation, data, get_async_key_state)
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
                "user32": {"base": user32_base, "GetAsyncKeyState": get_async_key_state},
                "patch": {"address": SITE, "before": ORIGINAL.hex(), "after": patched.hex()},
                "policy": (
                    "Active split-screen assigned P1 only: rising VK_TAB pulses common "
                    "gameplay mask bit 0x1000 for one frame; SP/P2/mouse/XInput untouched"
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
                raise RuntimeError("No active Tab gameplay-mask experiment")
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
            raw = process.read(int(state["data"]), 20)
            counters = dict(
                zip(
                    ("previousDownWord", "calls", "eligibleP1", "tabEdges", "injected"),
                    struct.unpack("<5I", raw),
                )
            )

        print(
            json.dumps(
                {
                    "pid": args.pid,
                    "status": state["status"] if state else "native",
                    "site": process.read(SITE, len(ORIGINAL)).hex(),
                    "counters": counters,
                    "gameState": game_state(process),
                    "asiHash": asi_hash,
                },
                indent=2,
            )
        )
    finally:
        process.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
