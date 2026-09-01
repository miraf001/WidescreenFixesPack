"""Reversible MP-only Tab alias for A18690's native partner-command output.

The native keyboard query immediately before the hook is preserved.  In active
split-screen, and only for the actor assigned to player 1, held VK_TAB follows
the verified gamepad-Y branch that calls 0x701770 and sets output byte +0x20.
All other calls replay the original ``test al, al`` continuation, preserving
RMB and single-player ChangeCharacter behavior.  XInput and device selection
are never modified.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def load_tool(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_tool("partner_tab_base", "test-rerev2-partner-command-tab-live.py")
mask = load_tool("partner_tab_mask", "test-rerev2-partner-command-tab-mask-live.py")
hud = base.hud

SITE = 0x00A186FF
ORIGINAL = bytes.fromhex("8B 74 24 18 84 C0 EB 46")
MODE_POINTER = 0x0157AE00
ACTOR_MANAGER = 0x01567EAC
KEYBOARD_OWNER_GATE = 0x00A186E6
MP_PARTNER_PATH = 0x00A18809
NATIVE_CONTINUATION = 0x00A1874D
VK_TAB = 0x09
VERSION = 1
SUPPORTED_ASI_HASH = base.SUPPORTED_ASI_HASH

GUARDS = (
    (0x00A186D9, bytes.fromhex("39 AF 20 79 00 00")),
    (
        0x00A186EF,
        bytes.fromhex("8B 0D 18 E9 5D 01 6A 02 55 6A 01 E8 E1 5A F8 FF"),
    ),
    (
        MP_PARTNER_PATH,
        bytes.fromhex("8B CF E8 60 8F CE FF 84 C0 74 04 C6 43 20 01"),
    ),
)


def redirect(site: int, target: int, size: int) -> bytes:
    if size < 5:
        raise RuntimeError("Redirect requires at least five bytes")
    return b"\xE9" + hud.u32((target - site - 5) & 0xFFFFFFFF) + b"\x90" * (size - 5)


def make_thunk(address: int, counters: int, get_async_key_state: int) -> bytes:
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

    def absolute_jump(target: int) -> None:
        emit("E9")
        imm((target - (address + len(code) + 4)) & 0xFFFFFFFF)

    # First displaced instruction.  ESI is required by both native branches.
    emit("8B 74 24 18")  # mov esi,[esp+18]
    emit("9C 60")        # pushfd; pushad
    emit("F0 FF 05"); imm(counters + 0)  # calls

    # Active local split-screen only.
    emit("A1"); imm(MODE_POINTER)
    emit("85 C0"); branch("0F 84", "native")
    emit("83 B8 F0 08 00 00 01"); branch("0F 85", "native")
    emit("83 B8 F4 08 00 00 01"); branch("0F 85", "native")

    # Only the actor assigned to player 1.  PUSHAD saved original EDI at [esp].
    emit("8B 90 F8 08 00 00")       # mov edx,[eax+8f8]
    emit("83 FA 08"); branch("0F 83", "native")
    emit("8B 0D"); imm(ACTOR_MANAGER)
    emit("85 C9"); branch("0F 84", "native")
    emit("8B 3C 24")                # mov edi,[esp] (saved actor)
    emit("3B 7C 91 20"); branch("0F 85", "native")
    emit("F0 FF 05"); imm(counters + 4)  # eligible P1 frames

    # Query Tab only after the MP/P1 gates, so SP remains entirely native.
    emit("6A"); emit(bytes((VK_TAB,)))
    emit("B8"); imm(get_async_key_state)
    emit("FF D0")
    emit("66 A9 00 80"); branch("0F 84", "native")
    emit("F0 FF 05"); imm(counters + 8)  # Tab-down frames

    # Carry in the saved EFLAGS is a thread-local decision bit.  All native
    # flags are irrelevant because the native path recreates TEST AL,AL.
    emit("83 4C 24 20 01")
    branch("E9", "restore")

    label("native")
    emit("83 64 24 20 FE")

    label("restore")
    emit("61 9D")  # popad; popfd
    branch("0F 82", "partner")  # jc partner

    emit("F0 FF 05"); imm(counters + 12)  # native frames
    emit("84 C0")  # displaced test al,al
    absolute_jump(NATIVE_CONTINUATION)

    label("partner")
    emit("F0 FF 05"); imm(counters + 16)  # partner-command frames
    absolute_jump(MP_PARTNER_PATH)

    for offset, target in fixups:
        struct.pack_into("<i", code, offset, labels[target] - offset - 4)
    if len(code) > 4096:
        raise RuntimeError("Tab output thunk exceeds one page")
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
            if not any(row["slot"] == primary and row["id"] == 0 for row in current["actors"]):
                raise RuntimeError("Assigned primary actor has not been verified")

            user32_base, get_async_key_state = mask.target_user32(args.pid, process)
            allocation = process.k.VirtualAllocEx(process.handle, None, 8192, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 8192 > 0x1_0000_0000:
                raise RuntimeError("Allocation is outside x86 address space")
            counters = allocation + 4096
            code = make_thunk(allocation, counters, get_async_key_state)
            patched = redirect(SITE, allocation, len(ORIGINAL))
            state = {
                "pid": args.pid,
                "identity": identity,
                "version": VERSION,
                "status": "prepared",
                "asiHash": asi_hash,
                "allocation": allocation,
                "counters": counters,
                "code": code.hex(),
                "user32": {"base": user32_base, "GetAsyncKeyState": get_async_key_state},
                "patch": {"address": SITE, "before": ORIGINAL.hex(), "after": patched.hex()},
                "policy": (
                    "MP assigned P1 held Tab follows verified A18690 output+0x20 path; "
                    "all other frames replay native TEST AL,AL; SP/P2/RMB/XInput untouched"
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
                raise RuntimeError("No active Tab output experiment")
            patched = bytes.fromhex(state["patch"]["after"])
            actual = process.read(SITE, len(ORIGINAL))
            if actual not in (ORIGINAL, patched):
                raise RuntimeError("Unexpected patch-site bytes; no writes performed")
            hud.transact(process, [(SITE, actual, ORIGINAL)], guards=GUARDS)
            state["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")

        counter_values = None
        if state:
            process.expect(int(state["allocation"]), bytes.fromhex(state["code"]))
            patched = bytes.fromhex(state["patch"]["after"])
            process.expect(SITE, patched if state["status"] == "applied" else ORIGINAL)
            counter_values = dict(
                zip(
                    ("calls", "eligibleP1", "tabDown", "native", "partner"),
                    struct.unpack("<5I", process.read(int(state["counters"]), 20)),
                )
            )

        print(
            json.dumps(
                {
                    "pid": args.pid,
                    "status": state["status"] if state else "native",
                    "site": process.read(SITE, len(ORIGINAL)).hex(),
                    "counters": counter_values,
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
