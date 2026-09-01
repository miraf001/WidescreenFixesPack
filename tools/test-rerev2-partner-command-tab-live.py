"""Reversible MP-only Tab alias for the native partner-command action.

Capcom's keyboard branch queries Tab but routes it to the first action in
sub_A18690.  With the active gamepad profile, Y (0x8000) follows the second
branch, which calls 0x701770 and sets output byte +0x20.  This test redirects
only the post-keyboard-query continuation:

* Tab false: retain the native secondary-key query.
* Tab true in SP: retain the native first-action path (character switch).
* Tab true in active split-screen: use the gamepad Y partner-command path.

No XInput state, key bindings, actor assignment, or game state is modified.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


spec = importlib.util.spec_from_file_location(
    "hud", Path(__file__).with_name("test-rerev2-sp-hud-live.py")
)
hud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hud)


SITE = 0x00A186FF
ORIGINAL = bytes.fromhex("8B 74 24 18 84 C0 EB 46")
GAME_STATE_POINTER = 0x0157AE00
KEYBOARD_OWNER_GATE = 0x00A186E6
MP_PARTNER_PATH = 0x00A18809
SP_FIRST_ACTION_PATH = 0x00A18753
TAB_FALSE_PATH = 0x00A187E4
VERSION = 1
SUPPORTED_ASI_HASH = (
    "8e527e0b43f6c7358082ad14c07db5bd79b336bf7a0ddd657ab121254e9fd592"
)

GUARDS = (
    (0x00A186D9, bytes.fromhex("39 AF 20 79 00 00")),
    (
        0x00A186EF,
        bytes.fromhex(
            "8B 0D 18 E9 5D 01 6A 02 55 6A 01 E8 E1 5A F8 FF"
        ),
    ),
    (
        MP_PARTNER_PATH,
        bytes.fromhex("8B CF E8 60 8F CE FF 84 C0 74 04 C6 43 20 01"),
    ),
    (
        SP_FIRST_ACTION_PATH,
        bytes.fromhex("6A 00 8B CF E8 D4 8C CE FF 84 C0"),
    ),
    (
        TAB_FALSE_PATH,
        bytes.fromhex("57 8B CB E8 D4 C6 FF FF 84 C0"),
    ),
)


def redirect(site: int, target: int, size: int) -> bytes:
    if size < 5:
        raise RuntimeError("Redirect requires at least five bytes")
    return b"\xE9" + hud.u32((target - site - 5) & 0xFFFFFFFF) + b"\x90" * (size - 5)


def make_thunk(address: int, counter: int) -> bytes:
    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str]] = []

    def emit(value: str | bytes) -> None:
        code.extend(bytes.fromhex(value) if isinstance(value, str) else value)

    def branch(opcode: str, label: str) -> None:
        emit(opcode)
        fixups.append((len(code), label))
        emit(bytes(4))

    def absolute_jump(target: int) -> None:
        emit("E9")
        displacement = target - (address + len(code) + 4)
        emit(struct.pack("<i", displacement))

    # Reproduce the displaced keyboard-only continuation.
    emit("8B 74 24 18")  # mov esi,[esp+18]
    emit("84 C0")        # test al,al
    branch("0F 84", "tab_false")

    # Runtime MP test.  The patch remains installed safely when returning to SP.
    emit("A1")
    emit(hud.u32(GAME_STATE_POINTER))
    emit("85 C0")
    branch("0F 84", "single_player")
    emit("83 B8 F0 08 00 00 01")
    branch("0F 85", "single_player")
    emit("83 B8 F4 08 00 00 01")
    branch("0F 85", "single_player")

    # Same downstream eligibility and output path reached by gamepad Y.
    emit("F0 FF 05")
    emit(hud.u32(counter))
    absolute_jump(MP_PARTNER_PATH)

    labels["single_player"] = len(code)
    absolute_jump(SP_FIRST_ACTION_PATH)

    labels["tab_false"] = len(code)
    absolute_jump(TAB_FALSE_PATH)

    for offset, label in fixups:
        struct.pack_into("<i", code, offset, labels[label] - offset - 4)
    if len(code) > 4096:
        raise RuntimeError("Partner-command thunk exceeds one page")
    return bytes(code)


def game_state(process) -> dict:
    mode = process.integer(GAME_STATE_POINTER)
    return {
        "pointer": mode,
        "splitMode": process.integer(mode + 0x8F0) if mode else None,
        "splitState": process.integer(mode + 0x8F4) if mode else None,
        "playerAssignment": (
            [process.integer(mode + 0x8F8), process.integer(mode + 0x8FC)]
            if mode
            else None
        ),
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
    for address, expected in GUARDS:
        process.expect(address, expected)
    owner_gate = process.read(KEYBOARD_OWNER_GATE, 7)
    if owner_gate[0] != 0xE9 or owner_gate[-2:] != b"\x90\x90":
        raise RuntimeError("Permanent keyboard-owner gate is not active")
    return asi_hash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument(
        "--mode", choices=("apply", "inspect", "restore"), default="inspect"
    )
    args = parser.parse_args()

    state = (
        json.loads(args.state.read_text(encoding="utf-8"))
        if args.state.exists()
        else None
    )
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
            current_game_state = game_state(process)
            if (
                current_game_state["splitMode"] != 1
                or current_game_state["splitState"] != 1
            ):
                raise RuntimeError("Apply only while split-screen is active")

            allocation = process.k.VirtualAllocEx(
                process.handle, None, 8192, 0x3000, 0x04
            )
            process.check(allocation)
            if allocation + 8192 > 0x1_0000_0000:
                raise RuntimeError("Allocation is outside x86 address space")
            counter = allocation + 4096
            code = make_thunk(allocation, counter)
            patched = redirect(SITE, allocation, len(ORIGINAL))
            state = {
                "pid": args.pid,
                "identity": identity,
                "version": VERSION,
                "status": "prepared",
                "asiHash": asi_hash,
                "allocation": allocation,
                "counter": counter,
                "code": code.hex(),
                "patch": {
                    "address": SITE,
                    "before": ORIGINAL.hex(),
                    "after": patched.hex(),
                },
                "policy": (
                    "Tab false keeps native secondary query; Tab true uses native first "
                    "action in SP and gamepad-Y partner action in active split-screen"
                ),
                "before": current_game_state,
            }
            process.write(allocation, code)
            process.expect(allocation, code)
            process.protect(allocation, 4096, 0x20)
            process.check(
                process.k.FlushInstructionCache(process.handle, allocation, len(code))
            )
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            hud.transact(process, [(SITE, ORIGINAL, patched)], guards=GUARDS)
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")

        elif args.mode == "restore":
            if not state or state["status"] not in ("prepared", "applied"):
                raise RuntimeError("No active partner-command Tab test")
            patched = bytes.fromhex(state["patch"]["after"])
            current = process.read(SITE, len(ORIGINAL))
            if current not in (ORIGINAL, patched):
                raise RuntimeError("Unexpected code at patch site; no writes performed")
            hud.transact(process, [(SITE, current, ORIGINAL)], guards=GUARDS)
            # Keep the executable page allocated until process exit for in-flight calls.
            state["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")

        if state:
            code = bytes.fromhex(state["code"])
            process.expect(int(state["allocation"]), code)
            patched = bytes.fromhex(state["patch"]["after"])
            expected = patched if state["status"] == "applied" else ORIGINAL
            process.expect(SITE, expected)

        print(
            json.dumps(
                {
                    "pid": args.pid,
                    "status": state["status"] if state else "native",
                    "site": process.read(SITE, len(ORIGINAL)).hex(),
                    "aliasCalls": (
                        process.integer(int(state["counter"])) if state else 0
                    ),
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
