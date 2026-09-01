"""Reversible live test for viewport-clamped co-op partner command markers.

uGUICommandNear already contains a native clamp against the physical rectangle
of its owning player view.  The game leaves that path disabled at +0x2F8.  This
test enables only that existing per-controller flag; it does not patch code,
change projection math, or use resolution-specific coordinates.

P1 can use that native clamp because its physical and viewport-local origins are
both zero. P2 projection is already viewport-local, so its physical native clamp
must stay disabled; an optional update wrapper instead clamps P2 directly to its
cached local rectangle.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "hud", Path(__file__).with_name("test-rerev2-sp-hud-live.py")
)
hud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hud)

NEAR_VTABLE = 0x0139ACA0
NEAR_UPDATE_SLOT = NEAR_VTABLE + 0x24
NEAR_UPDATE = 0x008E34F0
CLAMP_FLAG_OFFSET = 0x2F8
GFX_POINTER = 0x015DE88C
GAME_STATE_POINTER = 0x0157AE00
NATIVE_SAFE_MARGIN = 0x014DD080
SUPPORTED_ASI_HASH = (
    "8e527e0b43f6c7358082ad14c07db5bd79b336bf7a0ddd657ab121254e9fd592"
)


def make_update_localizer(address: int, counter: int) -> bytes:
    """Call native Near update, then clamp only P2 in viewport-local space."""
    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str]] = []

    def emit(value: str | bytes) -> None:
        code.extend(bytes.fromhex(value) if isinstance(value, str) else value)

    def jump(opcode: str, label: str) -> None:
        emit(opcode)
        fixups.append((len(code), label))
        emit(bytes(4))

    # Preserve this and the native EAX return value.
    emit("56 8B F1 B8")
    emit(hud.u32(NEAR_UPDATE))
    emit("FF D0 50")
    emit("81 3E")
    emit(hud.u32(NEAR_VTABLE))
    jump("0F 85", "done")
    emit("8B 15")
    emit(hud.u32(GAME_STATE_POINTER))
    emit("85 D2")
    jump("0F 84", "done")
    for offset in (0x8F0, 0x8F4):
        emit("83 BA")
        emit(hud.u32(offset))
        emit("01")
        jump("0F 85", "done")
    emit("83 BE AC 02 00 00 01")
    jump("0F 85", "done")
    emit("80 BE F8 02 00 00 00")
    jump("0F 85", "done")

    # The cached rectangle is local (0..viewport width/height) for both players.
    # P2 uses it directly, with the same native 40-pixel safe margin as P1.
    for position, low, high in ((0x40, 0x168, 0x170), (0x44, 0x16C, 0x174)):
        emit("F3 0F 2A 86")
        emit(hud.u32(low))
        emit("F3 0F 58 05")
        emit(hud.u32(NATIVE_SAFE_MARGIN))
        emit("F3 0F 2A 8E")
        emit(hud.u32(high))
        emit("F3 0F 5C 0D")
        emit(hud.u32(NATIVE_SAFE_MARGIN))
        emit("0F 2F C8")
        jump("0F 86", "done")
        emit("F3 0F 10 96")
        emit(hud.u32(position))
        emit("F3 0F 5F D0 F3 0F 5D D1 F3 0F 11 96")
        emit(hud.u32(position))
    emit("F0 FF 05")
    emit(hud.u32(counter))

    labels["done"] = len(code)
    emit("58 5E C3")
    for offset, label in fixups:
        struct.pack_into("<i", code, offset, labels[label] - offset - 4)
    if len(code) > 4096:
        raise RuntimeError("Near update localizer exceeds one executable page")
    return bytes(code)


def read_viewport(process, player: int) -> list[int]:
    gfx = process.integer(GFX_POINTER)
    if not gfx:
        raise RuntimeError("Missing graphics state")
    viewport = list(struct.unpack("<4i", process.read(gfx + 0x48 + player * 0x190, 16)))
    left, top, right, bottom = viewport
    if left < 0 or top < 0 or right <= left or bottom <= top:
        raise RuntimeError(f"Invalid player {player} viewport: {viewport}")
    return viewport


def validate_controller(process, controller: int, expected_player: int | None = None) -> dict:
    process.expect(controller, hud.u32(NEAR_VTABLE))
    player = process.integer(controller + 0x2AC)
    if player not in (0, 1):
        raise RuntimeError(f"Unexpected controller player {player}")
    if expected_player is not None and player != expected_player:
        raise RuntimeError(
            f"Controller 0x{controller:08X} changed player: {player} != {expected_player}"
        )
    root = process.integer(controller + 0xF4)
    if not root:
        raise RuntimeError(f"Controller 0x{controller:08X} has no loaded render root")
    process.expect(root + 0x6C, hud.u32(controller))
    return {
        "controller": controller,
        "player": player,
        "root": root,
        "viewport": read_viewport(process, player),
        "flagAddress": controller + CLAMP_FLAG_OFFSET,
    }


def validate_process(process, identity: dict, state: dict | None = None) -> str:
    asi = (
        Path(identity["image"]).parent
        / "scripts"
        / "ResidentEvilRevelations2.FusionFix.asi"
    )
    asi_hash = hashlib.sha256(asi.read_bytes()).hexdigest()
    if asi_hash != SUPPORTED_ASI_HASH:
        raise RuntimeError(f"Unsupported deployed ASI {asi_hash}")
    localizer = (state or {}).get("updateLocalizer")
    if localizer and localizer.get("status") == "applied":
        process.expect(NEAR_UPDATE_SLOT, hud.u32(int(localizer["allocation"])))
        process.expect(
            int(localizer["allocation"]),
            bytes.fromhex(localizer["code"]),
        )
    else:
        process.expect(NEAR_UPDATE_SLOT, hud.u32(NEAR_UPDATE))
    process.expect(0x008E3B01, bytes.fromhex("80 BF F8 02 00 00 00"))
    process.expect(0x008E3B7D, bytes.fromhex("F3 0F 11 5F 40"))
    game_state = process.integer(GAME_STATE_POINTER)
    if not game_state or process.integer(game_state + 0x8F0) != 1:
        raise RuntimeError("Split-screen state is not active")
    return asi_hash


def public_state(state: dict, process) -> dict:
    result = dict(state)
    for entry in result.get("controllers", []):
        address = int(entry["flagAddress"])
        entry["currentFlag"] = process.read(address, 1).hex()
        try:
            live = validate_controller(
                process, int(entry["controller"]), int(entry["player"])
            )
            entry["currentViewport"] = live["viewport"]
            entry["currentPosition"] = list(
                struct.unpack("<2f", process.read(int(entry["controller"]) + 0x40, 8))
            )
        except (OSError, RuntimeError) as error:
            entry["liveValidation"] = str(error)
    localizer = result.get("updateLocalizer")
    if localizer:
        localizer["currentUpdate"] = f"0x{process.integer(NEAR_UPDATE_SLOT):08X}"
        localizer["localizationCalls"] = process.integer(int(localizer["counter"]))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument(
        "--controller",
        action="append",
        type=lambda value: int(value, 0),
        help="Active uGUICommandNear controller; repeat for both players",
    )
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument(
        "--mode",
        choices=(
            "apply",
            "add-localize",
            "disable-p2-native",
            "refine-p2-local",
            "inspect",
            "restore",
        ),
        default="inspect",
    )
    args = parser.parse_args()

    process = hud.Process(
        args.pid,
        args.mode
        in ("apply", "add-localize", "disable-p2-native", "refine-p2-local", "restore"),
    )
    try:
        identity = process.identity()
        state = json.loads(args.state.read_text(encoding="utf-8")) if args.state.exists() else None
        if state and (state["pid"] != args.pid or state["identity"] != identity):
            raise RuntimeError("Stale process state")
        asi_hash = validate_process(process, identity, state)

        if args.mode == "apply":
            if state:
                raise RuntimeError("Use a fresh state path")
            if not args.controller:
                raise RuntimeError("Apply requires at least one active controller")
            rows = [validate_controller(process, address) for address in args.controller]
            if len({row["controller"] for row in rows}) != len(rows):
                raise RuntimeError("Duplicate controller")
            if len(rows) > 1 and {row["player"] for row in rows} != {0, 1}:
                raise RuntimeError("Two-controller test must cover player 0 and player 1")
            for row in rows:
                process.expect(row["flagAddress"], b"\x00")
            state = {
                "pid": args.pid,
                "identity": identity,
                "status": "prepared",
                "asiHash": asi_hash,
                "policy": "enable native uGUICommandNear clamp against each physical player viewport",
                "nativeClampSite": "0x008E3B01",
                "controllers": [
                    {**row, "before": "00", "after": "01"} for row in rows
                ],
            }
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            try:
                with process.suspended():
                    for row in state["controllers"]:
                        process.expect(int(row["flagAddress"]), b"\x00")
                    for row in state["controllers"]:
                        process.write(int(row["flagAddress"]), b"\x01")
                    for row in state["controllers"]:
                        process.expect(int(row["flagAddress"]), b"\x01")
            except BaseException:
                with process.suspended():
                    for row in state["controllers"]:
                        if process.read(int(row["flagAddress"]), 1) == b"\x01":
                            process.write(int(row["flagAddress"]), b"\x00")
                raise
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif not state:
            raise RuntimeError("No saved state")
        elif args.mode == "add-localize":
            if state["status"] != "applied" or state.get("updateLocalizer"):
                raise RuntimeError("Localizer requires the active flag-only test")
            for row in state["controllers"]:
                process.expect(int(row["flagAddress"]), bytes.fromhex(row["after"]))
            process.expect(NEAR_UPDATE_SLOT, hud.u32(NEAR_UPDATE))
            allocation = process.k.VirtualAllocEx(
                process.handle, None, 8192, 0x3000, 0x04
            )
            process.check(allocation)
            if allocation + 8192 > 0x1_0000_0000:
                raise RuntimeError("Near localizer allocation is outside x86 address space")
            counter = allocation + 4096
            code = make_update_localizer(allocation, counter)
            process.write(allocation, code)
            process.expect(allocation, code)
            process.protect(allocation, 4096, 0x20)
            process.check(
                process.k.FlushInstructionCache(process.handle, allocation, len(code))
            )
            state["updateLocalizer"] = {
                "allocation": allocation,
                "counter": counter,
                "slot": NEAR_UPDATE_SLOT,
                "before": f"{NEAR_UPDATE:08x}",
                "after": f"{allocation:08x}",
                "code": code.hex(),
                "policy": "subtract owning physical viewport origin from each newly projected Near position",
                "status": "prepared",
            }
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            hud.transact(
                process,
                [(NEAR_UPDATE_SLOT, hud.u32(NEAR_UPDATE), hud.u32(allocation))],
            )
            state["updateLocalizer"]["status"] = "applied"
            state["policy"] = (
                "enable native Near clamp, then convert physical projection to owning viewport-local coordinates"
            )
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "disable-p2-native":
            localizer = state.get("updateLocalizer")
            if state["status"] != "applied" or not localizer or localizer.get("status") != "applied":
                raise RuntimeError("P2 native-clamp test requires the active localizer")
            matches = [row for row in state["controllers"] if int(row["player"]) == 1]
            if len(matches) != 1:
                raise RuntimeError("Expected exactly one P2 Near controller")
            row = matches[0]
            if row.get("active", row["after"]) != "01":
                raise RuntimeError("P2 native clamp is already disabled")
            with process.suspended():
                process.expect(int(row["flagAddress"]), b"\x01")
                process.write(int(row["flagAddress"]), b"\x00")
                process.expect(int(row["flagAddress"]), b"\x00")
            row["active"] = "00"
            state["p2NativeClamp"] = {
                "status": "disabled",
                "reason": "P2 projection is viewport-local; physical native bounds pin valid x to their left edge",
            }
            state["policy"] = (
                "P1 uses native Near clamp; P2 native physical clamp is disabled while its local projection is measured"
            )
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "refine-p2-local":
            localizer = state.get("updateLocalizer")
            p2 = state.get("p2NativeClamp")
            if (
                state["status"] != "applied"
                or not localizer
                or localizer.get("status") != "applied"
                or not p2
                or p2.get("status") != "disabled"
            ):
                raise RuntimeError("P2 local clamp requires the disabled P2 native clamp")
            allocation = int(localizer["allocation"])
            counter = int(localizer["counter"])
            previous = bytes.fromhex(localizer["code"])
            replacement = make_update_localizer(allocation, counter)
            if previous == replacement:
                raise RuntimeError("The active wrapper already uses the P2 local clamp")
            process.expect(NEAR_UPDATE_SLOT, hud.u32(allocation))
            process.expect(allocation, previous)
            process.expect(NATIVE_SAFE_MARGIN, struct.pack("<f", 40.0))
            hud.transact(process, [(allocation, previous, replacement)])
            localizer["previousCode"] = previous.hex()
            localizer["code"] = replacement.hex()
            localizer["policy"] = (
                "leave P1 native clamp active; clamp P2 raw projection to cached viewport-local bounds"
            )
            localizer["refinement"] = "P2 local x/y clamp"
            state["policy"] = (
                "P1 uses native local-equivalent clamp; P2 uses custom cached-rectangle local clamp"
            )
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "restore":
            if state["status"] != "applied":
                raise RuntimeError("No active test to restore")
            with process.suspended():
                localizer = state.get("updateLocalizer")
                if localizer and localizer.get("status") == "applied":
                    process.expect(NEAR_UPDATE_SLOT, hud.u32(int(localizer["allocation"])))
                    process.write(NEAR_UPDATE_SLOT, hud.u32(NEAR_UPDATE))
                for row in state["controllers"]:
                    validate_controller(
                        process, int(row["controller"]), int(row["player"])
                    )
                    process.expect(
                        int(row["flagAddress"]),
                        bytes.fromhex(row.get("active", row["after"])),
                    )
                for row in state["controllers"]:
                    process.write(int(row["flagAddress"]), bytes.fromhex(row["before"]))
            state["status"] = "restored"
            if state.get("updateLocalizer"):
                state["updateLocalizer"]["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")

        for row in state["controllers"]:
            expected = row.get("active", row["after"]) if state["status"] == "applied" else row["before"]
            process.expect(int(row["flagAddress"]), bytes.fromhex(expected))
        localizer = state.get("updateLocalizer")
        if localizer:
            expected_update = (
                int(localizer["allocation"])
                if localizer["status"] == "applied"
                else NEAR_UPDATE
            )
            process.expect(NEAR_UPDATE_SLOT, hud.u32(expected_update))
            process.expect(int(localizer["allocation"]), bytes.fromhex(localizer["code"]))
        print(json.dumps(public_state(state, process), indent=2))
    finally:
        process.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
