"""Reversible MP test for the uGUICommandFar viewport transform.

The deployed fork routes CommandFar through its legacy OFFSET draw wrapper.
In side-by-side split-screen that wrapper subtracts 1/GetDiff (0.625 at 16:9)
instead of the owning viewport's normal NDC origin (1.0), shifting the complete
arrow/distance group toward or beyond the other player view.  This test routes
only CommandFar through the already-loaded native/core GUI transform.  No node,
resolution, camera, gameplay, or other HUD class is changed.

The optional animation clamp wraps CommandFar's native timeline update and
clamps only the resulting child translations to the owning viewport's native
40-pixel safe area.  Scale, icon shape, text, angle and animation timing remain
unchanged.  Bounds are read from the controller every call, not hard-coded for
the captured resolution.
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

DRAW_ENTRY = 0x00E18040
FAR_DRAW_SLOT = 0x0139AB98
FAR_MP_CENTER_SITE = 0x008E2A13
FAR_ANIMATION_CALL = 0x008E323F
FAR_ANIMATION_UPDATE = 0x00E68DF0
FAR_ANIMATION_CALL_BYTES = bytes.fromhex("E8 AC 5B 58 00")
FAR_VTABLE = 0x0139AB40
NATIVE_SAFE_MARGIN = 0x014DD080
FAR_MP_CENTER_800 = struct.pack("<f", 800.0)
FAR_SP_CENTER_640 = struct.pack("<f", 640.0)
ASI_RESCALE_RVA = 0x2D60
ASI_CORE_RVA = 0x25C0
ASI_OFFSET_RVA = 0x3190
GAME_STATE_POINTER = 0x0157AE00
SUPPORTED_ASI_HASH = (
    "8e527e0b43f6c7358082ad14c07db5bd79b336bf7a0ddd657ab121254e9fd592"
)


def call_redirect(site: int, target: int) -> bytes:
    return b"\xE8" + hud.u32((target - site - 5) & 0xFFFFFFFF)


def make_animation_clamp(address: int, counter: int) -> bytes:
    """Call native timeline update, then clamp Far child translations in MP."""
    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str]] = []

    def emit(value: str | bytes) -> None:
        code.extend(bytes.fromhex(value) if isinstance(value, str) else value)

    def jump(opcode: str, label: str) -> None:
        emit(opcode)
        fixups.append((len(code), label))
        emit(bytes(4))

    # Preserve this and the native EAX result. The original function is
    # __thiscall and removes its two copied arguments; this wrapper removes the
    # original pair with RET 8.
    emit("56 8B F1 FF 74 24 0C FF 74 24 0C B8")
    emit(hud.u32(FAR_ANIMATION_UPDATE))
    emit("FF D0 50")
    emit("8B 46 6C 85 C0")
    jump("0F 84", "done")
    emit("81 38")
    emit(hud.u32(FAR_VTABLE))
    jump("0F 85", "done")

    # This must remain a split-screen-only correction.
    emit("8B 15")
    emit(hud.u32(GAME_STATE_POINTER))
    emit("85 D2")
    jump("0F 84", "done")
    for offset in (0x8F0, 0x8F4):
        emit("83 BA")
        emit(hud.u32(offset))
        emit("01")
        jump("0F 85", "done")

    emit("83 B8 AC 02 00 00 01")
    jump("0F 87", "done")
    emit("8B 8E E8 00 00 00 85 C9")
    jump("0F 84", "done")

    # CachedRectangle is viewport-relative for both players. Reuse the game's
    # own Near-marker safe margin so behavior stays consistent with native UI.
    emit("F3 0F 2A 80 68 01 00 00")
    emit("F3 0F 58 05")
    emit(hud.u32(NATIVE_SAFE_MARGIN))
    emit("F3 0F 2A 88 70 01 00 00")
    emit("F3 0F 5C 0D")
    emit(hud.u32(NATIVE_SAFE_MARGIN))
    emit("0F 2F C8")
    jump("0F 86", "done")

    # Slot 0 contains the parent viewport matrix. Slot 1 contains the animated
    # canonical translation. Keep both that source value and all resulting
    # child matrices in the same safe area: the renderer can cull from the
    # source translation before consuming the final matrix.
    emit("8B 11 85 D2")
    jump("0F 84", "done")
    emit("F3 0F 10 62 10 0F 57 ED 0F 2F E5")
    jump("0F 86", "done")
    emit("F3 0F 10 5A 40")
    emit("8B 51 04 85 D2")
    jump("0F 84", "done")
    emit("F3 0F 10 92 80 00 00 00")
    emit("F3 0F 59 D4 F3 0F 58 D3 F3 0F 5F D0 F3 0F 5D D1")
    emit("F3 0F 10 EA F3 0F 5C EB F3 0F 5E EC")
    emit("F3 0F 11 AA 80 00 00 00")

    # Slots 1..6 are the arrow/icon/text group. Translation is corrected, but
    # each element's scale, shape, angle, opacity and timing remain untouched.
    for index, slot in enumerate(range(0x04, 0x1C, 0x04)):
        next_label = f"child_{index + 1}"
        emit("8B 51")
        emit(bytes((slot,)))
        emit("85 D2")
        jump("0F 84", next_label)
        emit("F3 0F 11 52 40")
        labels[next_label] = len(code)

    emit("F0 FF 05")
    emit(hud.u32(counter))
    labels["done"] = len(code)
    emit("58 5E C2 08 00")
    for offset, label in fixups:
        struct.pack_into("<i", code, offset, labels[label] - offset - 4)
    if len(code) > 4096:
        raise RuntimeError("CommandFar animation clamp exceeds one executable page")
    return bytes(code)


def target_from_jump(process, address: int) -> int:
    jump = process.read(address, 5)
    if jump[0] != 0xE9:
        raise RuntimeError(f"Expected JMP at 0x{address:08X}")
    return address + 5 + struct.unpack("<i", jump[1:])[0]


def validate(process, identity: dict) -> dict:
    asi = (
        Path(identity["image"]).parent
        / "scripts"
        / "ResidentEvilRevelations2.FusionFix.asi"
    )
    asi_hash = hashlib.sha256(asi.read_bytes()).hexdigest()
    if asi_hash != SUPPORTED_ASI_HASH:
        raise RuntimeError(f"Unsupported deployed ASI {asi_hash}")
    base = target_from_jump(process, DRAW_ENTRY) - ASI_RESCALE_RVA
    process.expect(base, b"MZ")
    core = base + ASI_CORE_RVA
    offset = base + ASI_OFFSET_RVA
    process.expect(core, bytes.fromhex("55 53 57 56 83 EC 64"))
    process.expect(offset, bytes.fromhex("BA DD DD CC CC E9"))
    # Native CommandFar update selects x=800 in MP and x=640 in SP.  The
    # side-by-side viewport needs the canonical SP center for both players.
    center = process.read(FAR_MP_CENTER_SITE, 4)
    if center not in (FAR_MP_CENTER_800, FAR_SP_CENTER_640):
        raise RuntimeError(f"Unexpected CommandFar center immediate {center.hex()}")
    game_state = process.integer(GAME_STATE_POINTER)
    if not game_state or process.integer(game_state + 0x8F4) != 1:
        raise RuntimeError("Split-screen state is not active")
    return {
        "asiHash": asi_hash,
        "asiBase": base,
        "coreDraw": core,
        "legacyOffsetDraw": offset,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument(
        "--mode",
        choices=(
            "apply",
            "add-center",
            "add-clamp",
            "refine-clamp",
            "inspect",
            "restore",
        ),
        default="inspect",
    )
    args = parser.parse_args()

    process = hud.Process(
        args.pid,
        args.mode in ("apply", "add-center", "add-clamp", "refine-clamp", "restore"),
    )
    try:
        identity = process.identity()
        layout = validate(process, identity)
        state = json.loads(args.state.read_text(encoding="utf-8")) if args.state.exists() else None
        if state and (state["pid"] != args.pid or state["identity"] != identity):
            raise RuntimeError("Stale process state")

        original = hud.u32(layout["legacyOffsetDraw"])
        patched = hud.u32(layout["coreDraw"])
        if args.mode == "apply":
            if state:
                raise RuntimeError("Use a fresh state path")
            process.expect(FAR_DRAW_SLOT, original)
            state = {
                "pid": args.pid,
                "identity": identity,
                "status": "prepared",
                **layout,
                "slot": FAR_DRAW_SLOT,
                "before": original.hex(),
                "after": patched.hex(),
                "rootCenterPatch": {
                    "site": FAR_MP_CENTER_SITE,
                    "before": FAR_MP_CENTER_800.hex(),
                    "after": FAR_SP_CENTER_640.hex(),
                    "status": "prepared",
                },
                "policy": "CommandFar uses the owning viewport NDC origin and canonical x=640 center in MP",
            }
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            hud.transact(
                process,
                [
                    (FAR_DRAW_SLOT, original, patched),
                    (FAR_MP_CENTER_SITE, FAR_MP_CENTER_800, FAR_SP_CENTER_640),
                ],
            )
            state["rootCenterPatch"]["status"] = "applied"
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif not state:
            raise RuntimeError("No saved state")
        elif args.mode == "add-center":
            if state["status"] != "applied" or state.get("rootCenterPatch"):
                raise RuntimeError("Center patch requires the active draw-only test")
            process.expect(FAR_DRAW_SLOT, bytes.fromhex(state["after"]))
            hud.transact(
                process,
                [(FAR_MP_CENTER_SITE, FAR_MP_CENTER_800, FAR_SP_CENTER_640)],
            )
            state["rootCenterPatch"] = {
                "site": FAR_MP_CENTER_SITE,
                "before": FAR_MP_CENTER_800.hex(),
                "after": FAR_SP_CENTER_640.hex(),
                "status": "applied",
            }
            state["policy"] = (
                "CommandFar uses the owning viewport NDC origin and canonical x=640 center in MP"
            )
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "add-clamp":
            if state["status"] != "applied" or state.get("animationClamp"):
                raise RuntimeError("Animation clamp requires the active unclamped test")
            center = state.get("rootCenterPatch")
            if not center or center.get("status") != "applied":
                raise RuntimeError("Apply the canonical center correction first")
            process.expect(FAR_DRAW_SLOT, bytes.fromhex(state["after"]))
            process.expect(FAR_MP_CENTER_SITE, FAR_SP_CENTER_640)
            process.expect(FAR_ANIMATION_CALL, FAR_ANIMATION_CALL_BYTES)
            process.expect(NATIVE_SAFE_MARGIN, struct.pack("<f", 40.0))
            allocation = process.k.VirtualAllocEx(
                process.handle, None, 8192, 0x3000, 0x04
            )
            process.check(allocation)
            if allocation + 8192 > 0x1_0000_0000:
                raise RuntimeError("Animation clamp allocation is outside x86 address space")
            counter = allocation + 4096
            code = make_animation_clamp(allocation, counter)
            process.write(allocation, code)
            process.expect(allocation, code)
            process.protect(allocation, 4096, 0x20)
            process.check(
                process.k.FlushInstructionCache(process.handle, allocation, len(code))
            )
            redirect = call_redirect(FAR_ANIMATION_CALL, allocation)
            state["animationClamp"] = {
                "allocation": allocation,
                "counter": counter,
                "callSite": FAR_ANIMATION_CALL,
                "before": FAR_ANIMATION_CALL_BYTES.hex(),
                "after": redirect.hex(),
                "code": code.hex(),
                "nativeSafeMarginAddress": NATIVE_SAFE_MARGIN,
                "policy": "clamp animated child translations to cached viewport bounds plus native safe margin",
                "status": "prepared",
            }
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            hud.transact(
                process,
                [(FAR_ANIMATION_CALL, FAR_ANIMATION_CALL_BYTES, redirect)],
            )
            state["animationClamp"]["status"] = "applied"
            state["policy"] = (
                "CommandFar uses viewport origin, canonical center, and native safe-area child translation clamp"
            )
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "refine-clamp":
            clamp = state.get("animationClamp")
            if state["status"] != "applied" or not clamp or clamp.get("status") != "applied":
                raise RuntimeError("Refinement requires the active animation clamp")
            allocation = int(clamp["allocation"])
            counter = int(clamp["counter"])
            previous = bytes.fromhex(clamp["code"])
            replacement = make_animation_clamp(allocation, counter)
            if previous == replacement:
                raise RuntimeError("The active clamp already has the refined code")
            process.expect(int(clamp["callSite"]), bytes.fromhex(clamp["after"]))
            process.expect(allocation, previous)
            hud.transact(process, [(allocation, previous, replacement)])
            clamp["previousCode"] = previous.hex()
            clamp["code"] = replacement.hex()
            clamp["refinement"] = (
                "clamp both canonical animation translation and final child matrices"
            )
            clamp["policy"] = (
                "clamp source translation and final matrices to cached viewport bounds plus native safe margin"
            )
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "restore":
            if state["status"] != "applied":
                raise RuntimeError("No active test to restore")
            patches = [
                (int(state["slot"]), bytes.fromhex(state["before"]), bytes.fromhex(state["after"]))
            ]
            center = state.get("rootCenterPatch")
            clamp = state.get("animationClamp")
            if clamp and clamp.get("status") == "applied":
                patches.append(
                    (
                        int(clamp["callSite"]),
                        bytes.fromhex(clamp["before"]),
                        bytes.fromhex(clamp["after"]),
                    )
                )
            if center and center.get("status") == "applied":
                patches.append(
                    (
                        int(center["site"]),
                        bytes.fromhex(center["before"]),
                        bytes.fromhex(center["after"]),
                    )
                )
            hud.transact(
                process,
                patches,
                restore=True,
            )
            if center:
                center["status"] = "restored"
            if clamp:
                clamp["status"] = "restored"
            state["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")

        expected = bytes.fromhex(state["after"] if state["status"] == "applied" else state["before"])
        process.expect(int(state["slot"]), expected)
        center = state.get("rootCenterPatch")
        if center:
            center_expected = center["after"] if center["status"] == "applied" else center["before"]
            process.expect(int(center["site"]), bytes.fromhex(center_expected))
        clamp = state.get("animationClamp")
        if clamp:
            clamp_expected = (
                clamp["after"] if clamp["status"] == "applied" else clamp["before"]
            )
            process.expect(int(clamp["callSite"]), bytes.fromhex(clamp_expected))
            process.expect(
                int(clamp["allocation"]),
                bytes.fromhex(clamp["code"]),
            )
            result_clamp = dict(clamp)
            result_clamp["correctionCalls"] = process.integer(int(clamp["counter"]))
            result_clamp["nativeSafeMargin"] = struct.unpack(
                "<f", process.read(NATIVE_SAFE_MARGIN, 4)
            )[0]
            state["animationClamp"] = result_clamp
        result = dict(state)
        result["currentDraw"] = f"0x{process.integer(int(state['slot'])):08X}"
        result["currentCanonicalCenterX"] = struct.unpack(
            "<f", process.read(FAR_MP_CENTER_SITE, 4)
        )[0]
        print(json.dumps(result, indent=2))
    finally:
        process.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
