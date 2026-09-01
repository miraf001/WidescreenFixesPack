"""Reversible SP-shape test for the Campaign uGUIEquipShortcut controller.

The Quick Menu shortcut cross is laid out with the same local coordinates in
SP and side-by-side co-op.  Native co-op nevertheless selects uniform-fit
scale 0.75 for the root, halving both its size and vertical position.  This
extension keeps native independent X placement while using viewport-height Y
scale for root geometry, matching the already validated Equip/Heal/Reticle
policy.  It chains after the active reticle geometry hook and never patches
inventory text, item preview, input, or gameplay HUD classes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location(
    "reticle_live", Path(__file__).with_name("test-rerev2-reticle-live.py"))
reticle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reticle)
hud = reticle.hud

SHORTCUT = ("uGUIEquipShortcut", 0x139AFB0, 0x8E53F0, 0, "", (0,))
UPDATE_OFFSET, ASPECT_OFFSET = 0, 0x400


def code_blobs(state):
    allocation = state["allocation"]
    return (
        (allocation + UPDATE_OFFSET, hud.make_scale_update_thunk(
            allocation + UPDATE_OFFSET, allocation + 0xC00,
            SHORTCUT[2], SHORTCUT[5])),
        (allocation + ASPECT_OFFSET, hud.make_aspect_thunk(
            allocation + ASPECT_OFFSET, allocation + 0xC04,
            state["stretch"], fallback=state["parentAspect"])),
    )


def code_patches(state):
    return [
        (SHORTCUT[1] + 0x24, hud.u32(SHORTCUT[2]),
         hud.u32(state["allocation"] + UPDATE_OFFSET)),
        (hud.GEOMETRY_X_LOAD, hud.aspect_redirect(state["parentAspect"]),
         hud.aspect_redirect(state["allocation"] + ASPECT_OFFSET)),
    ]


def validate(process, identity, parent, flash_state, reticle_state, state):
    core = reticle.validate(process, identity, parent, flash_state, reticle_state)
    if reticle_state["status"] != "applied":
        raise RuntimeError("Confirmed reticle parent is not active")
    parent_aspect = reticle_state["allocation"] + reticle.ASPECT_OFFSET
    if state:
        if state["identity"] != identity or state["status"] not in ("prepared", "applied"):
            raise RuntimeError("Stale or inactive shortcut state")
        if state["parentAspect"] != parent_aspect:
            raise RuntimeError("Unexpected shortcut geometry parent")
        for address, code in code_blobs(state):
            process.expect(address, code)
        for address, original, patched in code_patches(state):
            allowed = (original, patched) if state["status"] == "prepared" else (patched,)
            if process.read(address, len(original)) not in allowed:
                raise RuntimeError(f"Unexpected shortcut patch at {address:X}")
    else:
        process.expect(SHORTCUT[1] + 0x24, hud.u32(SHORTCUT[2]))
        process.expect(hud.GEOMETRY_X_LOAD, hud.aspect_redirect(parent_aspect))
    return core, parent_aspect


def plan(process, controllers):
    if len(controllers) != 1:
        raise RuntimeError("Supply the one freshly verified active Campaign shortcut controller")
    stretch = hud.plan_stretch(process, controllers, definitions=(SHORTCUT,))
    tree = stretch["trees"][0]
    if tuple(tree["source"]) != (1280, 720):
        raise RuntimeError("Unverified shortcut source dimensions")
    controller = controllers[0]
    selected = process.integer(process.integer(controller + 0xF8))
    nodes = [node for node in stretch["nodes"] if node["owner"] == controller]
    if len(nodes) != 1 or nodes[0]["node"] != selected or nodes[0]["vtable"] != 0x141D330:
        raise RuntimeError("Shortcut tree differs from the verified single root layout node")
    process.expect(selected + 0xA0, struct.pack("<2f", 340, 280))
    return stretch


def restore(process, state, path):
    patches = []
    for address, original, patched in code_patches(state):
        actual = process.read(address, len(original))
        if actual not in (original, patched):
            raise RuntimeError("Unknown shortcut patch during restore")
        patches.append((address, actual, original))
    hud.transact(process, patches)
    state["status"] = "restored"
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    guards, _, dirty = hud.stretch_transaction_inputs(state["stretch"])
    try:
        with process.suspended():
            for address, expected in guards:
                process.expect(address, expected)
            changes = []
            for node in state["stretch"]["nodes"]:
                address = node["node"] + 0x80
                flags = process.integer(address)
                if ((flags >> 16) & 15) not in (2, 5):
                    raise RuntimeError("Unexpected selector; code restored, tree not touched")
                restored = (flags & ~0xF0000) | (node["before"] & 0xF0000)
                changes.append((address, hud.u32(flags), hud.u32(restored)))
            hud.transact(process, changes, guards=guards, dirty_nodes=dirty, suspend=False)
        hud.refresh_stretch(process, state)
        state["stretch"]["status"] = "restored"
    except (OSError, RuntimeError) as error:
        state["treeRestoreWarning"] = str(error)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--hud-state", type=Path, required=True)
    parser.add_argument("--flash-state", type=Path, required=True)
    parser.add_argument("--reticle-state", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--controller", type=lambda text: int(text, 0), action="append", default=[])
    parser.add_argument("--mode", choices=("plan", "apply", "inspect", "refresh", "restore"),
                        default="inspect")
    args = parser.parse_args()
    parent = json.loads(args.hud_state.read_text())
    flash_state = json.loads(args.flash_state.read_text())
    reticle_state = json.loads(args.reticle_state.read_text())
    state = json.loads(args.state.read_text()) if args.state.exists() else None
    process = hud.Process(args.pid, args.mode not in ("inspect", "plan"))
    try:
        identity = process.identity()
        for checkpoint in (parent, flash_state, reticle_state, state):
            if checkpoint and (checkpoint["pid"] != args.pid or checkpoint["identity"] != identity):
                raise RuntimeError("State PID/creation time mismatch")
        core, parent_aspect = validate(
            process, identity, parent, flash_state, reticle_state, state)
        if args.mode in ("plan", "apply"):
            if state:
                raise RuntimeError("Use a new state path; never overwrite a backup")
            stretch = plan(process, args.controller)
            if args.mode == "plan":
                print(json.dumps(stretch, indent=2))
                return 0
            allocation = process.k.VirtualAllocEx(process.handle, None, 4096, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 4096 > 0x100000000:
                raise RuntimeError("Allocation outside x86 address space")
            stretch["status"] = "applied"
            state = {
                "pid": args.pid, "identity": identity, "status": "prepared", "core": core,
                "hudState": str(args.hud_state.resolve()),
                "flashState": str(args.flash_state.resolve()),
                "reticleState": str(args.reticle_state.resolve()),
                "parentAspect": parent_aspect, "allocation": allocation,
                "stretch": stretch, "controllers": args.controller,
                "before": hud.snapshot(process, args.controller, definitions=(SHORTCUT,)),
            }
            for (address, code), limit in zip(
                    code_blobs(state), (allocation + ASPECT_OFFSET, allocation + 0xC00)):
                if address + len(code) > limit:
                    raise RuntimeError("Shortcut code exceeds reserved slot")
                process.write(address, code)
                process.expect(address, code)
            process.protect(allocation, 4096, 0x20)
            process.check(process.k.FlushInstructionCache(process.handle, allocation, 4096))
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            guards, patches, dirty = hud.stretch_transaction_inputs(stretch)
            hud.transact(process, code_patches(state) + patches,
                         guards=guards, dirty_nodes=dirty)
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            hud.refresh_stretch(process, state)
        elif args.mode in ("restore", "refresh"):
            if not state or state["status"] not in ("prepared", "applied"):
                raise RuntimeError("No active shortcut extension")
            if args.mode == "restore":
                restore(process, state, args.state)
            else:
                hud.refresh_stretch(process, state)
        result = {
            "pid": args.pid, "nonAtomicSnapshot": True,
            "status": state["status"] if state else "native",
            "controllers": hud.snapshot(
                process, args.controller or (state or {}).get("controllers", []),
                definitions=(SHORTCUT,)),
        }
        if state:
            result["counters"] = {
                "selector": process.integer(state["allocation"] + 0xC00),
                "aspect": process.integer(state["allocation"] + 0xC04),
            }
        print(json.dumps(result, indent=2))
        return 0
    finally:
        process.close()


if __name__ == "__main__":
    raise SystemExit(main())
