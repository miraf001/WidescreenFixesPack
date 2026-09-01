"""Reversible SP-shape/viewport-position test for uGUIReticleBase ONLY.

Requires the confirmed Claire HUD and Flash live extensions. Restore this
extension FIRST, then Flash, then Claire. No input, camera, weapon spread,
raycast, or other reticle class is patched. No game-thread Python callbacks.

Native local SP origin (640,360) uses independent viewport/source scale for
position. Only node 0 geometry uses uniform viewport-height scale. Children
retain native weapon-specific animations. SP takes the original draw path.
Like the parent HUD test, geometry identity is instance-bound: recreated
trees need a fresh plan, not reuse of saved process addresses.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("flash_live", Path(__file__).with_name("test-rerev2-flash-live.py"))
flash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flash)
hud = flash.hud

RETICLE = ("uGUIReticleBase", 0x13A3868, 0x94FC00, 0x94FC34, "e897570000", (0,))
LAYOUT_TEST = 0x94FC3C  # PUSH ECX / MOV ECX,ESI occur between CALL and TEST!
DRAW_OFFSET, UPDATE_OFFSET, ASPECT_OFFSET = 0, 0x400, 0x800


def code_blobs(state):
    allocation = state["allocation"]
    return (
        (allocation, hud.make_thunk(allocation, allocation + 0x1000, state["core"])),
        (allocation + UPDATE_OFFSET, hud.make_scale_update_thunk(
            allocation + UPDATE_OFFSET, allocation + 0x1004, RETICLE[2], RETICLE[5])),
        (allocation + ASPECT_OFFSET, hud.make_aspect_thunk(
            allocation + ASPECT_OFFSET, allocation + 0x1008, state["stretch"],
            fallback=state["parentAspect"])),
    )


def code_patches(state):
    return [
        (LAYOUT_TEST, b"\x84", b"\x30"),
        (RETICLE[1] + 0x58, hud.u32(hud.DRAW_ENTRY), hud.u32(state["allocation"])),
        (RETICLE[1] + 0x24, hud.u32(RETICLE[2]), hud.u32(state["allocation"] + UPDATE_OFFSET)),
        (hud.GEOMETRY_X_LOAD, hud.aspect_redirect(state["parentAspect"]),
         hud.aspect_redirect(state["allocation"] + ASPECT_OFFSET)),
    ]


def validate(process, identity, parent, extension, state):
    for checkpoint in (parent, extension):
        if checkpoint["identity"] != identity or checkpoint["status"] != "applied":
            raise RuntimeError("Confirmed HUD/Flash parent is not active in this process")
    if (parent.get("aspect", {}).get("status") != "applied"
            or extension["parentAspect"] != parent["aspect"]["allocation"]):
        raise RuntimeError("Unexpected parent geometry chain")
    parent_aspect = extension["allocation"] + flash.ASPECT_OFFSET
    expected_geometry = hud.aspect_redirect(parent_aspect)
    active = state and state["status"] in ("prepared", "applied")
    if active:
        if state["identity"] != identity or state["parentAspect"] != parent_aspect:
            raise RuntimeError("Stale reticle process or parent state")
        for address, code in code_blobs(state):
            process.expect(address, code)
        for address, original, patched in code_patches(state):
            allowed = (original, patched) if state["status"] == "prepared" else (patched,)
            if process.read(address, len(original)) not in allowed:
                raise RuntimeError(f"Unexpected reticle patch at {address:X}")
        expected_geometry = process.read(hud.GEOMETRY_X_LOAD, 9)
    else:
        process.expect(LAYOUT_TEST, bytes.fromhex("84c0743b"))
        process.expect(RETICLE[1] + 0x24, hud.u32(RETICLE[2]))
        process.expect(RETICLE[1] + 0x58, hud.u32(hud.DRAW_ENTRY))
    process.expect(RETICLE[3], bytes.fromhex(RETICLE[4] + "518bce"))
    process.expect(LAYOUT_TEST + 1, bytes.fromhex("c0743b"))
    # Independently validate the complete unchanged Flash chain before allowing
    # our own geometry redirect as an override to the parent inspector.
    for address, code in flash.code_blobs(extension):
        process.expect(address, code)
    for address, _, patched in flash.code_patches(extension):
        process.expect(address, expected_geometry if address == hud.GEOMETRY_X_LOAD else patched)
    for address, _, patched in hud.patch_set(parent["allocation"]):
        process.expect(address, patched)
    return hud.validate_build(process, identity, parent, geometry_override=expected_geometry)


def plan(process, controllers):
    if not controllers or len(set(controllers)) != len(controllers):
        raise RuntimeError("Supply distinct freshly verified Base reticle controllers")
    stretch = hud.plan_stretch(process, controllers, definitions=(RETICLE,))
    for tree in stretch["trees"]:
        if tuple(tree["source"]) != (1280, 720):
            raise RuntimeError("Unverified reticle source dimensions")
        controller = tree["controller"]
        selected = process.integer(process.integer(controller + 0xF8))
        nodes = [n for n in stretch["nodes"] if n["owner"] == controller]
        if len(nodes) != 1 or nodes[0]["node"] != selected or nodes[0]["vtable"] != 0x141D330:
            raise RuntimeError("Reticle tree differs from the verified single layout node")
        process.expect(selected + 0xA0, struct.pack("<2f", 800, 360))
        process.expect(selected + 0xB0, struct.pack("<3f", 2, 2, 2))
    return stretch


def restore(process, state, path):
    # Code restores even if the saved tree has since been destroyed. Executable
    # pages stay allocated until exit for any draw/update already in flight.
    patches = []
    for address, original, patched in code_patches(state):
        actual = process.read(address, len(original))
        if actual not in (original, patched):
            raise RuntimeError("Unknown reticle patch during restore")
        patches.append((address, actual, original))
    hud.transact(process, patches)
    state["status"] = "restored"
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    guards, _, dirty = hud.stretch_transaction_inputs(state["stretch"])
    try:
        with process.suspended():
            for address, expected in guards:
                process.expect(address, expected)
            patches = []
            for node in state["stretch"]["nodes"]:
                address = node["node"] + 0x80
                flags = process.integer(address)
                if ((flags >> 16) & 15) not in (2, 5):
                    raise RuntimeError("Unexpected selector; code restored, tree not touched")
                patches.append((address, hud.u32(flags), hud.u32((flags & ~0xF0000) | (node["before"] & 0xF0000))))
            hud.transact(process, patches, guards=guards, dirty_nodes=dirty, suspend=False)
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
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--controller", type=lambda s: int(s, 0), action="append", default=[])
    parser.add_argument("--mode", choices=("plan", "apply", "inspect", "refresh", "restore"), default="inspect")
    args = parser.parse_args()
    parent = json.loads(args.hud_state.read_text())
    extension = json.loads(args.flash_state.read_text())
    state = json.loads(args.state.read_text()) if args.state.exists() else None
    process = hud.Process(args.pid, args.mode not in ("inspect", "plan"))
    try:
        identity = process.identity()
        for checkpoint in (parent, extension, state):
            if checkpoint and (checkpoint["pid"] != args.pid or checkpoint["identity"] != identity):
                raise RuntimeError("State PID/creation time mismatch")
        core = validate(process, identity, parent, extension, state)
        if args.mode in ("plan", "apply"):
            if state:
                raise RuntimeError("Use a new state path; never overwrite a backup")
            process.expect(process.integer(hud.MODE_POINTER) + 0x8F0, hud.u32(1) + hud.u32(1))
            stretch = plan(process, args.controller)
            if args.mode == "plan":
                print(json.dumps(stretch, indent=2))
                return
            allocation = process.k.VirtualAllocEx(process.handle, None, 8192, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 8192 > 0x100000000:
                raise RuntimeError("Allocation outside x86 address space")
            stretch["status"] = "applied"
            state = {"pid": args.pid, "identity": identity, "status": "prepared", "core": core,
                     "hudState": str(args.hud_state.resolve()), "flashState": str(args.flash_state.resolve()),
                     "parentAspect": extension["allocation"] + flash.ASPECT_OFFSET,
                     "allocation": allocation, "stretch": stretch, "controllers": args.controller,
                     "before": hud.snapshot(process, args.controller, definitions=(RETICLE,))}
            for (address, code), limit in zip(code_blobs(state), (allocation + UPDATE_OFFSET, allocation + ASPECT_OFFSET, allocation + 4096)):
                if address + len(code) > limit:
                    raise RuntimeError("Reticle code exceeds reserved slot")
                process.write(address, code)
                process.expect(address, code)
            process.protect(allocation, 4096, 0x20)
            process.check(process.k.FlushInstructionCache(process.handle, allocation, 4096))
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            guards, patches, dirty = hud.stretch_transaction_inputs(stretch)
            hud.transact(process, code_patches(state) + patches, guards=guards, dirty_nodes=dirty)
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            hud.refresh_stretch(process, state)
        elif args.mode in ("restore", "refresh"):
            if not state or state["status"] not in ("prepared", "applied"):
                raise RuntimeError("No active reticle extension")
            if args.mode == "restore":
                restore(process, state, args.state)
            else:
                hud.refresh_stretch(process, state)
        result = {"pid": args.pid, "nonAtomicSnapshot": True,
                  "status": state["status"] if state else "native",
                  "controllers": hud.snapshot(process, args.controller or (state or {}).get("controllers", []), definitions=(RETICLE,))}
        if state:
            result["counters"] = {name: process.integer(state["allocation"] + offset)
                                  for name, offset in (("draw", 0x1000), ("selector", 0x1004), ("aspect", 0x1008))}
        print(json.dumps(result, indent=2))
    finally:
        process.close()


if __name__ == "__main__":
    main()
