"""Reversible uGUIFlash extension to the confirmed Claire SP-layout live test.

Restore this extension BEFORE using the parent tool's restore/unstretch/aspect
modes. The chained geometry hook keeps the parent's executable code unchanged.
No native input or other character/controller class is modified here.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("hud_live", Path(__file__).with_name("test-rerev2-sp-hud-live.py"))
hud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hud)

FLASH = ("uGUIFlash", 0x139B558, 0x8E8360, 0x8E8389, "e842d00600", (2,))
DRAW_OFFSET, UPDATE_OFFSET, ASPECT_OFFSET = 0, 0x400, 0x800


def code_blobs(state: dict):
    allocation = state["allocation"]
    return (
        (allocation, hud.make_thunk(allocation, allocation + 0x1000, state["core"])),
        (allocation + UPDATE_OFFSET, hud.make_scale_update_thunk(
            allocation + UPDATE_OFFSET, allocation + 0x1004, FLASH[2], FLASH[5])),
        (allocation + ASPECT_OFFSET, hud.make_aspect_thunk(
            allocation + ASPECT_OFFSET, allocation + 0x1008, state["stretch"],
            fallback=state["parentAspect"])),
    )


def code_patches(state: dict):
    return [
        (FLASH[3] + 5, b"\x84", b"\x30"),
        (FLASH[1] + 0x58, hud.u32(hud.DRAW_ENTRY), hud.u32(state["allocation"])),
        (FLASH[1] + 0x24, hud.u32(FLASH[2]), hud.u32(state["allocation"] + UPDATE_OFFSET)),
        (hud.GEOMETRY_X_LOAD, hud.aspect_redirect(state["parentAspect"]),
         hud.aspect_redirect(state["allocation"] + ASPECT_OFFSET)),
    ]


def validate(process, identity, parent, state):
    if parent["identity"] != identity or parent["status"] != "applied" or parent.get("aspect", {}).get("status") != "applied":
        raise RuntimeError("The confirmed parent layout/aspect test must still be active in this process")
    override = None
    if state and state["status"] in ("prepared", "applied"):
        if state["identity"] != identity or state["parentAspect"] != parent["aspect"]["allocation"]:
            raise RuntimeError("Stale process/parent geometry state")
        for address, code in code_blobs(state):
            process.expect(address, code)
        for address, original, patched in code_patches(state):
            actual = process.read(address, len(original))
            allowed = (original, patched) if state["status"] == "prepared" else (patched,)
            if actual not in allowed:
                raise RuntimeError(f"Unexpected Flash patch at {address:X}")
        override = process.read(hud.GEOMETRY_X_LOAD, len(hud.GEOMETRY_X_BYTES))
    else:
        process.expect(FLASH[3], bytes.fromhex(FLASH[4]) + b"\x84\xc0")
        process.expect(FLASH[1] + 0x24, hud.u32(FLASH[2]))
        process.expect(FLASH[1] + 0x58, hud.u32(hud.DRAW_ENTRY))
    return hud.validate_build(process, identity, parent, geometry_override=override)


def restore(process, state, path):
    # First remove all code redirects, including the chained geometry extension.
    # Cached GUI trees may have been destroyed: their absence must not leave
    # live redirects behind. Keep all allocated pages for in-flight thunks.
    patches = []
    for address, original, patched in code_patches(state):
        actual = process.read(address, len(original))
        if actual not in (original, patched):
            raise RuntimeError("Unknown Flash patch during restore")
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
                    raise RuntimeError("Unexpected Flash selector; code restored but tree not touched")
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
    parser.add_argument("--parent-state", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mode", choices=("plan", "apply", "inspect", "refresh", "restore"), default="inspect")
    parser.add_argument("--controller", type=lambda s: int(s, 0), action="append", default=[])
    args = parser.parse_args()
    parent = json.loads(args.parent_state.read_text())
    state = json.loads(args.state.read_text()) if args.state.exists() else None
    process = hud.Process(args.pid, args.mode not in ("inspect", "plan"))
    try:
        identity = process.identity()
        if parent["pid"] != args.pid or (state and (state["pid"] != args.pid or state["identity"] != identity)):
            raise RuntimeError("State PID/creation time mismatch")
        core = validate(process, identity, parent, state)
        if args.mode in ("apply", "plan"):
            if state:
                raise RuntimeError("Use a new state path; existing backup will not be overwritten")
            if not args.controller:
                raise RuntimeError("Supply freshly verified Flash controller addresses")
            mode_object = process.integer(hud.MODE_POINTER)
            process.expect(mode_object + 0x8F0, hud.u32(1) + hud.u32(1))
            stretch = hud.plan_stretch(process, args.controller, definitions=(FLASH,))
            # Native Flash update only owns index 2. Refuse unexpected resources
            # with additional explicit nodes rather than extending scope blindly.
            for tree in stretch["trees"]:
                selected = process.integer(process.integer(tree["controller"] + 0xF8) + 8)
                nodes = [n["node"] for n in stretch["nodes"] if n["owner"] == tree["controller"]]
                if nodes != [selected]:
                    raise RuntimeError("Flash tree does not match verified single-node layout")
            if args.mode == "plan":
                print(json.dumps(stretch, indent=2))
                return
            allocation = process.k.VirtualAllocEx(process.handle, None, 8192, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 8192 > 0x100000000:
                raise RuntimeError("Allocation outside x86 address space")
            stretch["status"] = "applied"
            state = {"pid": args.pid, "identity": identity, "status": "prepared", "core": core,
                     "parentState": str(args.parent_state.resolve()), "parentAspect": parent["aspect"]["allocation"],
                     "allocation": allocation, "stretch": stretch, "controllers": args.controller,
                     "before": hud.snapshot(process, args.controller, definitions=(FLASH,))}
            for address, code in code_blobs(state):
                if address + len(code) > allocation + 4096:
                    raise RuntimeError("Flash code exceeds RX page")
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
                raise RuntimeError("No active Flash extension")
            if args.mode == "restore":
                restore(process, state, args.state)
            else:
                hud.refresh_stretch(process, state)
        result = {"pid": args.pid, "status": state["status"] if state else "native",
                  "controllers": hud.snapshot(process, args.controller or (state or {}).get("controllers", []), definitions=(FLASH,))}
        if state:
            result["counters"] = {name: process.integer(state["allocation"] + offset)
                                  for name, offset in (("draw", 0x1000), ("selector", 0x1004), ("aspect", 0x1008))}
        print(json.dumps(result, indent=2))
    finally:
        process.close()


if __name__ == "__main__":
    main()
