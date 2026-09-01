"""Historical auto-detection-only co-op input test (FAILED player isolation).

Patch only the split-screen skip in native auto-device selection (9885D0).
Retain gamepad polling, join/Start handling, pad activity timers and the native
actor+7920==0 checks. These DO NOT identify P1: both local actors have zero.
The user confirmed this test controls BOTH players. Do not reapply alone.
No input emulation or new threads.
Release bridge capture with F9 for a meaningful keyboard/mouse test.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("hud", Path(__file__).with_name("test-rerev2-sp-hud-live.py"))
hud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hud)

SITE = 0x98861C
ORIGINAL = bytes.fromhex("0f 84 85 00 00 00")
# Both versions remain ONE six-byte instruction. Branch-to-next permits safe
# suspended apply/restore without PCs sitting inside a multi-NOP replacement.
PATCHED = bytes.fromhex("0f 84 00 00 00 00")
GUARDS = (
    (0x988610, bytes.fromhex("a1 00 ae 57 01 83 b8 f0 08 00 00 01")),
    (0x988622, bytes.fromhex("57 8b 3d 18 e9 5d 01 33 d2 eb 03")),
    (0x988680, bytes.fromhex("c7 86 bc c4 15 00 01 00 00 00 89 86 c0 c4 15 00")),
    (0x9886A7, bytes.fromhex("c7 86 bc c4 15 00 00 00 00 00 c7 86 c0 c4 15 00 00 00 00 00")),
    (0xA15521, bytes.fromhex("83 be 20 79 00 00 00")),
    (0xA155A5, bytes.fromhex("83 b8 bc c4 15 00 01")),
)


def snapshot(process):
    cfg = process.integer(0x157D120)
    mode = process.integer(hud.MODE_POINTER)
    keyboard = process.integer(0x15DE918)
    mouse = process.integer(0x15DE940)
    return {"nonAtomicSnapshot": True, "settings": hex(cfg),
            "splitMode": process.integer(mode + 0x8F0),
            "splitState": process.integer(mode + 0x8F4),
            "playerAssignment": [process.integer(mode + o) for o in (0x8F8, 0x8FC)],
            "primaryInputMode": process.integer(cfg + 0x15C4BC),
            "promptInputMode": process.integer(cfg + 0x15C4C0),
            "padActivityTimers": struct.unpack("<2f", process.read(cfg + 0x15C690, 8)),
            "otherInputBlock": process.integer(cfg + 0x15C4F0),
            "primaryPadProfile": {"enabled": process.read(cfg + 0x15C4C8, 1)[0],
                                  "backend": process.integer(cfg + 0x15C4CC),
                                  "index": process.integer(cfg + 0x15C4D0)},
            "keyboard": hex(keyboard), "mouse": hex(mouse),
            "mouseDelta": struct.unpack("<3i", process.read(mouse + 0x2C, 12)),
            "keyboardActionBlock": process.integer(keyboard + 0xC74)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mode", choices=("inspect", "apply", "restore"), default="inspect")
    args = parser.parse_args()
    if args.mode == "apply":
        raise RuntimeError("Auto-detection alone controls BOTH players. Use the ownership experiment instead.")
    state = json.loads(args.state.read_text()) if args.state.exists() else None
    process = hud.Process(args.pid, args.mode != "inspect")
    try:
        identity = process.identity()
        if state and (state["pid"] != args.pid or state["identity"] != identity):
            raise RuntimeError("State belongs to a different process instance")
        asi = Path(identity["image"]).parent / "scripts/ResidentEvilRevelations2.FusionFix.asi"
        if hashlib.sha256(asi.read_bytes()).hexdigest() != hud.ASI_HASH:
            raise RuntimeError("Only the verified Debug build is supported by this experiment")
        for address, code in GUARDS:
            process.expect(address, code)
        if args.mode == "apply":
            if state:
                raise RuntimeError("Use a fresh state path; existing backup is never overwritten")
            process.expect(SITE, ORIGINAL)
            process.expect(process.integer(hud.MODE_POINTER) + 0x8F0, hud.u32(1) + hud.u32(1))
            state = {"pid": args.pid, "identity": identity, "status": "prepared", "before": snapshot(process),
                     "patch": {"address": hex(SITE), "original": ORIGINAL.hex(), "patched": PATCHED.hex()}}
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            hud.transact(process, [(SITE, ORIGINAL, PATCHED)], guards=GUARDS)
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "restore":
            if not state or state["status"] not in ("applied", "prepared"):
                raise RuntimeError("No active input test to restore")
            current = process.read(SITE, 6)
            if current not in (ORIGINAL, PATCHED):
                raise RuntimeError("Unexpected input code; no writes performed")
            hud.transact(process, [(SITE, current, ORIGINAL)], guards=GUARDS)
            state["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        expected = PATCHED if state and state["status"] == "applied" else ORIGINAL
        process.expect(SITE, expected)
        print(json.dumps({"pid": args.pid, "status": state["status"] if state else "native",
                          "instruction": process.read(SITE, 6).hex(), **snapshot(process)}, indent=2))
    finally:
        process.close()


if __name__ == "__main__":
    main()
