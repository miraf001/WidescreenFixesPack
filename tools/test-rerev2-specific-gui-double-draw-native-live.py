"""Reversibly replay one exact RE:Rev2 GUI controller in the right viewport.

The helper only touches the class draw slot after validating the selected
controller's vtable and loaded root owner.  All other instances tail-jump to
the original function.  It is an in-memory experiment, never an ASI build.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys


ROOT = Path(__file__).resolve().parent
RESCALE_ENTRY = 0x00E18040
GAME_STATE_POINTER = 0x015DE88C
RENDER_ROOT_OFFSET = 0xF4
OWNER_OFFSET = 0x6C


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def load_process_module():
    path = ROOT / "test-rerev2-sp-hud-live.py"
    spec = importlib.util.spec_from_file_location("rerev2_live_process", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HUD = load_process_module()


def relative_branch(code: bytearray, allocation: int, opcode: bytes, target: int) -> None:
    code += opcode
    code += u32(target - (allocation + len(code) + 4))


def relative_call(code: bytearray, allocation: int, target: int) -> None:
    code += b"\xE8"
    code += u32(target - (allocation + len(code) + 4))


def native_wrapper(allocation: int, controller: int, dual_mode_flag: int) -> bytes:
    """x86 thiscall wrapper: target controller renders twice; all others once."""
    code = bytearray()
    code += b"\x81\xF9" + u32(controller)   # cmp ecx, controller
    relative_branch(code, allocation, b"\x0F\x85", RESCALE_ENTRY)  # jne original
    code += b"\x56\x57\x53"                 # preserve esi, edi, ebx
    code += b"\x8B\xF1\x8B\xFA"             # esi=this; edi=edx context
    code += b"\x8B\x46\x40\x50"             # save original controller X
    code += b"\xFF\x74\x24\x14"             # push original stack arg a2
    relative_call(code, allocation, RESCALE_ENTRY)
    code += b"\x80\x3D" + u32(dual_mode_flag) + b"\x00"  # cmp byte [mode], 0
    skip_replay = len(code)
    code += b"\x74\x00"                     # je restore
    code += b"\x8B\xCE\x8B\xD7"             # restore ecx/edx for replay
    code += b"\xA1" + u32(GAME_STATE_POINTER) # eax = game state
    code += b"\x8B\x40\x50"                 # eax = live split width
    code += b"\xF3\x0F\x2A\xC0"             # xmm0 = float(eax)
    code += b"\xF3\x0F\x58\x04\x24"       # xmm0 += original X
    code += b"\xF3\x0F\x11\x46\x40"       # controller X = right-copy X
    code += b"\xFF\x74\x24\x14"             # push original a2 again
    relative_call(code, allocation, RESCALE_ENTRY)
    restore = len(code)
    code += b"\x58\x89\x46\x40"             # restore original X
    code += b"\x5B\x5F\x5E\xC2\x04\x00"  # restore registers; ret 4
    delta = restore - (skip_replay + 2)
    if not 0 <= delta <= 0x7F:
        raise RuntimeError("conditional branch exceeded short range")
    code[skip_replay + 1] = delta
    return bytes(code)


def validate_controller(process, controller: int, draw_slot: int) -> int:
    if draw_slot < 0x58:
        raise RuntimeError("draw slot is invalid")
    expected_vtable = draw_slot - 0x58
    if process.integer(controller) != expected_vtable:
        raise RuntimeError("controller vtable does not match selected draw slot")
    root = process.integer(controller + RENDER_ROOT_OFFSET)
    if not root or process.integer(root + OWNER_OFFSET) != controller:
        raise RuntimeError("controller does not own a loaded render root")
    return root


def inspect(process, state: dict) -> dict:
    root = validate_controller(process, state["controller"], state["drawSlot"])
    live_state = process.integer(GAME_STATE_POINTER)
    return {
        "label": state["label"],
        "status": state["status"],
        "controller": hex(state["controller"]),
        "root": hex(root),
        "drawSlot": hex(state["drawSlot"]),
        "drawTarget": hex(process.integer(state["drawSlot"])),
        "expectedWrapper": hex(state["allocation"]),
        "liveSplitWidth": process.integer(live_state + 0x50),
        "dualModeEnabled": bool(process.read(state["dualModeFlag"], 1)[0]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mode", choices=("apply", "inspect", "restore"), required=True)
    parser.add_argument("--label")
    parser.add_argument("--controller", type=lambda value: int(value, 0))
    parser.add_argument("--draw-slot", type=lambda value: int(value, 0))
    parser.add_argument("--dual-mode-flag", type=lambda value: int(value, 0))
    args = parser.parse_args()
    writable = args.mode in ("apply", "restore")
    process = HUD.Process(args.pid, writable)
    try:
        identity = process.identity()
        state = json.loads(args.state.read_text(encoding="utf-8")) if args.state.exists() else None
        if state is not None and (state["pid"] != args.pid or state["identity"] != identity):
            raise RuntimeError("state belongs to another process; refusing stale state")

        if args.mode == "apply":
            if state is not None:
                raise RuntimeError("state already exists; inspect or restore it")
            if not args.label or args.controller is None or args.draw_slot is None or args.dual_mode_flag is None:
                raise RuntimeError("apply requires label, controller, draw slot and dual-mode flag")
            root = validate_controller(process, args.controller, args.draw_slot)
            if process.integer(args.draw_slot) != RESCALE_ENTRY:
                raise RuntimeError("draw slot is not the expected rescale entry")
            if not process.read(args.dual_mode_flag, 1)[0]:
                raise RuntimeError("dual mode is disabled; wrapper was not installed")
            allocation = process.k.VirtualAllocEx(process.handle, None, 0x1000, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 0x1000 > 0x1_0000_0000:
                raise RuntimeError("allocation is outside the 32-bit address range")
            code = native_wrapper(allocation, args.controller, args.dual_mode_flag)
            process.write(allocation, code)
            process.protect(allocation, len(code), 0x20)
            process.check(process.k.FlushInstructionCache(process.handle, allocation, len(code)))
            state = {
                "pid": args.pid,
                "identity": identity,
                "status": "prepared",
                "label": args.label,
                "allocation": allocation,
                "controller": args.controller,
                "root": root,
                "drawSlot": args.draw_slot,
                "originalDrawTarget": RESCALE_ENTRY,
                "dualModeFlag": args.dual_mode_flag,
                "wrapperSize": len(code),
            }
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as output:
                json.dump(state, output, indent=2)
            with process.suspended():
                process.expect(args.draw_slot, u32(RESCALE_ENTRY))
                process.patch(args.draw_slot, u32(allocation))
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            print(json.dumps(inspect(process, state), indent=2))
            return 0

        if state is None:
            raise RuntimeError("state file is required")
        if args.mode == "inspect":
            print(json.dumps(inspect(process, state), indent=2))
            return 0

        target = process.integer(state["drawSlot"])
        if target not in (state["allocation"], state["originalDrawTarget"]):
            raise RuntimeError(f"unexpected draw target during restore: 0x{target:X}")
        if target == state["allocation"]:
            with process.suspended():
                process.expect(state["drawSlot"], u32(state["allocation"]))
                process.patch(state["drawSlot"], u32(state["originalDrawTarget"]))
        state["status"] = "restored"
        args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        print(json.dumps({"label": state["label"], "status": "restored"}, indent=2))
        return 0
    finally:
        process.close()


if __name__ == "__main__":
    raise SystemExit(main())
