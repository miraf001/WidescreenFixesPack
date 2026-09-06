"""Reversibly duplicate the active RE:Rev2 pause menu in dual-monitor mode.

This is an in-process test only.  It replaces one uGUICommonMenu draw slot with
a small native wrapper which renders its original content, then replays the
same content one live viewport width to the right.  The wrapper checks the
loaded ASI's dual-mode flag before replaying, so a live switch to shared mode
keeps exactly the original single render.  Source, ASI and game files are not
modified.  Restore leaves the executable allocation mapped until game exit so
no render thread can return into freed code.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys


ROOT = Path(__file__).resolve().parent
COMMON_MENU_DRAW_SLOT = 0x013950C8
RESCALE_ENTRY = 0x00E18040
GAME_STATE_POINTER = 0x015DE88C


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HUD = load_module("rerev2_live_process", ROOT / "test-rerev2-sp-hud-live.py")
MENU = load_module("rerev2_common_menu_lookup", ROOT / "test-rerev2-common-menu-double-draw.py")


def relative_call(code: bytearray, allocation: int, target: int) -> int:
    index = len(code)
    code += b"\xE8\x00\x00\x00\x00"
    code[index + 1:index + 5] = u32(target - (allocation + index + 5))
    return index


def native_wrapper(allocation: int, dual_mode_flag: int) -> bytes:
    """Build x86 thiscall -> fastcall replay code for one CommonMenu draw."""
    code = bytearray()
    code += b"\x56\x57\x53"             # preserve esi, edi, ebx
    code += b"\x8B\xF1\x8B\xFA"         # esi=this; edi=edx context
    code += b"\x8B\x46\x40\x50"         # save original controller X
    code += b"\xFF\x74\x24\x14"         # push original stack argument a2
    relative_call(code, allocation, RESCALE_ENTRY)
    code += b"\x80\x3D" + u32(dual_mode_flag) + b"\x00"  # cmp byte [mode], 0
    skip_replay = len(code)
    code += b"\x74\x00"                 # je restore
    code += b"\x8B\xCE\x8B\xD7"         # restore ecx/edx for second call
    code += b"\xA1" + u32(GAME_STATE_POINTER)  # eax = game state
    code += b"\x8B\x40\x50"             # eax = current split viewport width
    code += b"\xF3\x0F\x2A\xC0"         # xmm0 = float(eax)
    code += b"\xF3\x0F\x58\x04\x24"   # xmm0 += saved original X
    code += b"\xF3\x0F\x11\x46\x40"   # controller X = right-copy X
    code += b"\xFF\x74\x24\x14"         # push original a2 again
    relative_call(code, allocation, RESCALE_ENTRY)
    restore = len(code)
    code += b"\x58\x89\x46\x40"         # restore original controller X
    code += b"\x5B\x5F\x5E\xC2\x04\x00"  # registers; ret 4
    delta = restore - (skip_replay + 2)
    if not 0 <= delta <= 0x7F:
        raise RuntimeError("native wrapper conditional jump exceeds short range")
    code[skip_replay + 1] = delta
    return bytes(code)


def inspect(process, state: dict) -> dict:
    controller, split_width = MENU.find_active_common_menu(state["pid"])
    return {
        "status": state["status"],
        "controller": hex(controller),
        "liveSplitWidth": split_width,
        "drawSlot": hex(process.integer(COMMON_MENU_DRAW_SLOT)),
        "expectedWrapper": hex(state["allocation"]),
        "dualModeFlag": hex(state["dualModeFlag"]),
        "dualModeEnabled": bool(process.read(state["dualModeFlag"], 1)[0]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mode", choices=("apply", "inspect", "restore"), required=True)
    parser.add_argument("--dual-mode-flag", type=lambda value: int(value, 0),
                        help="loaded ASI bool bSubtitlePerPlayer; required for apply")
    args = parser.parse_args()
    writable = args.mode in ("apply", "restore")
    process = HUD.Process(args.pid, writable)
    try:
        identity = process.identity()
        state = json.loads(args.state.read_text(encoding="utf-8")) if args.state.exists() else None
        if state is not None and (state["pid"] != args.pid or state["identity"] != identity):
            raise RuntimeError("state belongs to a different game process; refusing stale restore")

        if args.mode == "apply":
            if state is not None:
                raise RuntimeError("state file already exists; inspect or restore it instead")
            if args.dual_mode_flag is None:
                raise RuntimeError("--dual-mode-flag is required for apply")
            controller, split_width = MENU.find_active_common_menu(args.pid)
            if process.integer(COMMON_MENU_DRAW_SLOT) != RESCALE_ENTRY:
                raise RuntimeError("CommonMenu draw slot is not the expected rescale entry")
            if not process.read(args.dual_mode_flag, 1)[0]:
                raise RuntimeError("dual-mode flag is disabled; no wrapper was installed")
            allocation = process.k.VirtualAllocEx(process.handle, None, 0x1000, 0x3000, 0x04)
            process.check(allocation)
            if allocation + 0x1000 > 0x1_0000_0000:
                raise RuntimeError("native allocation is outside the 32-bit address range")
            code = native_wrapper(allocation, args.dual_mode_flag)
            process.write(allocation, code)
            process.protect(allocation, len(code), 0x20)
            process.check(process.k.FlushInstructionCache(process.handle, allocation, len(code)))
            state = {
                "pid": args.pid,
                "identity": identity,
                "status": "prepared",
                "allocation": allocation,
                "controller": controller,
                "initialSplitWidth": split_width,
                "dualModeFlag": args.dual_mode_flag,
                "drawSlot": COMMON_MENU_DRAW_SLOT,
                "originalDrawTarget": RESCALE_ENTRY,
                "wrapperSize": len(code),
            }
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as output:
                json.dump(state, output, indent=2)
            with process.suspended():
                process.expect(COMMON_MENU_DRAW_SLOT, u32(RESCALE_ENTRY))
                process.patch(COMMON_MENU_DRAW_SLOT, u32(allocation))
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            print(json.dumps(inspect(process, state), indent=2))
            return 0

        if state is None:
            raise RuntimeError("state file is required for inspect or restore")
        if args.mode == "inspect":
            print(json.dumps(inspect(process, state), indent=2))
            return 0

        actual = process.integer(COMMON_MENU_DRAW_SLOT)
        if actual not in (state["allocation"], state["originalDrawTarget"]):
            raise RuntimeError(f"unexpected CommonMenu draw target during restore: 0x{actual:X}")
        if actual == state["allocation"]:
            with process.suspended():
                process.expect(COMMON_MENU_DRAW_SLOT, u32(state["allocation"]))
                process.patch(COMMON_MENU_DRAW_SLOT, u32(state["originalDrawTarget"]))
        state["status"] = "restored"
        args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        print(json.dumps({"status": "restored", "drawSlot": hex(COMMON_MENU_DRAW_SLOT)}, indent=2))
        return 0
    finally:
        process.close()


if __name__ == "__main__":
    raise SystemExit(main())
