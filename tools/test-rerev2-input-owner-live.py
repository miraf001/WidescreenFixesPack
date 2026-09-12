"""Reversible native keyboard/mouse isolation for the assigned primary actor.

This is NOT an input/gamepad emulator. The game still reads native input and
selects devices. Its gameplay keyboard predicates additionally require the
actor assigned to player 1. Player 2 follows the original gamepad branches.
No actor fields, controller assignments, HUD hooks, or bridge state are changed.
Use with bridge capture released (F9); keep both pads connected.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("input_base", Path(__file__).with_name("test-rerev2-input-live.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
hud = base.hud
ACTOR_MANAGER = 0x1567EAC
VERSION = 1

# (instruction address, actor register, native comparison bytes).
# Only verified keyboard-mode predicates, NOT arbitrary actor+7920 checks.
# Both local co-op actors have +7920==0; it is not a player index.
EAX_MODE = "83 b8 bc c4 15 00 01"
ECX_MODE = "83 b9 bc c4 15 00 01"
GATES = (
    (0x7017D5, "ebx", EAX_MODE),  # native actor keyboard action helper
    (0x704635, "esi", ECX_MODE),  # actor mode-dependent action eligibility
    (0xA126EF, "edi", ECX_MODE), # alternate camera/input path
    (0xA127F2, "edi", EAX_MODE),
    (0xA128D2, "edi", ECX_MODE),
    (0xA12AA4, "edi", ECX_MODE),
    (0xA14E29, "ecx", EAX_MODE), # per-actor action helper
    (0xA14ECA, "eax", "83 b8 20 79 00 00 00"), # bool helper; EAX later becomes cfg
    (0xA154E4, "esi", EAX_MODE),
    (0xA155A5, "esi", EAX_MODE), # WASD and mouse-look branch
    (0xA15BD3, "esi", EAX_MODE),
    (0xA15CC4, "esi", EAX_MODE),
    (0xA15D09, "esi", EAX_MODE),
    (0xA1688F, "esi", EAX_MODE),
    (0xA16BC3, "esi", EAX_MODE),
    (0xA171F8, "ebx", EAX_MODE),
    (0xA17371, "ebx", EAX_MODE),
    (0xA17460, "edi", EAX_MODE),
    (0xA1751F, "esi", EAX_MODE),
    (0xA17716, "ebx", EAX_MODE),
    (0xA17831, "ebx", EAX_MODE),
    (0xA17CC9, "esi", EAX_MODE),
    (0xA17E8A, "edi", EAX_MODE),
    (0xA17FB4, "edi", EAX_MODE),
    (0xA18086, "edi", EAX_MODE),
    (0xA1824D, "edi", EAX_MODE),
    (0xA1838F, "ebx", EAX_MODE),
    (0xA186E6, "edi", EAX_MODE),
    (0x40EF84, "ebp", EAX_MODE), # interactable selected for this actor/player
)
CODE_SIZE = ((len(GATES) * 0x100 + 4095) // 4096) * 4096
GUARDS = tuple((a, b) for a, b in base.GUARDS if a != 0xA155A5) + (
    (0x6E6DC0, bytes.fromhex("8b44240483f8ff7f0533c0c2040083f8087df68b448120c20400")),
    (0x886DD0, bytes.fromhex("8b44240483f801770a8b8481f8080000c20400")),
)


def redirect(site, target, size):
    return b"\xe9" + hud.u32((target - site - 5) & 0xFFFFFFFF) + b"\x90" * (size - 5)


def make_thunk(address, counter, gate):
    """Replay one CMP; add ownership to its ZF result only in split mode.

    Preserve all GPR/SSE registers, stack and all other native result flags.
    The original conditional branch remains in place. Original false, SP, and
    the assigned primary actor all retain the native comparison result.
    Actor identity is compared by pointer against the native manager slot;
    no unverified actor pointer is dereferenced and no actor field is written.
    """
    site, actor, original = gate
    code = bytearray.fromhex(original)
    fixups, labels = [], {}

    def emit(s):
        code.extend(bytes.fromhex(s))

    def branch(op, target):
        emit(op)
        fixups.append((len(code), target))
        code.extend(bytes(4))

    emit("9c 60") # PUSHFD, PUSHAD (saved comparison flags at [esp+32])
    branch("0f 85", "native")
    emit({"eax": "8b f0", "ecx": "8b f1", "ebx": "8b f3",
          "esi": "8b f6", "edi": "8b f7", "ebp": "8b f5"}[actor])
    emit("a1")
    code.extend(hud.u32(hud.MODE_POINTER))
    emit("85 c0")
    branch("0f 84", "native")
    emit("83 b8 f0 08 00 00 01")
    branch("0f 85", "native")
    emit("85 f6")
    branch("0f 84", "blocked")
    emit("8b 90 f8 08 00 00 83 fa 08") # assigned P1 actor slot, range 0..7
    branch("0f 83", "blocked")
    emit("8b 0d")
    code.extend(hud.u32(ACTOR_MANAGER))
    emit("85 c9")
    branch("0f 84", "blocked")
    emit("3b 74 91 20") # cmp esi,[ecx+edx*4+20] = native actor array
    branch("0f 85", "blocked")
    emit("f0 ff 05")
    code.extend(hud.u32(counter)) # verified primary actor
    branch("e9", "done")
    labels["blocked"] = len(code)
    emit("f0 ff 05")
    code.extend(hud.u32(counter + 4))
    emit("83 64 24 20 bf") # clear ONLY saved ZF; leave original branch to use pad path
    branch("e9", "done")
    labels["native"] = len(code)
    emit("f0 ff 05")
    code.extend(hud.u32(counter + 8))
    labels["done"] = len(code)
    emit("61 9d e9")
    code.extend(hud.u32((site + len(bytes.fromhex(original)) - address - len(code) - 4) & 0xFFFFFFFF))
    for offset, name in fixups:
        struct.pack_into("<i", code, offset, labels[name] - offset - 4)
    if len(code) > 0x100:
        raise RuntimeError("Ownership thunk exceeds its slot")
    return bytes(code)


def blobs(allocation):
    return [(allocation + i * 0x100,
             make_thunk(allocation + i * 0x100, allocation + CODE_SIZE + i * 12, gate))
            for i, gate in enumerate(GATES)]


def patches(allocation):
    return [(site, bytes.fromhex(original), redirect(site, allocation + i * 0x100, len(bytes.fromhex(original))))
            for i, (site, _, original) in enumerate(GATES)] + [(base.SITE, base.ORIGINAL, base.PATCHED)]


def actors(process):
    manager = process.integer(ACTOR_MANAGER)
    result = []
    if manager:
        for index in range(8):
            actor = process.integer(manager + 0x20 + 4 * index)
            if actor:
                result.append({"slot": index, "pointer": hex(actor),
                               "id": process.read(actor + 0x790C, 1)[0],
                               "category": process.integer(actor + 0x7920)})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mode", choices=("inspect", "apply", "restore"), default="inspect")
    args = parser.parse_args()
    state = json.loads(args.state.read_text()) if args.state.exists() else None
    process = hud.Process(args.pid, args.mode != "inspect")
    try:
        identity = process.identity()
        if state and (state["pid"] != args.pid or state["identity"] != identity or state.get("version") != VERSION):
            raise RuntimeError("State belongs to a different process or experiment version")
        asi = Path(identity["image"]).parent / "scripts/ResidentEvilRevelations2.FusionFix.asi"
        if hashlib.sha256(asi.read_bytes()).hexdigest() != hud.ASI_HASH:
            raise RuntimeError("Only the verified Debug build is supported")
        for a, b in GUARDS:
            process.expect(a, b)
        if state:
            for a, b in blobs(state["allocation"]):
                process.expect(a, b)
        if args.mode == "apply":
            if state:
                raise RuntimeError("Use a fresh state path; backups are never overwritten")
            for a, b, _ in patches(0):
                process.expect(a, b)
            before = base.snapshot(process)
            if before["splitMode"] != 1 or before["splitState"] != 1:
                raise RuntimeError("Apply only in active co-op")
            actor_list = actors(process)
            primary = before["playerAssignment"][0]
            if not any(a["slot"] == primary and a["id"] == primary for a in actor_list):
                raise RuntimeError("Primary actor assignment has not been verified")
            allocation = process.k.VirtualAllocEx(process.handle, None, CODE_SIZE + 4096, 0x3000, 0x04)
            process.check(allocation)
            if allocation + CODE_SIZE + 4096 > 0x100000000:
                raise RuntimeError("Allocation outside x86 address space")
            state = {"pid": args.pid, "identity": identity, "version": VERSION,
                     "status": "prepared", "allocation": allocation, "before": before,
                     "actorsBefore": actor_list, "patches": [
                         {"address": hex(a), "original": b.hex(), "patched": c.hex()}
                         for a, b, c in patches(allocation)]}
            for a, b in blobs(allocation):
                process.write(a, b)
                process.expect(a, b)
            process.protect(allocation, CODE_SIZE, 0x20)
            process.check(process.k.FlushInstructionCache(process.handle, allocation, CODE_SIZE))
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            mode = process.integer(hud.MODE_POINTER)
            hud.transact(process, patches(allocation), guards=GUARDS + (
                (hud.MODE_POINTER, hud.u32(mode)), (mode + 0x8F0, hud.u32(1) + hud.u32(1))))
            state["status"] = "applied"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        elif args.mode == "restore":
            if not state or state["status"] not in ("prepared", "applied"):
                raise RuntimeError("No active ownership experiment to restore")
            changes = []
            for a, b, c in patches(state["allocation"]):
                actual = process.read(a, len(b))
                if actual not in (b, c):
                    raise RuntimeError(f"Unexpected code at {a:X}; no writes performed")
                changes.append((a, actual, b))
            hud.transact(process, list(reversed(changes)), guards=GUARDS)
            # Retain executable memory for any in-flight thunks until process exit.
            state["status"] = "restored"
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
        for a, b, c in patches(state["allocation"] if state else 0):
            process.expect(a, c if state and state["status"] == "applied" else b)
        result = {"pid": args.pid, "status": state["status"] if state else "native",
                  **base.snapshot(process), "actors": actors(process)}
        if state:
            result["counters"] = {hex(g[0]): dict(zip(("primary", "blocked", "native"),
                struct.unpack("<3I", process.read(state["allocation"] + CODE_SIZE + i * 12, 12))))
                for i, g in enumerate(GATES)}
        print(json.dumps(result, indent=2))
    finally:
        process.close()


if __name__ == "__main__":
    main()
