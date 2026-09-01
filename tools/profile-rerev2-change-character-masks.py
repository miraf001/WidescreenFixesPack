"""Trace the three native masks entering RE:Rev2's ChangeCharacter handler.

The dispatcher passes current/transition input masks as args 1..3 to
sub_A16F90.  This read-only Frida profile records only changes involving the
controller profile's 0x1000 button and branch/query counters.  Commands:

    reset NAME
    snapshot
    stop
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name, getattr(typing_extensions, compatibility_name))

import frida


JAVASCRIPT = r"""
const handler = ptr("0x00A16F90");
const keyboardContinuation = ptr("0x00A17038");
const controllerContinuation = ptr("0x00A1703D");
const started = Date.now();
let phase = fresh("baseline");

function readU8(address) {
    try { return address.readU8(); } catch (_) { return null; }
}

function actorId(actor) {
    if (actor.isNull()) return null;
    return readU8(actor.add(0x790c));
}

function fresh(name) {
    return {
        name: name,
        resetAtMs: Date.now() - started,
        calls: 0,
        actorCalls: {},
        keyboardBranchCalls: 0,
        keyboardTrueCalls: 0,
        controllerBranchCalls: 0,
        combinations: {},
        transitions: [],
        previous: {}
    };
}

function keyFor(actor) { return actor.toString(); }
function hex(value) { return "0x" + value.toString(16).padStart(8, "0"); }

Interceptor.attach(handler, {
    onEnter(args) {
        const actor = args[0];
        const id = actorId(actor);
        const masks = [args[1].toUInt32(), args[2].toUInt32(), args[3].toUInt32()];
        const key = keyFor(actor);
        phase.calls++;
        phase.actorCalls[key] = (phase.actorCalls[key] || 0) + 1;
        let combination = 0;
        for (let i = 0; i < 3; i++)
            if ((masks[i] & 0x1000) !== 0) combination |= (1 << i);
        phase.combinations["0b" + combination.toString(2).padStart(3, "0")] =
            (phase.combinations["0b" + combination.toString(2).padStart(3, "0")] || 0) + 1;
        const previous = phase.previous[key];
        if (combination !== 0 || previous === undefined || previous.combination !== combination) {
            if (phase.transitions.length < 256) {
                phase.transitions.push({
                    atMs: Date.now() - started,
                    actor: actor.toString(),
                    actorId: id,
                    combination: "0b" + combination.toString(2).padStart(3, "0"),
                    masks: masks.map(hex)
                });
            }
        }
        phase.previous[key] = { combination: combination, masks: masks };
    }
});

Interceptor.attach(keyboardContinuation, {
    onEnter() {
        phase.keyboardBranchCalls++;
        if ((this.context.eax.toUInt32() & 0xff) !== 0)
            phase.keyboardTrueCalls++;
    }
});

Interceptor.attach(controllerContinuation, {
    onEnter() { phase.controllerBranchCalls++; }
});

rpc.exports = {
    reset(name) { phase = fresh(name); return true; },
    snapshot() { return phase; }
};
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args()
    device = frida.get_local_device()
    session = device.attach(args.pid)
    script = session.create_script(JAVASCRIPT)
    script.load()
    stop = threading.Event()

    def watchdog():
        if not stop.wait(args.timeout):
            print(json.dumps({"event": "timeout", "snapshot": script.exports_sync.snapshot()}), flush=True)
            stop.set()

    threading.Thread(target=watchdog, daemon=True).start()
    print(json.dumps({"event": "ready", "pid": args.pid}), flush=True)
    try:
        for line in sys.stdin:
            command = line.strip().split(maxsplit=1)
            if not command:
                continue
            if command[0] == "reset":
                name = command[1] if len(command) > 1 else "capture"
                script.exports_sync.reset(name)
                print(json.dumps({"event": "reset", "name": name}), flush=True)
            elif command[0] == "snapshot":
                print(json.dumps({"event": "snapshot", "data": script.exports_sync.snapshot()}), flush=True)
            elif command[0] == "stop":
                print(json.dumps({"event": "stop", "data": script.exports_sync.snapshot()}), flush=True)
                break
            else:
                print(json.dumps({"event": "error", "command": line.strip()}), flush=True)
    finally:
        stop.set()
        script.unload()
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
