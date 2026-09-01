"""Find the action handler that consumes controller Y's 0x1000 state.

For frames where any of a handler's three input masks contains 0x1000, capture
byte-level changes to its output object and actor input/action region.  This is
read-only Frida instrumentation.  Commands: reset NAME, snapshot, stop.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name, getattr(typing_extensions, compatibility_name))

import frida


HANDLERS = (
    ("A174E0", 0x00A174E0), ("A171B0", 0x00A171B0),
    ("A17C90", 0x00A17C90), ("A16F90", 0x00A16F90),
    ("A17670", 0x00A17670), ("A18220", 0x00A18220),
    ("A182F0", 0x00A182F0), ("A18690", 0x00A18690),
    ("A18840", 0x00A18840), ("A18120", 0x00A18120),
    ("A18030", 0x00A18030), ("A17DF0", 0x00A17DF0),
    ("A17B40", 0x00A17B40), ("A17F80", 0x00A17F80),
    ("A17440", 0x00A17440),
)


JAVASCRIPT_TEMPLATE = r"""
const definitions = __HANDLERS__;
const started = Date.now();
let phase = fresh("baseline");

function fresh(name) {
    return { name: name, resetAtMs: Date.now() - started, handlers: {} };
}

function readBytes(address, size) {
    try { return new Uint8Array(address.readByteArray(size)); } catch (_) { return null; }
}

function actorId(actor) {
    try { return actor.add(0x790c).readU8(); } catch (_) { return null; }
}

function row(name, address) {
    let value = phase.handlers[name];
    if (value === undefined) {
        value = {
            address: address,
            activeCalls: 0,
            actorCalls: {},
            combinations: {},
            returnTrue: 0,
            outputDiffs: {},
            actorDiffs: {},
            samples: []
        };
        phase.handlers[name] = value;
    }
    return value;
}

function addDiffs(target, before, after, base) {
    if (before === null || after === null) return [];
    const sample = [];
    for (let i = 0; i < before.length; i++) {
        if (before[i] === after[i]) continue;
        const key = "0x" + (base + i).toString(16);
        target[key] = (target[key] || 0) + 1;
        if (sample.length < 32)
            sample.push({ offset: key, before: before[i], after: after[i] });
    }
    return sample;
}

for (const definition of definitions) {
    const name = definition[0];
    const address = ptr(definition[1]);
    Interceptor.attach(address, {
        onEnter(args) {
            this.name = name;
            this.address = address.toString();
            this.actor = args[0];
            this.output = this.context.ecx;
            this.masks = [args[1].toUInt32(), args[2].toUInt32(), args[3].toUInt32()];
            this.combination = 0;
            for (let i = 0; i < 3; i++)
                if ((this.masks[i] & 0x1000) !== 0) this.combination |= (1 << i);
            this.active = this.combination !== 0;
            if (!this.active) return;
            this.outputBefore = readBytes(this.output, 0xb00);
            this.actorBefore = readBytes(this.actor.add(0x7800), 0x180);
        },
        onLeave(retval) {
            if (!this.active) return;
            const current = row(this.name, this.address);
            current.activeCalls++;
            const actorKey = this.actor.toString() + "/" + actorId(this.actor);
            current.actorCalls[actorKey] = (current.actorCalls[actorKey] || 0) + 1;
            const combo = "0b" + this.combination.toString(2).padStart(3, "0");
            current.combinations[combo] = (current.combinations[combo] || 0) + 1;
            if ((retval.toUInt32() & 0xff) !== 0) current.returnTrue++;
            const outputSample = addDiffs(current.outputDiffs, this.outputBefore, readBytes(this.output, 0xb00), 0);
            const actorSample = addDiffs(current.actorDiffs, this.actorBefore, readBytes(this.actor.add(0x7800), 0x180), 0x7800);
            if ((outputSample.length || actorSample.length) && current.samples.length < 12) {
                current.samples.push({
                    atMs: Date.now() - started,
                    actor: this.actor.toString(),
                    actorId: actorId(this.actor),
                    combination: combo,
                    masks: this.masks.map(v => "0x" + v.toString(16).padStart(8, "0")),
                    output: outputSample,
                    actorChanges: actorSample
                });
            }
        }
    });
}

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
    javascript = JAVASCRIPT_TEMPLATE.replace(
        "__HANDLERS__", json.dumps([[name, hex(address)] for name, address in HANDLERS])
    )
    session = frida.get_local_device().attach(args.pid)
    script = session.create_script(javascript)
    script.load()
    stop = threading.Event()

    def watchdog():
        if not stop.wait(args.timeout):
            print(json.dumps({"event": "timeout", "data": script.exports_sync.snapshot()}), flush=True)
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
    finally:
        stop.set()
        script.unload()
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
