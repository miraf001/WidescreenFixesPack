"""Capture grouped input/output GUI transforms at the focused RE:Rev2 hook."""

from __future__ import annotations

import argparse
import json
import threading
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name, getattr(typing_extensions, compatibility_name))

import frida


def number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=number, required=True)
    parser.add_argument("--function", type=number, required=True)
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument("--maximum-groups", type=int, default=512)
    args = parser.parse_args()

    javascript = r"""
const target = ptr("%s");
const durationMilliseconds = %d;
const maximumGroups = %d;
const groups = new Map();
let calls = 0;

function readPointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}

function readS32(address) {
    try { return address.readS32(); } catch (_) { return null; }
}

function readU32(address) {
    try { return address.readU32(); } catch (_) { return null; }
}

function readF32(address) {
    try { return address.readFloat(); } catch (_) { return null; }
}

function cleanFloat(value) {
    if (value === null || !Number.isFinite(value))
        return null;
    return Math.round(value * 10000) / 10000;
}

function transformFromPointer(transform) {
    if (transform.isNull())
        return null;
    const values = [0, 4, 8, 12].map(offset => cleanFloat(readF32(transform.add(offset))));
    if (values.some(value => value === null))
        return null;
    return { pointer: transform.toString(), values: values };
}

Interceptor.attach(target, {
    onEnter() {
        this.tracked = false;
        calls++;
        const object = this.context.ecx;
        let context = NULL;
        let builder = NULL;
        try {
            context = this.context.esp.add(4).readPointer();
            builder = readPointer(context.add(4));
        } catch (_) {
            return;
        }
        if (builder.isNull())
            return;

        const bounds = [
            readS32(builder.add(47 * 4)),
            readS32(builder.add(48 * 4)),
            readS32(builder.add(49 * 4)),
            readS32(builder.add(50 * 4))
        ];
        const inputs = [
            cleanFloat(readF32(object.add(0x60))),
            cleanFloat(readF32(object.add(0x64))),
            cleanFloat(readF32(object.add(0x40))),
            cleanFloat(readF32(object.add(0x44)))
        ];
        if (bounds.some(value => value === null) || inputs.some(value => value === null))
            return;

        this.tracked = true;
        this.object = object;
        this.builder = builder;
        this.outputPointer = readPointer(builder.add(5 * Process.pointerSize));
        this.bounds = bounds;
        this.inputs = inputs;
        this.flags = readU32(object.add(0x148));
        this.returnAddressValue = this.returnAddress;
    },
    onLeave() {
        if (!this.tracked)
            return;
        const output = transformFromPointer(this.outputPointer);
        if (output === null)
            return;

        const key = JSON.stringify([this.bounds, this.inputs, output.values, this.flags]);
        let group = groups.get(key);
        if (group === undefined) {
            if (groups.size >= maximumGroups)
                return;
            group = {
                bounds: this.bounds,
                input: {
                    scaleX: this.inputs[0],
                    scaleY: this.inputs[1],
                    positionX: this.inputs[2],
                    positionY: this.inputs[3]
                },
                output: output.values,
                flags: this.flags === null ? null : "0x" + this.flags.toString(16),
                sampleObject: this.object.toString(),
                sampleBuilder: this.builder.toString(),
                returnAddress: this.returnAddressValue.toString(),
                calls: 0
            };
            groups.set(key, group);
        }
        group.calls++;
    }
});

setTimeout(function () {
    const rows = Array.from(groups.values());
    rows.sort((left, right) => right.calls - left.calls);
    send({ event: "summary", totalCalls: calls, capturedGroups: rows.length, groups: rows });
}, durationMilliseconds);

send({ event: "ready", target: target.toString() });
""" % (
        hex(args.function),
        max(1, round(args.seconds * 1000)),
        max(1, args.maximum_groups),
    )

    finished = threading.Event()
    result: dict | None = None
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal result
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print(f"READY target={payload['target']}", flush=True)
            elif payload.get("event") == "summary":
                result = payload
                print(json.dumps(payload, indent=2), flush=True)
                finished.set()
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                finished.set()

    script.on("message", on_message)
    script.load()
    try:
        finished.wait(args.seconds + 5.0)
    finally:
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass

    return 0 if result is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
