"""Read-only profile of uGUICommandFar's animated direction node."""

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
    parser.add_argument("--function", type=number, default=0x00E68DF0)
    parser.add_argument("--seconds", type=float, default=3.0)
    args = parser.parse_args()

    javascript = r"""
const target = ptr("%s");
const commandFarVtable = ptr("0x0139AB40");
const durationMilliseconds = %d;
const groups = new Map();
let totalCalls = 0;
let commandFarCalls = 0;

function readPointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}

function readU32(address) {
    try { return address.readU32(); } catch (_) { return null; }
}

function readF32(address) {
    try { return address.readFloat(); } catch (_) { return null; }
}

function cleanFloat(value) {
    if (value === null || !Number.isFinite(value) || Math.abs(value) > 1000000)
        return null;
    return Math.round(value * 100000) / 100000;
}

function readable(address, size) {
    if (address.isNull())
        return false;
    try {
        const range = Process.findRangeByAddress(address);
        return range !== null && range.protection.indexOf("r") !== -1 &&
            address.add(size).compare(range.base.add(range.size)) <= 0;
    } catch (_) {
        return false;
    }
}

function fields(object, size) {
    if (!readable(object, size))
        return null;
    const result = [];
    for (let offset = 0; offset < size; offset += 4) {
        const value = readU32(object.add(offset));
        const floating = cleanFloat(readF32(object.add(offset)));
        if (value !== 0) {
            result.push({
                offset: "0x" + offset.toString(16),
                u32: "0x" + value.toString(16).padStart(8, "0"),
                f32: floating
            });
        }
    }
    return result;
}

function snapshot(node, owner, angle, mode) {
    const animation = readPointer(node.add(0xe8));
    const parentDefinition = readPointer(node.add(0x5c));
    const animationChildren = [];
    if (readable(animation, 0x20)) {
        for (let offset = 0; offset < 0x20; offset += Process.pointerSize) {
            const child = readPointer(animation.add(offset));
            if (!readable(child, 0x100))
                continue;
            animationChildren.push({
                slot: "0x" + offset.toString(16),
                address: child.toString(),
                fields: fields(child, 0x100)
            });
        }
    }
    return {
        node: node.toString(),
        owner: owner.toString(),
        player: readU32(owner.add(0x2ac)),
        angle: cleanFloat(angle),
        mode: mode,
        localPosition: [cleanFloat(readF32(node.add(0xa0))), cleanFloat(readF32(node.add(0xa4)))],
        localScale: [cleanFloat(readF32(node.add(0xb0))), cleanFloat(readF32(node.add(0xb4)))],
        matrixPosition: [cleanFloat(readF32(node.add(0x40))), cleanFloat(readF32(node.add(0x44)))],
        matrixScale: [cleanFloat(readF32(node.add(0x10))), cleanFloat(readF32(node.add(0x24)))],
        animation: animation.toString(),
        animationFields: fields(animation, 0x80),
        animationChildren: animationChildren,
        parentDefinition: parentDefinition.toString(),
        parentDefinitionFields: fields(parentDefinition, 0x100)
    };
}

Interceptor.attach(target, {
    onEnter() {
        totalCalls++;
        this.tracked = false;
        const node = this.context.ecx;
        const owner = readPointer(node.add(0x6c));
        if (owner.isNull() || !readPointer(owner).equals(commandFarVtable))
            return;
        commandFarCalls++;
        this.tracked = true;
        this.node = node;
        this.owner = owner;
        this.angle = readF32(this.context.esp.add(4));
        this.mode = readU32(this.context.esp.add(8));
    },
    onLeave() {
        if (!this.tracked)
            return;
        const current = snapshot(this.node, this.owner, this.angle, this.mode);
        const key = current.owner + "|" + current.node + "|" + current.angle;
        let group = groups.get(key);
        if (group === undefined) {
            current.calls = 0;
            group = current;
            groups.set(key, group);
        }
        group.calls++;
    }
});

setTimeout(function () {
    send({
        event: "summary",
        totalCalls: totalCalls,
        commandFarCalls: commandFarCalls,
        samples: Array.from(groups.values())
    });
}, durationMilliseconds);

send({ event: "ready" });
""" % (hex(args.function), max(1, round(args.seconds * 1000)))

    finished = threading.Event()
    result: dict | None = None
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal result
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print("READY", flush=True)
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
