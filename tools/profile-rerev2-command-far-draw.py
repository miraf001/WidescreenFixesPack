"""Read-only capture of CommandFar animation fields at final GUI draw entry."""

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
    parser.add_argument("--seconds", type=float, default=2.0)
    args = parser.parse_args()

    javascript = r"""
const target = ptr("%s");
const durationMilliseconds = %d;
const farVtable = ptr("0x0139AB40");
const groups = new Map();
let calls = 0;

function pointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}
function u32(address) {
    try { return address.readU32(); } catch (_) { return null; }
}
function f32(address) {
    try {
        const value = address.readFloat();
        return Number.isFinite(value) ? Math.round(value * 100000) / 100000 : null;
    } catch (_) { return null; }
}

Interceptor.attach(target, {
    onEnter() {
        const controller = this.context.ecx;
        if (!pointer(controller).equals(farVtable))
            return;
        calls++;
        const table = pointer(controller.add(0xf8));
        const node = table.isNull() ? NULL : pointer(table.add(4));
        const animation = node.isNull() ? NULL : pointer(node.add(0xe8));
        const children = [];
        if (!animation.isNull()) {
            for (let slot = 4; slot < 0x1c; slot += 4) {
                const child = pointer(animation.add(slot));
                if (child.isNull())
                    continue;
                children.push({
                    slot: "0x" + slot.toString(16),
                    address: child.toString(),
                    matrix: [f32(child.add(0x40)), f32(child.add(0x44))],
                    animationPosition: [f32(child.add(0x80)), f32(child.add(0x84))],
                    scale: [f32(child.add(0x10)), f32(child.add(0x24))]
                });
            }
        }
        const sample = {
            controller: controller.toString(),
            player: u32(controller.add(0x2ac)),
            bounds: [u32(controller.add(0x168)), u32(controller.add(0x16c)),
                     u32(controller.add(0x170)), u32(controller.add(0x174))],
            node: node.toString(),
            animation: animation.toString(),
            children: children
        };
        const key = JSON.stringify(sample);
        let group = groups.get(key);
        if (group === undefined) {
            sample.calls = 0;
            group = sample;
            groups.set(key, group);
        }
        group.calls++;
    }
});

setTimeout(function () {
    send({event: "summary", calls: calls, samples: Array.from(groups.values())});
}, durationMilliseconds);
send({event: "ready"});
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
