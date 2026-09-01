"""Trace the rectangle and scale inputs used to build one RE:Rev2 GUI profile."""

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
    parser.add_argument("--controller", action="append", type=number, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args()

    javascript = r"""
const controllers = new Set(%s);
const gridBuilder = ptr("0xE1A070");
const scaleBuilder = ptr("0xE1A270");
const events = new Map();

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function matchesController(value) {
    return controllers.has(value.toString().toLowerCase());
}

function readS32s(address, count) {
    const values = [];
    for (let index = 0; index < count; index++)
        values.push(address.add(index * 4).readS32());
    return values;
}

function record(kind, context, returnAddress, inputs) {
    const controller = context.ecx;
    if (!matchesController(controller))
        return;
    const key = kind + ":" + controller.toString();
    if (events.has(key))
        return;
    const row = {
        event: kind,
        controller: controller.toString(),
        vtable: controller.readPointer().toString(),
        inputs: inputs,
        returnAddress: returnAddress.toString(),
        returnDescription: describe(returnAddress),
        backtrace: Thread.backtrace(context, Backtracer.ACCURATE).map(describe)
    };
    events.set(key, row);
    send(row);
}

Interceptor.attach(gridBuilder, {
    onEnter(args) {
        try {
            record("grid", this.context, this.returnAddress, readS32s(args[0], 4));
        } catch (_) {
        }
    }
});

Interceptor.attach(scaleBuilder, {
    onEnter(args) {
        try {
            record("scale", this.context, this.returnAddress, {
                source: readS32s(args[0], 2),
                target: readS32s(args[1], 2)
            });
        } catch (_) {
        }
    }
});

send({ event: "ready", controllers: Array.from(controllers) });
""" % json.dumps([f"0x{value:x}" for value in args.controller])

    finished = threading.Event()
    rows: list[dict[str, object]] = []
    expected = len(args.controller) * 2
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print(
                    f"READY controllers={','.join(payload['controllers'])}", flush=True
                )
                return
            rows.append(payload)
            print(json.dumps(payload, indent=2), flush=True)
            if len(rows) >= expected:
                finished.set()
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                finished.set()

    script.on("message", on_message)
    script.load()
    try:
        finished.wait(args.timeout_seconds)
    finally:
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass
    return 0 if rows else 2


if __name__ == "__main__":
    raise SystemExit(main())
