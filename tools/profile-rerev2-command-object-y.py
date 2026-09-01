"""Capture uGUICommandNear/Far object state around clean controller-Y edges.

This is read-only Frida instrumentation.  It watches the native XInput poll,
records rising/falling Y edges, and snapshots selected live GUI controllers at
small delays around each edge so activation-state fields can be identified.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import threading
import time
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(
            typing,
            compatibility_name,
            getattr(typing_extensions, compatibility_name),
        )

import frida


def number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=number, required=True)
    parser.add_argument("--controller", action="append", type=number, required=True)
    parser.add_argument("--seconds", type=float, default=15.0)
    parser.add_argument("--size", type=number, default=0x400)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    javascript = r"""
const controllers = __CONTROLLERS__.map(value => ptr(value));
const captureSize = __SIZE__;
const durationMs = __DURATION__;
const started = Date.now();
const events = [];
const previousBySource = new Map();
let edge = 0;

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null) return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function bytes(address, size) {
    try {
        const raw = new Uint8Array(address.readByteArray(size));
        let text = "";
        for (let i = 0; i < raw.length; i++)
            text += raw[i].toString(16).padStart(2, "0");
        return text;
    } catch (_) {
        return null;
    }
}

function pointer(address, offset) {
    try { return address.add(offset).readPointer(); } catch (_) { return NULL; }
}

function snapshot(kind, edgeId, delayMs, yDown, source) {
    const rows = [];
    for (const controller of controllers) {
        const root = pointer(controller, 0xf4);
        rows.push({
            controller: controller.toString(),
            object: bytes(controller, captureSize),
            root: root.toString(),
            rootBytes: root.isNull() ? null : bytes(root, 0x200)
        });
    }
    events.push({
        atMs: Date.now() - started,
        kind: kind,
        edge: edgeId,
        delayMs: delayMs,
        yDown: yDown,
        source: source,
        rows: rows
    });
}

function schedule(kind, edgeId, yDown, source) {
    for (const delay of [0, 16, 50, 120, 300, 700]) {
        setTimeout(function () {
            snapshot(kind, edgeId, delay, yDown, source);
        }, delay);
    }
}

snapshot("baseline", 0, 0, false, "ready");

const hooks = [];
const seen = new Set();
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase().indexOf("xinput") === -1) continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type !== "function" || exported.name.indexOf("XInputGetState") === -1)
            continue;
        const addressKey = exported.address.toString();
        if (seen.has(addressKey)) continue;
        seen.add(addressKey);
        hooks.push({ module: module.name, name: exported.name, address: addressKey });
        Interceptor.attach(exported.address, {
            onEnter(args) {
                this.index = args[0].toUInt32();
                this.state = args[1];
                this.caller = describe(this.returnAddress);
            },
            onLeave(retval) {
                if (retval.toUInt32() !== 0 || this.state.isNull()) return;
                let buttons;
                try { buttons = this.state.add(4).readU16(); } catch (_) { return; }
                const key = this.caller + "|" + this.index;
                const down = (buttons & 0x8000) !== 0;
                const previous = previousBySource.get(key);
                previousBySource.set(key, down);
                if (previous === undefined || previous === down) return;
                edge++;
                schedule(down ? "rising" : "falling", edge, down, key);
            }
        });
    }
}

setTimeout(function () {
    send({ event: "summary", hooks: hooks, events: events });
}, durationMs);
send({ event: "ready", hooks: hooks });
"""
    javascript = (
        javascript.replace("__CONTROLLERS__", json.dumps([hex(value) for value in args.controller]))
        .replace("__SIZE__", str(args.size))
        .replace("__DURATION__", str(max(1, round(args.seconds * 1000))))
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
                print("READY " + json.dumps(payload.get("hooks", [])), flush=True)
            elif payload.get("event") == "summary":
                result = payload
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                    print(
                        json.dumps(
                            {
                                "event": "summary",
                                "events": len(payload.get("events", [])),
                                "output": str(args.output),
                            }
                        ),
                        flush=True,
                    )
                else:
                    print(json.dumps(payload), flush=True)
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
