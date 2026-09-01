"""Profile calls into CommandNear/Far vtable methods around controller Y.

The instrumentation is read-only.  It discovers function pointers from the two
native vtables, filters calls whose ECX is one of the selected live controller
objects, and groups callers by the current raw XInput-Y state.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
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
    parser.add_argument("--seconds", type=float, default=15.0)
    parser.add_argument("--vtable-size", type=number, default=0x100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    javascript = r"""
const controllers = new Set(__CONTROLLERS__.map(value => ptr(value).toString()));
const vtables = [ptr("0x0139AB40"), ptr("0x0139ACA0")];
const vtableSize = __VTABLE_SIZE__;
const durationMs = __DURATION__;
const rows = new Map();
const hooks = [];
const hooked = new Set();
let yDown = false;
let yEdges = 0;

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null) return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function add(address, caller, object) {
    const key = address + "|" + caller + "|" + object;
    let row = rows.get(key);
    if (row === undefined) {
        row = { method: address, caller: caller, object: object, up: 0, down: 0 };
        rows.set(key, row);
    }
    if (yDown) row.down++; else row.up++;
}

for (const vtable of vtables) {
    for (let offset = 0; offset < vtableSize; offset += Process.pointerSize) {
        let method;
        try { method = vtable.add(offset).readPointer(); } catch (_) { continue; }
        if (method.isNull()) continue;
        const range = Process.findRangeByAddress(method);
        if (range === null || range.protection.indexOf("x") === -1) continue;
        const key = method.toString();
        if (hooked.has(key)) continue;
        hooked.add(key);
        try {
            Interceptor.attach(method, {
                onEnter() {
                    const object = this.context.ecx.toString();
                    if (!controllers.has(object)) return;
                    add(key, describe(this.returnAddress), object);
                }
            });
            hooks.push({ address: key, source: describe(method) });
        } catch (_) {
            hooks.push({ address: key, source: describe(method), skipped: true });
        }
    }
}

const xinputHooks = [];
const xinputSeen = new Set();
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase().indexOf("xinput") === -1) continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type !== "function" || exported.name.indexOf("XInputGetState") === -1)
            continue;
        const key = exported.address.toString();
        if (xinputSeen.has(key)) continue;
        xinputSeen.add(key);
        xinputHooks.push(key);
        Interceptor.attach(exported.address, {
            onEnter(args) {
                this.index = args[0].toUInt32();
                this.state = args[1];
                this.caller = describe(this.returnAddress);
            },
            onLeave(retval) {
                if (retval.toUInt32() !== 0 || this.state.isNull()) return;
                if (this.index !== 0 || this.caller !== "rerev2.exe+0x814b06") return;
                let buttons;
                try { buttons = this.state.add(4).readU16(); } catch (_) { return; }
                const current = (buttons & 0x8000) !== 0;
                if (current !== yDown) yEdges++;
                yDown = current;
            }
        });
    }
}

setTimeout(function () {
    send({
        event: "summary",
        yEdges: yEdges,
        hooks: hooks,
        xinputHooks: xinputHooks,
        rows: Array.from(rows.values()).sort(function (a, b) {
            const aScore = a.down - a.up;
            const bScore = b.down - b.up;
            if (aScore !== bScore) return bScore - aScore;
            return b.down - a.down;
        })
    });
}, durationMs);
send({ event: "ready", methods: hooks.length, xinputHooks: xinputHooks });
"""
    javascript = (
        javascript.replace("__CONTROLLERS__", json.dumps([hex(value) for value in args.controller]))
        .replace("__VTABLE_SIZE__", str(args.vtable_size))
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
                print("READY " + json.dumps(payload), flush=True)
            elif payload.get("event") == "summary":
                result = payload
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                    print(json.dumps({"event": "summary", "yEdges": payload.get("yEdges"), "rows": len(payload.get("rows", [])), "output": str(args.output)}), flush=True)
                else:
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
