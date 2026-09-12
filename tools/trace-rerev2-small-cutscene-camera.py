"""Focused read-only trace for RE:Rev2 short co-op event-camera routing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import threading
import time
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name, getattr(typing_extensions, compatibility_name))

ROOT = Path(__file__).resolve().parents[1]
FRIDA_PATH = ROOT / "out" / "toolchain" / "frida-17.5.1"
if FRIDA_PATH.is_dir():
    sys.path.insert(0, str(FRIDA_PATH))

import frida  # noqa: E402


SCRIPT = r"""
'use strict';

const graphicsSlot = ptr('0x015DE88C');
const rendererSlot = ptr('0x015E0388');
const splitSlot = ptr('0x0157AE00');
const eventCameraVtable = ptr('0x01264FE0');
const updateLayout = ptr('0x004AE570');
const bindScreenCamera = ptr('0x004A68C0');
const routeCamera = ptr('0x008882D0');
const routeMode = ptr('0x008882F0');
const demoBoot = ptr('0x0075D3A0');
const findEventCamera = ptr('0x0075D7D0');
const applyCameraRouting = ptr('0x0075D8D0');

const renderer = rendererSlot.readPointer();
const device = renderer.add(0x98).readPointer();
const vtable = device.readPointer();
const present = vtable.add(17 * Process.pointerSize).readPointer();
const listeners = [];
let enabled = true;
let frame = 0;
let sequence = 0;
let pending = [];
let lastSignature = '';

function safePointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}
function safeU8(address) {
    try { return address.readU8(); } catch (_) { return null; }
}
function safeS32(address) {
    try { return address.readS32(); } catch (_) { return null; }
}
function safeU32(address) {
    try { return address.readU32(); } catch (_) { return null; }
}
function describeAddress(address) {
    const module = Process.findModuleByAddress(address);
    return {
        address: address.toString(),
        module: module === null ? null : module.name,
        offset: module === null ? null : address.sub(module.base).toString()
    };
}
function cameraAt(address) {
    const object = safePointer(address);
    const objectVtable = object.isNull() ? NULL : safePointer(object);
    return {
        pointer: object.toString(),
        vtable: objectVtable.toString(),
        isEvent: objectVtable.equals(eventCameraVtable)
    };
}
function splitState() {
    const split = safePointer(splitSlot);
    if (split.isNull()) return null;
    return {
        pointer: split.toString(),
        activePlayer: safeS32(split.add(0x7a8)),
        modeTarget: safeS32(split.add(0x8f0)),
        modeCurrent: safeS32(split.add(0x8f4)),
        camera0: safeS32(split.add(0x8f8)),
        camera1: safeS32(split.add(0x8fc))
    };
}
function state() {
    const graphics = safePointer(graphicsSlot);
    if (graphics.isNull()) return null;
    return {
        graphics: graphics.toString(),
        split: splitState(),
        screen0: cameraAt(graphics.add(0x34)),
        screen1: cameraAt(graphics.add(0x1c4)),
        screen0Rect: [safeS32(graphics.add(0x48)), safeS32(graphics.add(0x4c)),
            safeS32(graphics.add(0x50)), safeS32(graphics.add(0x54))],
        screen1Rect: [safeS32(graphics.add(0x1d8)), safeS32(graphics.add(0x1dc)),
            safeS32(graphics.add(0x1e0)), safeS32(graphics.add(0x1e4))],
        cachedMode: safeS32(graphics.add(0xce0)),
        cachedCamera0: safeS32(graphics.add(0xcf0)),
        cachedCamera1: safeS32(graphics.add(0xcf4)),
        layoutDirty: safeU8(graphics.add(0xd0c))
    };
}
function event(point, fields) {
    pending.push(Object.assign({sequence: sequence++, point: point}, fields || {}));
}
function stackS32(context, offset) {
    return safeS32(context.esp.add(offset));
}

listeners.push(Interceptor.attach(updateLayout, {
    onEnter(_) {
        if (!enabled) return;
        this.capture = true;
        event('updateLayout.enter', {
            caller: describeAddress(this.returnAddress),
            ecx: this.context.ecx.toString(), state: state()
        });
    },
    onLeave(_) {
        if (!enabled || !this.capture) return;
        event('updateLayout.leave', {state: state()});
    }
}));

listeners.push(Interceptor.attach(bindScreenCamera, {
    onEnter(_) {
        if (!enabled) return;
        this.capture = true;
        event('bindScreenCamera.enter', {
            caller: describeAddress(this.returnAddress),
            screen: stackS32(this.context, 4), enabledArg: stackS32(this.context, 8),
            state: state()
        });
    },
    onLeave(_) {
        if (!enabled || !this.capture) return;
        event('bindScreenCamera.leave', {state: state()});
    }
}));

listeners.push(Interceptor.attach(routeCamera, {
    onEnter(_) {
        if (!enabled) return;
        event('routeCamera', {
            caller: describeAddress(this.returnAddress),
            screen: stackS32(this.context, 4), camera: stackS32(this.context, 8),
            state: state()
        });
    }
}));

listeners.push(Interceptor.attach(routeMode, {
    onEnter(_) {
        if (!enabled) return;
        event('routeMode', {
            caller: describeAddress(this.returnAddress),
            arg0: stackS32(this.context, 4), arg1: stackS32(this.context, 8),
            state: state()
        });
    }
}));

for (const [name, address] of Object.entries({demoBoot, findEventCamera, applyCameraRouting})) {
    listeners.push(Interceptor.attach(address, {
        onEnter(_) {
            if (!enabled) return;
            this.capture = true;
            event(name + '.enter', {
                caller: describeAddress(this.returnAddress),
                object: this.context.ecx.toString(), state: state()
            });
        },
        onLeave(result) {
            if (!enabled || !this.capture) return;
            event(name + '.leave', {result: result.toString(), state: state()});
        }
    }));
}

listeners.push(Interceptor.attach(present, {
    onEnter(args) {
        if (!enabled || !args[0].equals(device)) return;
        const current = state();
        const signature = JSON.stringify(current);
        if (pending.length || signature !== lastSignature) {
            send({event: 'frame', frame, state: current, timeline: pending});
            pending = [];
            lastSignature = signature;
        }
        frame++;
    }
}));

rpc.exports = {
    snapshot() {
        return {event: 'snapshot', frame, state: state(), timeline: pending};
    },
    stop() {
        enabled = false;
        for (const listener of listeners) listener.detach();
        return {event: 'stopped', frame, state: state(), timeline: pending};
    }
};

send({event: 'ready', pid: Process.id, device: device.toString(), state: state()});
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=120.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = args.output.open("w", encoding="utf-8", buffering=1)
    ready = threading.Event()
    detached = threading.Event()
    errors: list[dict[str, object]] = []
    session = frida.attach(args.pid)
    session.on("detached", lambda *unused: detached.set())
    script = session.create_script(SCRIPT)

    def on_message(message: dict[str, object], data: bytes | None) -> None:
        output.write(json.dumps(message, ensure_ascii=False) + "\n")
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("event") == "ready":
                print(json.dumps(payload, ensure_ascii=False), flush=True)
                ready.set()
        else:
            errors.append(message)
            print(json.dumps(message, ensure_ascii=False), flush=True)
            ready.set()

    script.on("message", on_message)
    script.load()
    if not ready.wait(5.0) or errors:
        raise RuntimeError("small-cutscene camera trace failed to initialize")
    print(f"TRACE_READY output={args.output}", flush=True)
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline and not detached.wait(0.25):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        if not detached.is_set():
            stopped = script.exports_sync.stop()
            output.write(json.dumps(stopped, ensure_ascii=False) + "\n")
            print(json.dumps(stopped, ensure_ascii=False), flush=True)
            script.unload()
            session.detach()
        output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
