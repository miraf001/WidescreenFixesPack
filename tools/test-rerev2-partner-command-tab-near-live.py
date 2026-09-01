"""Timed P1-only Tab activation for uGUICommandNear and uGUICommandFar.

This reversible Frida live test attaches only to the verified native function
entries used by the two partner-command controllers.  In active split-screen,
held VK_TAB extends a three-second deadline for player 0.  Near is allowed to
complete one native projection pass and its final clamp result is compared with
the current player viewport.  During the deadline bit 0x4000 is then retained
on P1 Near (inside the safe area) or P1 Far (at the viewport edge).  P2, XInput,
actor actions, SP, mouse, and device selection are untouched.  No instruction
inside either native function is hooked.

Commands on stdin: ``snapshot`` and ``stop``.
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
    parser.add_argument("--controller", type=number, required=True)
    parser.add_argument("--far", type=number, required=True)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--linger-ms", type=int, default=3000)
    args = parser.parse_args()
    if not 250 <= args.linger_ms <= 10000:
        raise RuntimeError("linger-ms must be between 250 and 10000")

    javascript = r"""
const nearController = ptr("__CONTROLLER__");
const farController = ptr("__FAR__");
const nearProjection = ptr("0x008E36A0");
const farUpdate = ptr("0x008E29E0");
const nearVtable = ptr("0x0139ACA0");
const farVtable = ptr("0x0139AB40");
const modePointer = ptr("0x0157AE00");
const graphicsPointer = ptr("0x015DE88C");
const safeMarginPointer = ptr("0x014DD080");
const playerOffset = 0x2ac;
const stateOffset = 0x0c;
const commandVisible = 0x4000;
const lingerMs = __LINGER__;
const startedAt = Date.now();
let expiresAt = 0;
let previousTabDown = false;
let nearOnscreen = true;
let rawX = null;
let rawY = null;
const counters = {
    projectionCalls: 0,
    p1Calls: 0,
    activeSplitCalls: 0,
    tabDownCalls: 0,
    tabEdges: 0,
    nearWrites: 0,
    nearProbeFrames: 0,
    nearSuppressions: 0,
    farUpdateCalls: 0,
    farWrites: 0,
    nearFrames: 0,
    farFrames: 0,
    validationFailures: 0
};

function readU32(address) {
    try { return address.readU32(); } catch (_) { return null; }
}

function activeSplit() {
    const mode = ptr(readU32(modePointer) || 0);
    if (mode.isNull()) return false;
    return readU32(mode.add(0x8f0)) === 1 && readU32(mode.add(0x8f4)) === 1;
}

function validController(controller, vtable) {
    try {
        return controller.readPointer().equals(vtable)
            && controller.add(playerOffset).readU32() === 0;
    } catch (_) {
        return false;
    }
}

function readI32(address) {
    try { return address.readS32(); } catch (_) { return null; }
}

function readF32(address) {
    try { return address.readFloat(); } catch (_) { return null; }
}

function refreshOnscreenFromFinalPosition() {
    const x = readF32(nearController.add(0x40));
    const y = readF32(nearController.add(0x44));
    const graphics = ptr(readU32(graphicsPointer) || 0);
    if (graphics.isNull()) return false;
    const left = readI32(graphics.add(0x48));
    const top = readI32(graphics.add(0x4c));
    const right = readI32(graphics.add(0x50));
    const bottom = readI32(graphics.add(0x54));
    const margin = readF32(safeMarginPointer);
    if ([x, y, left, top, right, bottom, margin].some(value => value === null))
        return false;
    if (!(right > left && bottom > top))
        return false;
    rawX = x;
    rawY = y;
    const epsilon = 0.5;
    nearOnscreen = x > left + margin + epsilon
        && x < right - margin - epsilon
        && y > top + margin + epsilon
        && y < bottom - margin - epsilon;
    return true;
}

function makeVisible(controller, counterName) {
    const stateAddress = controller.add(stateOffset);
    const state = readU32(stateAddress);
    if (state === null) return;
    if ((state & commandVisible) === 0) {
        stateAddress.writeU32((state | commandVisible) >>> 0);
        counters[counterName]++;
    }
}

function suppressNear() {
    const stateAddress = nearController.add(stateOffset);
    const state = readU32(stateAddress);
    if (state === null || (state & commandVisible) === 0) return;
    stateAddress.writeU32((state & ~commandVisible) >>> 0);
    counters.nearSuppressions++;
}

let getAsyncKeyState = null;
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase() !== "user32.dll") continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type === "function" && exported.name === "GetAsyncKeyState") {
            getAsyncKeyState = new NativeFunction(exported.address, "int16", ["int"]);
            break;
        }
    }
}
if (getAsyncKeyState === null)
    throw new Error("USER32!GetAsyncKeyState was not found");
if (!validController(nearController, nearVtable))
    throw new Error("Selected Near controller is not player-0 uGUICommandNear");
if (!validController(farController, farVtable))
    throw new Error("Selected Far controller is not player-0 uGUICommandFar");

Interceptor.attach(nearProjection, {
    onEnter() {
        this.probe = false;
        counters.projectionCalls++;
        if (!this.context.ecx.equals(nearController)) return;
        counters.p1Calls++;
        if (!validController(nearController, nearVtable) ||
            !validController(farController, farVtable)) {
            counters.validationFailures++;
            return;
        }
        if (!activeSplit()) {
            previousTabDown = false;
            expiresAt = 0;
            return;
        }
        counters.activeSplitCalls++;

        const tabDown = (getAsyncKeyState(0x09) & 0x8000) !== 0;
        if (tabDown) {
            counters.tabDownCalls++;
            expiresAt = Date.now() + lingerMs;
        }
        if (tabDown && !previousTabDown)
            counters.tabEdges++;
        previousTabDown = tabDown;

        if (Date.now() >= expiresAt) return;
        // Even while the partner was off screen last frame, allow Near to run
        // its complete projection so onLeave can detect a return.  onLeave
        // removes this bit again before draw if the final clamped position is
        // still at the edge of the owning viewport.
        counters.nearProbeFrames++;
        makeVisible(nearController, "nearWrites");
        this.probe = true;
    },
    onLeave() {
        if (!this.probe) return;
        if (!refreshOnscreenFromFinalPosition()) {
            counters.validationFailures++;
            return;
        }
        if (nearOnscreen)
            counters.nearFrames++;
        else
            suppressNear();
    }
});

Interceptor.attach(farUpdate, {
    onEnter() {
        this.p1 = this.context.ecx.equals(farController);
        if (this.p1) counters.farUpdateCalls++;
    },
    onLeave() {
        if (!this.p1 || Date.now() >= expiresAt || nearOnscreen || !activeSplit())
            return;
        if (!validController(farController, farVtable)) {
            counters.validationFailures++;
            return;
        }
        counters.farFrames++;
        makeVisible(farController, "farWrites");
    }
});

function snapshot(event) {
    return {
        event: event,
        elapsedMs: Date.now() - startedAt,
        nearController: nearController.toString(),
        farController: farController.toString(),
        player: readU32(nearController.add(playerOffset)),
        nearState: readU32(nearController.add(stateOffset)),
        farState: readU32(farController.add(stateOffset)),
        nearOnscreen: nearOnscreen,
        rawPosition: [rawX, rawY],
        viewport: [
            readI32(ptr(readU32(graphicsPointer) || 0).add(0x48)),
            readI32(ptr(readU32(graphicsPointer) || 0).add(0x4c)),
            readI32(ptr(readU32(graphicsPointer) || 0).add(0x50)),
            readI32(ptr(readU32(graphicsPointer) || 0).add(0x54))
        ],
        expiresInMs: Math.max(0, expiresAt - Date.now()),
        previousTabDown: previousTabDown,
        counters: counters
    };
}

rpc.exports = {
    snapshot() { return snapshot("snapshot"); },
    stop() { return snapshot("stop"); }
};

send(snapshot("ready"));
"""
    javascript = (
        javascript.replace("__CONTROLLER__", hex(args.controller))
        .replace("__FAR__", hex(args.far))
        .replace("__LINGER__", str(args.linger_ms))
    )

    stop = threading.Event()
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        if message.get("type") == "send":
            print(json.dumps(message.get("payload", {})), flush=True)
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                stop.set()

    script.on("message", on_message)
    script.load()

    def watchdog() -> None:
        if not stop.wait(args.timeout):
            try:
                print(json.dumps(script.exports_sync.stop()), flush=True)
            except frida.InvalidOperationError:
                pass
            stop.set()

    threading.Thread(target=watchdog, daemon=True).start()
    try:
        for line in sys.stdin:
            command = line.strip().lower()
            if command == "snapshot":
                print(json.dumps(script.exports_sync.snapshot()), flush=True)
            elif command == "stop":
                print(json.dumps(script.exports_sync.stop()), flush=True)
                break
        stop.set()
    finally:
        try:
            script.unload()
        except frida.InvalidOperationError:
            pass
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
