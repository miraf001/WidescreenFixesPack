"""Reversible downstream Tab alias for RE:Rev2's native MP command action.

This single-site diagnostic runs at sub_A16F90+0x16c, where the keyboard and
controller branches share their boolean action result.  A VK_TAB rising edge
for the assigned P1 actor changes only that result to true.  Capcom's MP/SP,
actor-state, eligibility, and partner-command checks then run unchanged.
XInput and the active device are never modified.

The Frida hook exists only while this process is running.  Commands on stdin:

    snapshot
    stop
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


JAVASCRIPT = r"""
const site = ptr("0x00A170FC");
const modePointer = ptr("0x0157AE00");
const actorManagerPointer = ptr("0x01567EAC");
const vkTab = 0x09;
const started = Date.now();
let previousTabDown = false;

function readU32(address) {
    try { return address.readU32(); } catch (_) { return 0; }
}

function activeMode() {
    const mode = ptr(readU32(modePointer));
    if (mode.isNull()) return null;
    if (readU32(mode.add(0x8f0)) !== 1 || readU32(mode.add(0x8f4)) !== 1)
        return null;
    return mode;
}

function primaryActor(mode) {
    const assignment = readU32(mode.add(0x8f8));
    if (assignment >= 8) return ptr(0);
    const manager = ptr(readU32(actorManagerPointer));
    if (manager.isNull()) return ptr(0);
    return ptr(readU32(manager.add(0x20 + assignment * 4)));
}

let getAsyncKeyStateAddress = null;
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase() !== "user32.dll") continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type === "function" && exported.name === "GetAsyncKeyState") {
            getAsyncKeyStateAddress = exported.address;
            break;
        }
    }
}
if (getAsyncKeyStateAddress === null)
    throw new Error("USER32!GetAsyncKeyState was not found");
const getAsyncKeyState = new NativeFunction(
    getAsyncKeyStateAddress, "int16", ["int"], { exceptions: "steal" }
);

const expected = [0x84, 0xc0, 0x0f, 0x84, 0x83, 0x00, 0x00, 0x00];
const actual = new Uint8Array(site.readByteArray(expected.length));
for (let i = 0; i < expected.length; i++) {
    if (actual[i] !== expected[i])
        throw new Error("sub_A16F90 downstream bytes do not match the supported build");
}

const counters = {
    siteCalls: 0,
    splitScreenCalls: 0,
    primaryActorCalls: 0,
    nativeTrueResults: 0,
    tabDownCalls: 0,
    tabEdges: 0,
    forcedTrueEdges: 0
};

Interceptor.attach(site, {
    onEnter() {
        counters.siteCalls++;
        const mode = activeMode();
        if (mode === null) {
            previousTabDown = false;
            return;
        }
        counters.splitScreenCalls++;
        const actor = this.context.edi;
        if (!actor.equals(primaryActor(mode))) return;
        counters.primaryActorCalls++;

        if ((this.context.eax.toUInt32() & 0xff) !== 0)
            counters.nativeTrueResults++;

        const tabDown = (getAsyncKeyState(vkTab) & 0x8000) !== 0;
        if (tabDown) counters.tabDownCalls++;
        const tabEdge = tabDown && !previousTabDown;
        previousTabDown = tabDown;
        if (!tabEdge) return;
        counters.tabEdges++;

        // Force only the shared boolean action result.  The original TEST AL,AL
        // and every following native branch/check still execute normally.
        this.context.eax = ptr((this.context.eax.toUInt32() & 0xffffff00) | 1);
        counters.forcedTrueEdges++;
    }
});

rpc.exports = {
    snapshot() {
        return {
            elapsedMs: Date.now() - started,
            site: site.toString(),
            getAsyncKeyState: getAsyncKeyStateAddress.toString(),
            previousTabDown: previousTabDown,
            counters: counters
        };
    }
};
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args()

    session = frida.get_local_device().attach(args.pid)
    script = session.create_script(JAVASCRIPT)
    script.load()
    stopped = threading.Event()

    def on_detached(*details) -> None:
        print(json.dumps({"event": "detached", "details": details}), flush=True)
        stopped.set()

    session.on("detached", on_detached)
    print(
        json.dumps(
            {"event": "ready", "pid": args.pid, "data": script.exports_sync.snapshot()}
        ),
        flush=True,
    )

    def watchdog() -> None:
        if not stopped.wait(args.timeout):
            try:
                snapshot = script.exports_sync.snapshot()
            except frida.InvalidOperationError:
                snapshot = None
            print(json.dumps({"event": "timeout", "data": snapshot}), flush=True)
            stopped.set()

    threading.Thread(target=watchdog, daemon=True).start()
    try:
        while not stopped.is_set():
            line = sys.stdin.readline()
            if not line:
                break
            command = line.strip().lower()
            if command == "snapshot":
                print(
                    json.dumps(
                        {"event": "snapshot", "data": script.exports_sync.snapshot()}
                    ),
                    flush=True,
                )
            elif command == "stop":
                print(
                    json.dumps(
                        {"event": "stop", "data": script.exports_sync.snapshot()}
                    ),
                    flush=True,
                )
                break
            elif command:
                print(json.dumps({"event": "error", "command": command}), flush=True)
    finally:
        stopped.set()
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
