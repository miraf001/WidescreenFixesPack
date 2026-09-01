"""Reversible Tab alias for RE:Rev2's native partner-command GUI trigger.

Read-only raw-Y snapshots established that activation adds state bit 0x4000 to
the assigned player's uGUICommandNear flags at +0x0c.  CommandNear's native
update requires this bit together with its existing 0x0800 state; CommandFar
is linked from Near and did not receive this change.  This live diagnostic
reproduces only that observed state transition for VK_TAB in active
split-screen.  XInput, active-device selection, actor state, SP keyboard
handling, P2, and mouse input remain untouched.

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


JAVASCRIPT_TEMPLATE = r"""
const heartbeat = ptr("0x00A16F90");
const modePointer = ptr("0x0157AE00");
const actorManagerPointer = ptr("0x01567EAC");
const commandNear = ptr("__NEAR__");
const commandFar = ptr("__FAR__");
const commandNearVtable = 0x0139aca0;
const commandFarVtable = 0x0139ab40;
const playerOffset = 0x2ac;
const stateOffset = 0x0c;
const commandActiveBit = 0x4000;
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

function validateController(controller, vtable) {
    return readU32(controller) === vtable &&
        readU32(controller.add(playerOffset)) === 0;
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

const expected = [0x53, 0x57, 0x8b, 0x7c, 0x24, 0x0c, 0x8b, 0xd9];
const actual = new Uint8Array(heartbeat.readByteArray(expected.length));
for (let i = 0; i < expected.length; i++) {
    if (actual[i] !== expected[i])
        throw new Error("sub_A16F90 entry bytes do not match the supported build");
}
if (!validateController(commandNear, commandNearVtable))
    throw new Error("The selected P1 CommandNear controller is invalid");
if (!validateController(commandFar, commandFarVtable))
    throw new Error("The selected P1 CommandFar controller is invalid");

const counters = {
    heartbeatCalls: 0,
    splitScreenCalls: 0,
    primaryActorCalls: 0,
    tabDownCalls: 0,
    tabEdges: 0,
    stateWrites: 0,
    controllerValidationFailures: 0
};

Interceptor.attach(heartbeat, {
    onEnter(args) {
        counters.heartbeatCalls++;
        const mode = activeMode();
        if (mode === null) {
            previousTabDown = false;
            return;
        }
        counters.splitScreenCalls++;
        if (!args[0].equals(primaryActor(mode))) return;
        counters.primaryActorCalls++;

        const tabDown = (getAsyncKeyState(vkTab) & 0x8000) !== 0;
        if (tabDown) counters.tabDownCalls++;
        const tabEdge = tabDown && !previousTabDown;
        previousTabDown = tabDown;
        if (!tabEdge) return;
        counters.tabEdges++;

        if (!validateController(commandNear, commandNearVtable) ||
            !validateController(commandFar, commandFarVtable)) {
            counters.controllerValidationFailures++;
            return;
        }
        const state = commandNear.add(stateOffset).readU32();
        commandNear.add(stateOffset).writeU32(state | commandActiveBit);
        counters.stateWrites++;
    }
});

rpc.exports = {
    snapshot() {
        return {
            elapsedMs: Date.now() - started,
            heartbeat: heartbeat.toString(),
            commandNear: commandNear.toString(),
            commandFar: commandFar.toString(),
            nearState: commandNear.add(stateOffset).readU32(),
            farState: commandFar.add(stateOffset).readU32(),
            previousTabDown: previousTabDown,
            counters: counters
        };
    }
};
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--near", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--far", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args()

    javascript = (
        JAVASCRIPT_TEMPLATE.replace("__NEAR__", hex(args.near)).replace(
            "__FAR__", hex(args.far)
        )
    )
    session = frida.get_local_device().attach(args.pid)
    script = session.create_script(javascript)
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
