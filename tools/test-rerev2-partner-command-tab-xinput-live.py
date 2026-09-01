"""Reversible live Tab -> XInput Y alias for RE:Rev2 local co-op.

The game already implements the partner marker correctly for controller Y.
This diagnostic changes only successful XInputGetState results for controller
index zero while active split-screen is confirmed: holding VK_TAB adds the
physical XINPUT_GAMEPAD_Y bit.  Single-player, mouse input, keyboard bindings,
and every other controller result remain untouched.

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
const modePointer = ptr("0x0157AE00");
const vkTab = 0x09;
const xinputGamepadY = 0x8000;
const targetIndex = 0;
const started = Date.now();

function readableU32(address) {
    try { return address.readU32(); } catch (_) { return 0; }
}

function activeSplitScreen() {
    const mode = ptr(readableU32(modePointer));
    if (mode.isNull()) return false;
    return readableU32(mode.add(0x8f0)) === 1 &&
        readableU32(mode.add(0x8f4)) === 1;
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

let xinputGetStateAddress = null;
let xinputSource = null;
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase() !== "xinput1_3.dll") continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type !== "function" ||
            exported.name.indexOf("XInputGetState") === -1) continue;
        xinputGetStateAddress = exported.address;
        xinputSource = module.name + "!" + exported.name;
        break;
    }
}
if (xinputGetStateAddress === null)
    throw new Error("XINPUT1_3!XInputGetState was not found");

const counters = {
    calls: 0,
    indexZeroCalls: 0,
    successfulIndexZeroCalls: 0,
    splitScreenCalls: 0,
    tabDownCalls: 0,
    injectedCalls: 0,
    nativeYCalls: 0
};

Interceptor.attach(xinputGetStateAddress, {
    onEnter(args) {
        counters.calls++;
        this.index = args[0].toUInt32();
        this.state = args[1];
        this.target = this.index === targetIndex && !this.state.isNull();
        if (this.target) counters.indexZeroCalls++;
    },
    onLeave(retval) {
        if (!this.target || retval.toUInt32() !== 0) return;
        counters.successfulIndexZeroCalls++;
        if (!activeSplitScreen()) return;
        counters.splitScreenCalls++;
        if ((getAsyncKeyState(vkTab) & 0x8000) === 0) return;
        counters.tabDownCalls++;
        try {
            const buttonsAddress = this.state.add(4);
            const buttons = buttonsAddress.readU16();
            if ((buttons & xinputGamepadY) !== 0) counters.nativeYCalls++;
            buttonsAddress.writeU16(buttons | xinputGamepadY);
            counters.injectedCalls++;
        } catch (_) {}
    }
});

rpc.exports = {
    snapshot() {
        return {
            elapsedMs: Date.now() - started,
            source: xinputSource,
            address: xinputGetStateAddress.toString(),
            getAsyncKeyState: getAsyncKeyStateAddress.toString(),
            targetIndex: targetIndex,
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
    ready = script.exports_sync.snapshot()
    print(json.dumps({"event": "ready", "pid": args.pid, "data": ready}), flush=True)

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
