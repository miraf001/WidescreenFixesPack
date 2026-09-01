"""Interactively compare the co-op partner-command gamepad and keyboard paths.

The tracer installs temporary Frida interceptors but never changes game data,
controller assignments, input state, or executable behavior.  Commands on
stdin select a named phase, print a grouped snapshot, or stop the trace:

    phase gamepad
    phase keyboard
    snapshot
    stop
"""

from __future__ import annotations

import argparse
import json
import sys
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


KEYBOARD_QUERY = 0x0099E1E0
ACTION_HELPER = 0x00A14E10
EVENT_DISPATCH = 0x00AD78E0


def number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=number, required=True)
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args()

    javascript = r"""
const keyboardQuery = ptr("0x0099E1E0");
const actionHelper = ptr("0x00A14E10");
const eventDispatch = ptr("0x00AD78E0");
let phase = "idle";
const started = Date.now();
const phases = new Map();
const previousButtons = new Map();

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function phaseData(name) {
    let result = phases.get(name);
    if (result === undefined) {
        result = {
            name: name,
            selectedAtMs: Date.now() - started,
            xinputEdges: [],
            keyboardTrue: new Map(),
            actionHelperTrue: new Map(),
            dispatchedEvents: new Map()
        };
        phases.set(name, result);
    }
    return result;
}

function increment(map, key, sample) {
    let row = map.get(key);
    if (row === undefined) {
        row = Object.assign({ count: 0 }, sample);
        map.set(key, row);
    }
    row.count++;
}

function pointerString(value) {
    try { return value.toString(); } catch (_) { return null; }
}

Interceptor.attach(keyboardQuery, {
    onEnter(args) {
        this.phase = phase;
        this.a0 = args[0].toUInt32();
        this.a1 = args[1].toUInt32();
        this.a2 = args[2].toUInt32();
        this.object = pointerString(this.context.ecx);
        this.caller = describe(this.returnAddress);
    },
    onLeave(retval) {
        if ((retval.toUInt32() & 0xff) === 0)
            return;
        const data = phaseData(this.phase);
        const key = this.caller + "|" + this.a0 + "|" + this.a1 + "|" + this.a2;
        increment(data.keyboardTrue, key, {
            caller: this.caller,
            args: [this.a0, this.a1, this.a2],
            keyboard: this.object
        });
    }
});

Interceptor.attach(actionHelper, {
    onEnter(args) {
        this.phase = phase;
        this.contextObject = pointerString(this.context.ecx);
        this.actor = pointerString(args[0]);
        this.mask = args[1].toUInt32();
        this.caller = describe(this.returnAddress);
    },
    onLeave(retval) {
        if ((retval.toUInt32() & 0xff) === 0)
            return;
        const data = phaseData(this.phase);
        const key = this.caller + "|" + this.actor + "|" + this.mask;
        increment(data.actionHelperTrue, key, {
            caller: this.caller,
            context: this.contextObject,
            actor: this.actor,
            mask: "0x" + this.mask.toString(16)
        });
    }
});

Interceptor.attach(eventDispatch, {
    onEnter(args) {
        const event = args[0].toUInt32();
        const caller = describe(this.returnAddress);
        const object = pointerString(this.context.ecx);
        const data = phaseData(phase);
        increment(data.dispatchedEvents, caller + "|" + event, {
            caller: caller,
            event: "0x" + event.toString(16),
            object: object
        });
    }
});

const hookedXInput = [];
const hookedAddresses = new Set();
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase().indexOf("xinput") === -1)
        continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type !== "function" || exported.name.indexOf("XInputGetState") === -1)
            continue;
        const addressKey = exported.address.toString();
        if (hookedAddresses.has(addressKey))
            continue;
        hookedAddresses.add(addressKey);
        const source = module.name + "!" + exported.name;
        hookedXInput.push({ source: source, address: addressKey });
        Interceptor.attach(exported.address, {
            onEnter(args) {
                this.index = args[0].toUInt32();
                this.state = args[1];
                this.source = source;
                this.phase = phase;
            },
            onLeave(retval) {
                if (retval.toUInt32() !== 0 || this.state.isNull())
                    return;
                let buttons;
                let packet;
                try {
                    packet = this.state.readU32();
                    buttons = this.state.add(4).readU16();
                } catch (_) {
                    return;
                }
                const key = this.source + "|" + this.index;
                const previous = previousButtons.get(key);
                previousButtons.set(key, buttons);
                if (previous === undefined || previous === buttons)
                    return;
                phaseData(this.phase).xinputEdges.push({
                    atMs: Date.now() - started,
                    source: this.source,
                    index: this.index,
                    packet: packet,
                    previous: "0x" + previous.toString(16).padStart(4, "0"),
                    buttons: "0x" + buttons.toString(16).padStart(4, "0"),
                    changed: "0x" + (previous ^ buttons).toString(16).padStart(4, "0")
                });
            }
        });
    }
}

function rows(map) {
    return Array.from(map.values()).sort(function (left, right) {
        return right.count - left.count;
    });
}

function summary() {
    return {
        event: "snapshot",
        currentPhase: phase,
        elapsedMs: Date.now() - started,
        xinputHooks: hookedXInput,
        phases: Array.from(phases.values()).map(function (data) {
            return {
                name: data.name,
                selectedAtMs: data.selectedAtMs,
                xinputEdges: data.xinputEdges,
                keyboardTrue: rows(data.keyboardTrue),
                actionHelperTrue: rows(data.actionHelperTrue),
                dispatchedEvents: rows(data.dispatchedEvents)
            };
        })
    };
}

function receiveCommand() {
    recv("command", function (message) {
        const command = message.payload || {};
        if (command.action === "phase") {
            phase = String(command.name || "unnamed");
            phaseData(phase);
            send({ event: "phase", name: phase, atMs: Date.now() - started });
        } else if (command.action === "snapshot") {
            send(summary());
        }
        receiveCommand();
    });
}

phaseData(phase);
receiveCommand();
send({
    event: "ready",
    hooks: {
        keyboardQuery: keyboardQuery.toString(),
        actionHelper: actionHelper.toString(),
        eventDispatch: eventDispatch.toString(),
        xinput: hookedXInput
    }
});
"""

    stopped = threading.Event()
    snapshot_received = threading.Event()
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            event = payload.get("event")
            if event == "ready":
                print("READY " + json.dumps(payload["hooks"], sort_keys=True), flush=True)
            elif event == "phase":
                print(
                    f"PHASE name={payload['name']} atMs={payload['atMs']}",
                    flush=True,
                )
            elif event == "snapshot":
                print("SNAPSHOT", flush=True)
                print(json.dumps(payload, indent=2), flush=True)
                snapshot_received.set()
            else:
                print(json.dumps(payload), flush=True)
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                stopped.set()

    def on_detached(*details) -> None:
        print(f"DETACHED {details}", flush=True)
        stopped.set()

    script.on("message", on_message)
    session.on("detached", on_detached)
    script.load()

    deadline = time.monotonic() + args.timeout
    try:
        while not stopped.is_set() and time.monotonic() < deadline:
            line = sys.stdin.readline()
            if not line:
                break
            fields = line.strip().split(maxsplit=1)
            if not fields:
                continue
            command = fields[0].lower()
            if command == "phase" and len(fields) == 2:
                script.post(
                    {"type": "command", "payload": {"action": "phase", "name": fields[1]}}
                )
            elif command == "snapshot":
                snapshot_received.clear()
                script.post({"type": "command", "payload": {"action": "snapshot"}})
                snapshot_received.wait(3.0)
            elif command == "stop":
                snapshot_received.clear()
                script.post({"type": "command", "payload": {"action": "snapshot"}})
                snapshot_received.wait(3.0)
                break
            else:
                print("COMMANDS: phase <name> | snapshot | stop", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
