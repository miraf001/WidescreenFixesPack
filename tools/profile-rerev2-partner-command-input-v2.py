"""Compact edge tracer for the RE:Rev2 partner-command input paths.

Unlike the first diagnostic pass, this tracer counts false-to-true edges per
keyboard query callsite and XInput caller.  A held input therefore counts once,
not once per rendered frame.  It also profiles sub_A18690's native input mask
and result bytes so the raw button can be tied to the downstream game action.

Interactive stdin commands:

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


def number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=number, required=True)
    parser.add_argument("--timeout", type=float, default=900.0)
    args = parser.parse_args()

    javascript = r"""
const keyboardQuery = ptr("0x0099E1E0");
const gameplayInput = ptr("0x00A18690");
const partnerEligibility = ptr("0x00701770");
let phase = "baseline";
const started = Date.now();
const phases = new Map();

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function readU8(address) {
    try { return address.readU8(); } catch (_) { return null; }
}

function actorId(actor) {
    if (actor.isNull())
        return null;
    return readU8(actor.add(0x790c));
}

function freshPhase(name) {
    return {
        name: name,
        selectedAtMs: Date.now() - started,
        keyboardRows: new Map(),
        keyboardStates: new Map(),
        xinputRows: new Map(),
        xinputStates: new Map(),
        gameplayRows: new Map(),
        gameplayStates: new Map(),
        eligibilityRows: new Map()
    };
}

function phaseData(name) {
    let result = phases.get(name);
    if (result === undefined) {
        result = freshPhase(name);
        phases.set(name, result);
    }
    return result;
}

function mapRow(map, key, sample) {
    let row = map.get(key);
    if (row === undefined) {
        row = Object.assign({ calls: 0 }, sample);
        map.set(key, row);
    }
    return row;
}

function bitCounter(row, field, bits, width) {
    if (bits === 0)
        return;
    if (row[field] === undefined)
        row[field] = {};
    for (let bit = 0; bit < width; bit++) {
        const mask = Math.pow(2, bit);
        if ((bits & mask) === 0)
            continue;
        const name = "0x" + mask.toString(16).padStart(width / 4, "0");
        row[field][name] = (row[field][name] || 0) + 1;
    }
}

Interceptor.attach(keyboardQuery, {
    onEnter(args) {
        this.phase = phase;
        this.caller = describe(this.returnAddress);
        this.thread = Process.getCurrentThreadId();
        this.values = [args[0].toUInt32(), args[1].toUInt32(), args[2].toUInt32()];
    },
    onLeave(retval) {
        const data = phaseData(this.phase);
        const key = this.caller + "|" + this.thread + "|" + this.values.join(",");
        const row = mapRow(data.keyboardRows, key, {
            caller: this.caller,
            thread: this.thread,
            args: this.values,
            trueCalls: 0,
            risingEdges: 0,
            fallingEdges: 0
        });
        row.calls++;
        const current = (retval.toUInt32() & 0xff) !== 0;
        if (current)
            row.trueCalls++;
        const previous = data.keyboardStates.get(key);
        if (previous === false && current)
            row.risingEdges++;
        else if (previous === true && !current)
            row.fallingEdges++;
        data.keyboardStates.set(key, current);
    }
});

Interceptor.attach(gameplayInput, {
    onEnter(args) {
        this.phase = phase;
        this.output = this.context.ecx;
        this.actor = args[0];
        this.flags = args[1].toUInt32();
        this.actorId = actorId(this.actor);
        this.before = {};
        for (const offset of [0x11, 0x15, 0x1a, 0x20, 0x804])
            this.before[offset] = readU8(this.output.add(offset));
    },
    onLeave() {
        const data = phaseData(this.phase);
        const key = this.actor.toString() + "|" + this.output.toString();
        const row = mapRow(data.gameplayRows, key, {
            actor: this.actor.toString(),
            actorId: this.actorId,
            output: this.output.toString(),
            nonzeroInputCalls: 0,
            resultSets: {}
        });
        row.calls++;
        if (this.flags !== 0)
            row.nonzeroInputCalls++;
        const previous = data.gameplayStates.get(key);
        if (previous !== undefined)
            bitCounter(row, "inputRisingEdges", (~previous & this.flags) >>> 0, 32);
        data.gameplayStates.set(key, this.flags);
        for (const offset of [0x11, 0x15, 0x1a, 0x20, 0x804]) {
            const after = readU8(this.output.add(offset));
            if (this.before[offset] === 0 && after !== null && after !== 0) {
                const name = "0x" + offset.toString(16);
                row.resultSets[name] = (row.resultSets[name] || 0) + 1;
            }
        }
    }
});

Interceptor.attach(partnerEligibility, {
    onEnter() {
        this.phase = phase;
        this.actor = this.context.ecx;
        this.actorId = actorId(this.actor);
    },
    onLeave(retval) {
        const data = phaseData(this.phase);
        const key = this.actor.toString();
        const row = mapRow(data.eligibilityRows, key, {
            actor: this.actor.toString(),
            actorId: this.actorId,
            trueCalls: 0
        });
        row.calls++;
        if ((retval.toUInt32() & 0xff) !== 0)
            row.trueCalls++;
    }
});

const xinputHooks = [];
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
        xinputHooks.push({ source: source, address: addressKey });
        Interceptor.attach(exported.address, {
            onEnter(args) {
                this.phase = phase;
                this.index = args[0].toUInt32();
                this.state = args[1];
                this.source = source;
                this.caller = describe(this.returnAddress);
                this.thread = Process.getCurrentThreadId();
            },
            onLeave(retval) {
                if (retval.toUInt32() !== 0 || this.state.isNull())
                    return;
                let buttons;
                try { buttons = this.state.add(4).readU16(); } catch (_) { return; }
                const data = phaseData(this.phase);
                const key = this.source + "|" + this.caller + "|" + this.thread + "|" + this.index;
                const row = mapRow(data.xinputRows, key, {
                    source: this.source,
                    caller: this.caller,
                    thread: this.thread,
                    index: this.index
                });
                row.calls++;
                const previous = data.xinputStates.get(key);
                if (previous !== undefined) {
                    bitCounter(row, "risingEdges", (~previous & buttons) & 0xffff, 16);
                    bitCounter(row, "fallingEdges", (previous & ~buttons) & 0xffff, 16);
                }
                data.xinputStates.set(key, buttons);
            }
        });
    }
}

function usefulRows(map, edgeFields) {
    return Array.from(map.values()).filter(function (row) {
        if (edgeFields.length === 0)
            return row.calls > 0;
        return edgeFields.some(function (field) {
            if (typeof row[field] === "number")
                return row[field] > 0;
            return row[field] !== undefined && Object.keys(row[field]).length > 0;
        });
    }).sort(function (left, right) {
        return right.calls - left.calls;
    });
}

function summary() {
    return {
        event: "snapshot",
        currentPhase: phase,
        elapsedMs: Date.now() - started,
        xinputHooks: xinputHooks,
        phases: Array.from(phases.values()).map(function (data) {
            return {
                name: data.name,
                selectedAtMs: data.selectedAtMs,
                keyboard: usefulRows(data.keyboardRows, ["risingEdges", "fallingEdges"]),
                xinput: usefulRows(data.xinputRows, ["risingEdges", "fallingEdges"]),
                gameplay: usefulRows(data.gameplayRows, ["inputRisingEdges", "resultSets"]),
                partnerEligibility: usefulRows(data.eligibilityRows, [])
            };
        })
    };
}

function receiveCommand() {
    recv("command", function (message) {
        const command = message.payload || {};
        if (command.action === "phase") {
            phase = String(command.name || "unnamed");
            phases.set(phase, freshPhase(phase));
            send({ event: "phase", name: phase, atMs: Date.now() - started });
        } else if (command.action === "snapshot") {
            send(summary());
        }
        receiveCommand();
    });
}

phases.set(phase, freshPhase(phase));
receiveCommand();
send({ event: "ready", xinputHooks: xinputHooks });
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
                print("READY " + json.dumps(payload, sort_keys=True), flush=True)
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
            elif command in ("snapshot", "stop"):
                snapshot_received.clear()
                script.post({"type": "command", "payload": {"action": "snapshot"}})
                snapshot_received.wait(3.0)
                if command == "stop":
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
