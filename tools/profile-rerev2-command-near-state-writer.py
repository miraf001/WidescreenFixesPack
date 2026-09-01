"""Trace the native writer of one uGUICommandNear state word around XInput Y.

This is read-only Frida instrumentation.  It follows only the GUI thread that
updates the selected CommandNear controller and inserts Stalker callouts only
for game instructions whose destination is a memory operand at displacement
+0x0c.  Events are retained only when the effective destination is the selected
controller's state word.  No game or controller memory is modified.
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
    parser.add_argument(
        "--trigger",
        type=number,
        help="CommandNear update entry; defaults to controller vtable slot +0x24",
    )
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    javascript = r"""
const durationMs = __DURATION__;
const controller = ptr("__CONTROLLER__");
const targetState = controller.add(0x0c);
const targetStateEnd = targetState.add(4);
const expectedVtable = ptr("0x0139ACA0");
const game = Process.getModuleByName("rerev2.exe");
const gameEnd = game.base.add(game.size);
const targetInputCaller = "rerev2.exe+0x814b06";
const requestedTrigger = __TRIGGER__;
const startedAt = Date.now();
const events = [];
let trigger = NULL;
let followedThread = 0;
let yDown = false;
let yEdges = 0;
let stalkerStarted = false;
let finished = false;

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null) return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function inGame(address) {
    return address.compare(game.base) >= 0 && address.compare(gameEnd) < 0;
}

function registerValue(context, name) {
    if (name === null || name === undefined || name === "") return 0;
    const value = context[name];
    if (value === undefined) return 0;
    return value.toUInt32();
}

function effectiveAddress(context, memory) {
    let value = memory.disp | 0;
    value = (value + registerValue(context, memory.base)) >>> 0;
    if (memory.index !== null && memory.index !== undefined && memory.index !== "") {
        value = (value + Math.imul(registerValue(context, memory.index), memory.scale || 1)) >>> 0;
    }
    return ptr(value);
}

const destinationWriters = new Set([
    "adc", "add", "and", "btr", "bts", "cmpxchg", "dec", "inc", "mov",
    "movnti", "movss", "movups", "not", "or", "rol", "ror", "sal", "sar",
    "sbb", "shl", "shr", "sub", "xadd", "xchg", "xor"
]);

function startStalker(threadId) {
    if (stalkerStarted) return;
    stalkerStarted = true;
    followedThread = threadId;
    Stalker.follow(threadId, {
        events: { call: false, ret: false, exec: false, block: false, compile: false },
        transform(iterator) {
            let instruction;
            while ((instruction = iterator.next()) !== null) {
                let instrument = false;
                let memory = null;
                if (inGame(instruction.address) && destinationWriters.has(instruction.mnemonic)) {
                    const operands = instruction.operands;
                    if (operands.length > 0 && operands[0].type === "mem") {
                        memory = operands[0].value;
                        const displacement = memory.disp | 0;
                        instrument = displacement >= 0x0c && displacement <= 0x0f;
                    }
                }
                if (instrument) {
                    const address = instruction.address;
                    const mnemonic = instruction.mnemonic;
                    const opStr = instruction.opStr;
                    const memorySpec = {
                        base: memory.base,
                        index: memory.index,
                        scale: memory.scale,
                        disp: memory.disp
                    };
                    iterator.putCallout(function (context) {
                        let destination;
                        try { destination = effectiveAddress(context, memorySpec); }
                        catch (_) { return; }
                        if (destination.compare(targetState) < 0 || destination.compare(targetStateEnd) >= 0)
                            return;
                        let before = null;
                        try { before = targetState.readU32(); } catch (_) {}
                        events.push({
                            atMs: Date.now() - startedAt,
                            instruction: address.toString(),
                            source: describe(address),
                            mnemonic: mnemonic,
                            opStr: opStr,
                            destination: destination.toString(),
                            stateByteOffset: destination.sub(targetState).toInt32(),
                            before: before,
                            yDown: yDown,
                            yEdges: yEdges,
                            threadId: Process.getCurrentThreadId(),
                            registers: {
                                eax: context.eax.toUInt32(),
                                ebx: context.ebx.toUInt32(),
                                ecx: context.ecx.toUInt32(),
                                edx: context.edx.toUInt32(),
                                esi: context.esi.toUInt32(),
                                edi: context.edi.toUInt32()
                            }
                        });
                        if (events.length > 512) events.shift();
                    });
                }
                iterator.keep();
            }
        }
    });
}

function stopStalker() {
    if (!stalkerStarted) return;
    try { Stalker.unfollow(followedThread); } catch (_) {}
    try { Stalker.flush(); } catch (_) {}
    try { Stalker.garbageCollect(); } catch (_) {}
}

function complete() {
    if (finished) return;
    finished = true;
    stopStalker();
    let finalState = null;
    try { finalState = targetState.readU32(); } catch (_) {}
    send({
        event: "summary",
        trigger: trigger.toString(),
        controller: controller.toString(),
        targetState: targetState.toString(),
        finalState: finalState,
        yEdges: yEdges,
        followedThread: followedThread,
        events: events
    });
}

if (!controller.readPointer().equals(expectedVtable))
    throw new Error("The selected controller is not a native uGUICommandNear object");
trigger = requestedTrigger === null
    ? controller.readPointer().add(0x24).readPointer()
    : ptr(requestedTrigger);

Interceptor.attach(trigger, {
    onEnter() {
        if (!this.context.ecx.equals(controller)) return;
        startStalker(Process.getCurrentThreadId());
    }
});

const xinputHooks = [];
const seen = new Set();
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase().indexOf("xinput") === -1) continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type !== "function" || exported.name.indexOf("XInputGetState") === -1)
            continue;
        const key = exported.address.toString();
        if (seen.has(key)) continue;
        seen.add(key);
        xinputHooks.push({ module: module.name, address: key });
        Interceptor.attach(exported.address, {
            onEnter(args) {
                this.index = args[0].toUInt32();
                this.state = args[1];
                this.caller = describe(this.returnAddress);
            },
            onLeave(retval) {
                if (retval.toUInt32() !== 0 || this.state.isNull()) return;
                if (this.index !== 0 || this.caller !== targetInputCaller) return;
                let buttons;
                try { buttons = this.state.add(4).readU16(); } catch (_) { return; }
                const current = (buttons & 0x8000) !== 0;
                if (current !== yDown) yEdges++;
                yDown = current;
            }
        });
    }
}

setTimeout(complete, durationMs);
send({
    event: "ready",
    trigger: trigger.toString(),
    controller: controller.toString(),
    targetState: targetState.toString(),
    initialState: targetState.readU32(),
    xinputHooks: xinputHooks
});
"""
    trigger_js = "null" if args.trigger is None else json.dumps(hex(args.trigger))
    javascript = (
        javascript.replace("__DURATION__", str(max(1, round(args.seconds * 1000))))
        .replace("__CONTROLLER__", hex(args.controller))
        .replace("__TRIGGER__", trigger_js)
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
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                print(
                    json.dumps(
                        {
                            "event": "summary",
                            "yEdges": payload.get("yEdges"),
                            "events": len(payload.get("events", [])),
                            "output": str(args.output),
                        }
                    ),
                    flush=True,
                )
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
