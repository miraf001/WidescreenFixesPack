"""Compare idle and Y-down GUI-thread frames for P1 CommandNear.

The current live CommandNear wrapper is used only as a frame boundary.  Frida
Stalker follows that GUI thread from one P1 update entry to the next and records
game-module call/basic-block coverage for one idle frame and one Y-down frame.
No process state is modified.
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
    parser.add_argument("--trigger", type=number, required=True)
    parser.add_argument("--controller", type=number, required=True)
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    javascript = r"""
const durationMs = __DURATION__;
const trigger = ptr("__TRIGGER__");
const trackedController = ptr("__CONTROLLER__");
const targetInputCaller = "rerev2.exe+0x814b06";
const game = Process.getModuleByName("rerev2.exe");
const gameEnd = game.base.add(game.size);
const captures = [];
let active = null;
let yDown = false;
let idleStarted = false;
let yStarted = false;

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null) return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function inGame(address) {
    return address.compare(game.base) >= 0 && address.compare(gameEnd) < 0;
}

function increment(map, key) { map.set(key, (map.get(key) || 0) + 1); }

function startCapture(name, threadId) {
    if (active !== null) return;
    const capture = { name: name, threadId: threadId, calls: new Map(), blocks: new Map(), rawEvents: 0 };
    active = capture;
    Stalker.follow(threadId, {
        events: { call: true, ret: false, exec: false, block: true, compile: false },
        onReceive(raw) {
            let events;
            try { events = Stalker.parse(raw, { annotate: true, stringify: true }); }
            catch (_) { return; }
            capture.rawEvents += events.length;
            for (const event of events) {
                if (event[0] === "call") {
                    const from = ptr(event[1]);
                    const to = ptr(event[2]);
                    if (inGame(from) || inGame(to)) increment(capture.calls, describe(from) + "->" + describe(to));
                } else if (event[0] === "block") {
                    const begin = ptr(event[1]);
                    if (inGame(begin)) increment(capture.blocks, describe(begin));
                }
            }
        }
    });
}

function stopCapture(threadId) {
    if (active === null || active.threadId !== threadId) return;
    Stalker.unfollow(threadId);
    Stalker.flush();
    const capture = active;
    active = null;
    setTimeout(function () { Stalker.garbageCollect(); }, 20);
    captures.push(capture);
}

Interceptor.attach(trigger, {
    onEnter() {
        this.tracked = this.context.ecx.equals(trackedController);
        if (!this.tracked) return;
        this.captureThread = Process.getCurrentThreadId();
        stopCapture(this.captureThread);
        if (!idleStarted && !yDown) {
            idleStarted = true;
            startCapture("idle-gui", this.captureThread);
        } else if (!yStarted && yDown) {
            yStarted = true;
            startCapture("y-down-gui", this.captureThread);
        }
    }
});

const xinputHooks = [];
const seen = new Set();
for (const module of Process.enumerateModules()) {
    if (module.name.toLowerCase().indexOf("xinput") === -1) continue;
    for (const exported of module.enumerateExports()) {
        if (exported.type !== "function" || exported.name.indexOf("XInputGetState") === -1) continue;
        const key = exported.address.toString();
        if (seen.has(key)) continue;
        seen.add(key);
        xinputHooks.push(key);
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
                yDown = (buttons & 0x8000) !== 0;
            }
        });
    }
}

function publicCapture(capture) {
    return {
        name: capture.name,
        threadId: capture.threadId,
        rawEvents: capture.rawEvents,
        calls: Array.from(capture.calls.entries()).map(value => ({ path: value[0], count: value[1] })),
        blocks: Array.from(capture.blocks.entries()).map(value => ({ address: value[0], count: value[1] }))
    };
}

setTimeout(function () {
    if (active !== null) stopCapture(active.threadId);
    setTimeout(function () {
        send({ event: "summary", xinputHooks: xinputHooks, captures: captures.map(publicCapture) });
    }, 100);
}, durationMs);
send({ event: "ready", trigger: trigger.toString(), controller: trackedController.toString() });
"""
    javascript = (
        javascript.replace("__DURATION__", str(max(1, round(args.seconds * 1000))))
        .replace("__TRIGGER__", hex(args.trigger))
        .replace("__CONTROLLER__", hex(args.controller))
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
                print(json.dumps({"event": "summary", "captures": [{"name": row.get("name"), "calls": len(row.get("calls", [])), "blocks": len(row.get("blocks", [])), "rawEvents": row.get("rawEvents")} for row in payload.get("captures", [])], "output": str(args.output)}), flush=True)
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
