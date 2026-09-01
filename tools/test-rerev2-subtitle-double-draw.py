"""Replay the active TextVoice transform once per render with the opposite X."""

from __future__ import annotations

import argparse
import json
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
    parser.add_argument("--function", type=number, required=True)
    parser.add_argument("--controller", type=number, required=True)
    parser.add_argument("--offset", type=number, required=True)
    parser.add_argument("--seconds", type=float, default=30.0)
    args = parser.parse_args()

    javascript = r"""
const target = ptr("%s");
const controller = ptr("%s");
const offset = ptr("%s");
const replay = new NativeFunction(
    target, "void", ["pointer", "pointer", "pointer"], "fastcall");
const recursiveThreads = new Set();
let originalCalls = 0;
let replayCalls = 0;
let stopped = false;

const listener = Interceptor.attach(target, {
    onEnter() {
        const threadId = Process.getCurrentThreadId();
        this.savedThreadId = threadId;
        this.isReplay = recursiveThreads.has(threadId);
        this.isTarget = !this.isReplay && this.context.ecx.equals(controller);
        if (!this.isTarget)
            return;
        this.object = this.context.ecx;
        this.edx = this.context.edx;
        this.a2 = this.context.esp.add(4).readPointer();
        offset.writeFloat(-0.25);
        originalCalls++;
    },
    onLeave() {
        if (!this.isTarget || stopped)
            return;
        offset.writeFloat(0.25);
        recursiveThreads.add(this.savedThreadId);
        try {
            replay(this.object, this.edx, this.a2);
            replayCalls++;
        } catch (error) {
            stopped = true;
            send({ event: "error", message: String(error) });
        } finally {
            recursiveThreads.delete(this.savedThreadId);
            offset.writeFloat(0.25);
        }
    }
});

setInterval(function () {
    send({ event: "counts", original: originalCalls, replay: replayCalls, stopped: stopped });
}, 500);

send({ event: "ready" });
""" % (hex(args.function), hex(args.controller), hex(args.offset))

    session = frida.attach(args.pid)
    script = session.create_script(javascript)
    finished = threading.Event()
    latest = {"original": 0, "replay": 0, "stopped": False}

    def on_message(message, data) -> None:
        nonlocal latest
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "counts":
                latest = payload
            elif payload.get("event") == "error":
                print(json.dumps(payload), flush=True)
                finished.set()
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                finished.set()

    script.on("message", on_message)
    script.load()
    try:
        finished.wait(args.seconds)
    finally:
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass

    print(json.dumps(latest, sort_keys=True), flush=True)
    return 0 if latest.get("replay", 0) else 2


if __name__ == "__main__":
    raise SystemExit(main())
