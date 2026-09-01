"""Trace uGUITextVoice creation and lifecycle calls from game startup."""

from __future__ import annotations

import argparse
import json
import threading
import time
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name, getattr(typing_extensions, compatibility_name))

import frida


def wait_for_process(device, name: str, timeout_seconds: float) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for process in device.enumerate_processes():
            if process.name.casefold() == name.casefold():
                return process.pid
        time.sleep(0.02)
    raise RuntimeError(f"{name} did not start within {timeout_seconds:g} seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--process-name", default="rerev2.exe")
    parser.add_argument("--wait-seconds", type=float, default=30.0)
    parser.add_argument("--trace-seconds", type=float, default=35.0)
    args = parser.parse_args()

    javascript = r"""
const textVoiceVtable = ptr("0x013BEF30");
const tracked = new Set();

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function readPointer(address) {
    try {
        return address.readPointer();
    } catch (_) {
        return NULL;
    }
}

function snapshot(object) {
    return {
        object: object.toString(),
        vtable: readPointer(object).toString(),
        owner: readPointer(object.add(0xf0)).toString(),
        root: readPointer(object.add(0xf4)).toString(),
        callbackTable: readPointer(object.add(0x258)).toString(),
        guiObject: readPointer(object.add(0x2c0)).toString(),
        textObject: readPointer(object.add(0x2c4)).toString()
    };
}

function trace(name, address, identifyOnLeave) {
    Interceptor.attach(ptr(address), {
        onEnter(args) {
            this.object = this.context.ecx;
            this.capture = tracked.has(this.object.toString()) ||
                readPointer(this.object).equals(textVoiceVtable);
            this.details = {
                event: "enter",
                method: name,
                threadId: Process.getCurrentThreadId(),
                returnAddress: describe(this.returnAddress),
                backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 12).map(describe)
            };
            if (this.capture)
                Object.assign(this.details, snapshot(this.object));
            if (this.capture)
                send(this.details);
        },
        onLeave(retval) {
            if (identifyOnLeave && !retval.isNull()) {
                tracked.add(retval.toString());
                send(Object.assign({
                    event: "leave",
                    method: name,
                    retval: retval.toString()
                }, snapshot(retval)));
            } else if (this.capture) {
                send(Object.assign({
                    event: "leave",
                    method: name,
                    retval: retval.toString()
                }, snapshot(this.object)));
            }
        }
    });
}

trace("factory", "0x00967B50", true);
trace("constructor", "0x009679A0", true);
trace("activate", "0x00967BF0", false);
trace("resource-ready", "0x009677C0", false);
trace("base-activate", "0x0096ACD0", false);
trace("request-resource", "0x00968090", false);
trace("register-callbacks", "0x0096A8F0", false);

send({ event: "ready", pid: Process.id });
"""

    device = frida.get_local_device()
    pid = wait_for_process(device, args.process_name, args.wait_seconds)
    print(f"Attaching to PID {pid}...", flush=True)
    session = device.attach(pid)
    script = session.create_script(javascript)
    finished = threading.Event()
    events = 0

    def on_message(message, data) -> None:
        nonlocal events
        if message.get("type") == "send":
            payload = message.get("payload", {})
            print(json.dumps(payload), flush=True)
            if payload.get("event") != "ready":
                events += 1
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                finished.set()

    def on_detached(*details) -> None:
        print(f"Target detached: {details}", flush=True)
        finished.set()

    script.on("message", on_message)
    session.on("detached", on_detached)
    script.load()
    try:
        finished.wait(args.trace_seconds)
    finally:
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass
    print(f"Captured lifecycle events: {events}", flush=True)
    return 0 if events else 2


if __name__ == "__main__":
    raise SystemExit(main())
