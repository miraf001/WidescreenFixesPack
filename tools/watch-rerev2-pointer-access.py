"""Use x86 hardware watchpoints to find code accessing selected RE:Rev2 fields."""

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument(
        "--address", action="append", type=lambda value: int(value, 0), required=True
    )
    parser.add_argument(
        "--access",
        choices=("r", "w", "rw"),
        default="r",
        help="Hardware watchpoint access type (default: r).",
    )
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if not 1 <= len(args.address) <= 4:
        parser.error("Specify between one and four --address values.")
    if any(address % 4 for address in args.address):
        parser.error("Every watched pointer address must be four-byte aligned.")

    javascript = r"""
const watched = %s.map(value => ptr(value));
const access = %s;
const watchedThreads = new Map();
let armed = true;

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

function armThread(thread) {
    if (!armed || watchedThreads.has(thread.id))
        return;
    const installed = [];
    for (let index = 0; index < watched.length; index++) {
        try {
            thread.setHardwareWatchpoint(index, watched[index], 4, access);
            installed.push(index);
        } catch (error) {
            send({
                event: "watch-error",
                threadId: thread.id,
                watchpoint: index,
                address: watched[index].toString(),
                error: String(error)
            });
        }
    }
    if (installed.length !== 0)
        watchedThreads.set(thread.id, { thread: thread, installed: installed });
}

function disarmThread(threadId) {
    const state = watchedThreads.get(threadId);
    if (state === undefined)
        return;
    for (const index of state.installed) {
        try {
            state.thread.unsetHardwareWatchpoint(index);
        } catch (_) {
        }
    }
    watchedThreads.delete(threadId);
}

function disarmAll() {
    for (const threadId of Array.from(watchedThreads.keys()))
        disarmThread(threadId);
}

Process.setExceptionHandler(details => {
    if (!armed || (details.type !== "single-step" && details.type !== "breakpoint"))
        return false;

    armed = false;
    const threadId = Process.getCurrentThreadId();
    disarmThread(threadId);
    const registers = {};
    for (const name of ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"])
        if (details.context[name] !== undefined)
            registers[name] = details.context[name].toString();
    send({
        event: "access",
        type: details.type,
        threadId: threadId,
        instruction: details.address.toString(),
        instructionDescription: describe(details.address),
        memory: details.memory === undefined ? null : {
            operation: details.memory.operation,
            address: details.memory.address.toString()
        },
        registers: registers,
        backtrace: Thread.backtrace(details.context, Backtracer.ACCURATE)
            .map(address => describe(address))
    });
    setImmediate(disarmAll);
    return true;
});

const observer = Process.attachThreadObserver({
    onAdded(thread) {
        armThread(thread);
    },
    onRemoved(thread) {
        watchedThreads.delete(thread.id);
    }
});

send({
    event: "ready",
    addresses: watched.map(value => value.toString()),
    access: access,
    threadCount: watchedThreads.size
});
""" % (
        json.dumps([f"0x{address:X}" for address in args.address]),
        json.dumps(args.access),
    )

    finished = threading.Event()
    captured: dict | None = None

    print(f"Attaching to PID {args.pid}...", flush=True)
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal captured
        if message.get("type") == "send":
            payload = message.get("payload", {})
            event = payload.get("event")
            if event == "ready":
                print(
                    f"READY access={payload['access']} "
                    f"addresses={','.join(payload['addresses'])} "
                    f"threads={payload['threadCount']}",
                    flush=True,
                )
            elif event == "access":
                captured = payload
                print(json.dumps(payload, indent=2), flush=True)
                finished.set()
            else:
                print(json.dumps(payload), flush=True)
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
        finished.wait(args.timeout_seconds)
    except KeyboardInterrupt:
        print("Stopping watchpoint session.", flush=True)
    finally:
        session.detach()

    if captured is None:
        print("No watched access captured.", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
