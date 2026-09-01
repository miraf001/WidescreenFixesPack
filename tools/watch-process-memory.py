"""Use Frida hardware watchpoints to identify code reading target addresses."""

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
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if not 1 <= len(args.address) <= 4:
        raise RuntimeError("Hardware watchpoints support between one and four addresses.")

    targets = [f"0x{address:X}" for address in args.address]
    javascript = r"""
const targetStrings = %s;
const targets = targetStrings.map(value => ptr(value));
let handled = false;
const watchedThreads = new Map();

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

Process.setExceptionHandler(details => {
    const isHardwareTrap = details.type === "single-step" || details.type === "breakpoint";
    if (!isHardwareTrap)
        return false;
    if (handled)
        return true;

    handled = true;
    const context = details.context;
    const memory = details.memory;
    const registers = {};
    for (const name of ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"])
        if (context[name] !== undefined)
            registers[name] = context[name].toString();
    const backtrace = Thread.backtrace(context, Backtracer.FUZZY)
        .map(address => describe(address));
    send({
        event: "access",
        targets: targetStrings,
        exceptionType: details.type,
        accessedAddress: memory === undefined ? null : memory.address.toString(),
        operation: memory === undefined ? null : memory.operation,
        instruction: details.address.toString(),
        instructionDescription: describe(details.address),
        registers: registers,
        backtrace: backtrace
    });
    return true;
});

const observer = Process.attachThreadObserver({
    onAdded(thread) {
        try {
            targets.forEach((target, index) =>
                thread.setHardwareWatchpoint(index, target, 1, "r"));
            watchedThreads.set(thread.id, thread);
        } catch (error) {
            send({ event: "thread-error", threadId: thread.id, error: String(error) });
        }
    },
    onRemoved(thread) {
        watchedThreads.delete(thread.id);
    }
});

send({ event: "ready", targets: targetStrings, threadCount: watchedThreads.size });
""" % json.dumps(targets)

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
                    f"READY targets={','.join(payload['targets'])} "
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

    script.on("message", on_message)
    def on_detached(*details) -> None:
        print(f"Target detached: {details}", flush=True)
        finished.set()

    session.on("detached", on_detached)
    script.load()
    try:
        finished.wait(args.timeout_seconds)
    except KeyboardInterrupt:
        print("Stopping watchpoint session.", flush=True)
    finally:
        session.detach()

    if captured is None:
        print("No matching memory access captured.", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
