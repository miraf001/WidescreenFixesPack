"""Trace RE:Rev2's verified direct-string setter and match text content."""

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
    parser.add_argument("--function", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--contains", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    args = parser.parse_args()

    javascript = r"""
const functionAddress = ptr(%s);
const needle = %s;
let hitCount = 0;

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

Interceptor.attach(functionAddress, {
    onEnter(args) {
        const destination = this.context.ecx;
        const textPointer = args[1];
        let value;
        try {
            value = textPointer.readUtf8String(2048);
        } catch (_) {
            return;
        }
        if (value === null || value.indexOf(needle) === -1)
            return;

        hitCount++;
        send({
            event: "match",
            hit: hitCount,
            function: functionAddress.toString(),
            destination: destination.toString(),
            textPointer: textPointer.toString(),
            text: value,
            returnAddress: this.returnAddress.toString(),
            returnDescription: describe(this.returnAddress),
            backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(address => describe(address))
        });
    }
});

send({ event: "ready", function: functionAddress.toString(), needle: needle });
""" % (json.dumps(f"0x{args.function:X}"), json.dumps(args.contains))

    finished = threading.Event()
    captured: dict | None = None

    print(f"Attaching to PID {args.pid}...", flush=True)
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal captured
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print(
                    f"READY function={payload['function']} contains={payload['needle']!r}",
                    flush=True,
                )
            elif payload.get("event") == "match":
                captured = payload
                print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)
                finished.set()
            else:
                print(json.dumps(payload, ensure_ascii=False), flush=True)
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
        print("Stopping trace session.", flush=True)
    finally:
        session.detach()

    if captured is None:
        print("No matching text setter call captured.", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
