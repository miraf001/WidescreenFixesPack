"""Trace calls whose selected pointer argument matches one of the requested addresses."""

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
    parser.add_argument("--argument-index", type=int, default=1)
    parser.add_argument(
        "--match-address", action="append", type=lambda value: int(value, 0), required=True
    )
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    args = parser.parse_args()
    if not 0 <= args.argument_index <= 15:
        raise RuntimeError("argument-index must be between 0 and 15.")

    function_address = f"0x{args.function:X}"
    match_addresses = [f"0x{address:X}" for address in args.match_address]
    javascript = r"""
const functionAddress = ptr(%s);
const argumentIndex = %d;
const matchStrings = %s;
const matches = matchStrings.map(value => ptr(value));
let hitCount = 0;

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

const listener = Interceptor.attach(functionAddress, {
    onEnter(args) {
        const selected = args[argumentIndex];
        const matchIndex = matches.findIndex(value => selected.equals(value));
        if (matchIndex < 0)
            return;
        hitCount++;
        const registers = {};
        for (const name of ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"])
            if (this.context[name] !== undefined)
                registers[name] = this.context[name].toString();
        send({
            event: "match",
            hit: hitCount,
            function: functionAddress.toString(),
            argumentIndex: argumentIndex,
            argument: selected.toString(),
            match: matchStrings[matchIndex],
            returnAddress: this.returnAddress.toString(),
            returnDescription: describe(this.returnAddress),
            registers: registers,
            backtrace: Thread.backtrace(this.context, Backtracer.FUZZY)
                .map(address => describe(address))
        });
    }
});

send({
    event: "ready",
    function: functionAddress.toString(),
    argumentIndex: argumentIndex,
    matches: matchStrings
});
""" % (json.dumps(function_address), args.argument_index, json.dumps(match_addresses))

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
                    f"READY function={payload['function']} argument={payload['argumentIndex']} "
                    f"matches={','.join(payload['matches'])}",
                    flush=True,
                )
            elif payload.get("event") == "match":
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
        print("Stopping trace session.", flush=True)
    finally:
        session.detach()

    if captured is None:
        print("No matching call captured.", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
