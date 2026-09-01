"""Trace resolved RE:Rev2 localization strings returned by sub_954B40."""

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
    parser.add_argument("--contains", default="")
    parser.add_argument(
        "--address-range",
        action="append",
        default=[],
        help="Optional inclusive-exclusive pointer range formatted as START:END.",
    )
    parser.add_argument(
        "--pointer-table",
        action="append",
        default=[],
        help="Optional pointer table formatted as START:COUNT.",
    )
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    args = parser.parse_args()

    parsed_ranges: list[tuple[int, int]] = []
    for value in args.address_range:
        start_text, separator, end_text = value.partition(":")
        if not separator:
            parser.error(f"Invalid --address-range {value!r}; expected START:END.")
        start = int(start_text, 0)
        end = int(end_text, 0)
        if start >= end:
            parser.error(f"Invalid --address-range {value!r}; START must be below END.")
        parsed_ranges.append((start, end))

    parsed_pointer_tables: list[tuple[int, int]] = []
    for value in args.pointer_table:
        start_text, separator, count_text = value.partition(":")
        if not separator:
            parser.error(f"Invalid --pointer-table {value!r}; expected START:COUNT.")
        start = int(start_text, 0)
        count = int(count_text, 0)
        if count <= 0 or count > 4096:
            parser.error(f"Invalid --pointer-table {value!r}; COUNT must be 1..4096.")
        parsed_pointer_tables.append((start, count))

    javascript = r"""
const functionAddress = ptr(%s);
const needle = %s;
const ranges = %s.map(item => [ptr(item[0]), ptr(item[1])]);
const pointerTables = %s.map(item => [ptr(item[0]), item[1]]);
const allowedPointers = new Set();
for (const [start, count] of pointerTables) {
    for (let index = 0; index < count; index++) {
        try {
            const value = start.add(index * Process.pointerSize).readPointer();
            if (!value.isNull())
                allowedPointers.add(value.toString());
        } catch (_) {
        }
    }
}

function describe(address) {
    const module = Process.findModuleByAddress(address);
    if (module === null)
        return address.toString();
    return module.name + "+0x" + address.sub(module.base).toString(16);
}

Interceptor.attach(functionAddress, {
    onEnter(args) {
        this.owner = this.context.ecx;
        this.index = args[0];
        this.variant = args[1];
        this.caller = this.returnAddress;
        this.trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(address => describe(address));
    },
    onLeave(retval) {
        if (allowedPointers.size !== 0 && !allowedPointers.has(retval.toString()))
            return;
        if (ranges.length !== 0 && !ranges.some(item =>
            retval.compare(item[0]) >= 0 && retval.compare(item[1]) < 0))
            return;
        let value;
        try {
            value = retval.readUtf8String(2048);
        } catch (_) {
            return;
        }
        if (value === null || value.trim().length < 2 || value.startsWith("(dummy") ||
            (needle.length !== 0 && value.indexOf(needle) === -1))
            return;
        send({
            event: "match",
            function: functionAddress.toString(),
            owner: this.owner.toString(),
            index: this.index.toInt32(),
            variant: this.variant.toInt32(),
            textPointer: retval.toString(),
            text: value,
            returnAddress: this.caller.toString(),
            returnDescription: describe(this.caller),
            backtrace: this.trace
        });
    }
});

send({
    event: "ready",
    function: functionAddress.toString(),
    needle: needle,
    ranges: ranges.map(item => [item[0].toString(), item[1].toString()]),
    allowedPointerCount: allowedPointers.size
});
""" % (
        json.dumps(f"0x{args.function:X}"),
        json.dumps(args.contains),
        json.dumps([[f"0x{start:X}", f"0x{end:X}"] for start, end in parsed_ranges]),
        json.dumps([[f"0x{start:X}", count] for start, count in parsed_pointer_tables]),
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
            if payload.get("event") == "ready":
                print(
                    f"READY function={payload['function']} contains={payload['needle']!r} "
                    f"ranges={payload['ranges']} "
                    f"allowedPointers={payload['allowedPointerCount']}",
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
        print("No matching localization result captured.", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
