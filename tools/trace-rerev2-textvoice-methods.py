"""Trace low-frequency uGUITextVoice methods and look for subtitle text arguments."""

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
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    parser.add_argument("--maximum-events", type=int, default=48)
    parser.add_argument("--samples-per-method", type=int, default=6)
    args = parser.parse_args()

    javascript = r"""
const textVoiceVtable = ptr("0x013BEF30");
const maximumEvents = %d;
const samplesPerMethod = %d;
const methods = [
    ["E171F0", "0x00E171F0"],
    ["E173A0", "0x00E173A0"],
    ["E17C60", "0x00E17C60"],
    ["E17EB0", "0x00E17EB0"],
    ["E17F00", "0x00E17F00"],
    ["E189D0", "0x00E189D0"],
    ["E18C50", "0x00E18C50"],
    ["E18CB0", "0x00E18CB0"],
    ["E18D10", "0x00E18D10"],
    ["E18EA0", "0x00E18EA0"],
    ["E18EC0", "0x00E18EC0"],
    ["E195F0", "0x00E195F0"]
];

let eventCount = 0;
const methodHits = {};

function readPointer(address) {
    try {
        return address.readPointer();
    } catch (_) {
        return NULL;
    }
}

function readable(address) {
    if (address.isNull())
        return false;
    try {
        const range = Process.findRangeByAddress(address);
        return range !== null && range.protection.indexOf("r") !== -1;
    } catch (_) {
        return false;
    }
}

function cleanText(value) {
    if (value === null || value.length < 2)
        return null;
    const shortened = value.substring(0, 160);
    let useful = 0;
    for (let index = 0; index < shortened.length; index++) {
        const code = shortened.charCodeAt(index);
        if (code === 9 || code === 10 || code === 13 || code >= 32)
            useful++;
    }
    if (useful / shortened.length < 0.85)
        return null;
    return shortened;
}

function stringsAt(address) {
    if (!readable(address))
        return [];
    const result = [];
    try {
        const value = cleanText(address.readUtf8String(160));
        if (value !== null)
            result.push({ encoding: "utf8", value: value });
    } catch (_) {
    }
    try {
        const value = cleanText(address.readUtf16String(80));
        if (value !== null && !result.some(item => item.value === value))
            result.push({ encoding: "utf16", value: value });
    } catch (_) {
    }
    return result;
}

function describePointer(value) {
    const result = { value: value.toString() };
    const direct = stringsAt(value);
    if (direct.length !== 0)
        result.strings = direct;

    const nested = [];
    for (const offset of [0, 4, 8, 12, 16, 20, 24, 28]) {
        const candidate = readPointer(value.add(offset));
        const strings = stringsAt(candidate);
        if (strings.length !== 0)
            nested.push({ offset: "0x" + offset.toString(16), pointer: candidate.toString(), strings: strings });
    }
    if (nested.length !== 0)
        result.nested = nested;
    return result;
}

function inspectObject(object) {
    const strings = [];
    for (let offset = 4; offset < 0x170; offset += 4) {
        const candidate = readPointer(object.add(offset));
        const values = stringsAt(candidate);
        if (values.length !== 0)
            strings.push({ offset: "0x" + offset.toString(16), pointer: candidate.toString(), strings: values });
    }
    return strings;
}

for (const [name, addressText] of methods) {
    methodHits[name] = 0;
    Interceptor.attach(ptr(addressText), {
        onEnter() {
            this.capture = false;
            if (eventCount >= maximumEvents || methodHits[name] >= samplesPerMethod)
                return;

            const object = this.context.ecx;
            if (readPointer(object).compare(textVoiceVtable) !== 0)
                return;

            methodHits[name]++;
            eventCount++;
            this.capture = true;
            this.name = name;
            this.object = object;
            const args = [];
            for (let index = 0; index < 6; index++) {
                const value = readPointer(this.context.esp.add(4 + index * 4));
                args.push(describePointer(value));
            }
            send({
                event: "enter",
                method: name,
                hit: methodHits[name],
                object: object.toString(),
                returnAddress: this.returnAddress.toString(),
                args: args,
                objectStrings: inspectObject(object)
            });
        },
        onLeave(retval) {
            if (!this.capture)
                return;
            send({
                event: "leave",
                method: this.name,
                object: this.object.toString(),
                retval: retval.toString(),
                objectStrings: inspectObject(this.object)
            });
        }
    });
}

send({ event: "ready", methods: methods.map(item => item[0]) });
""" % (args.maximum_events, args.samples_per_method)

    finished = threading.Event()
    captured = 0

    print(f"Attaching to PID {args.pid}...", flush=True)
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal captured
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print("READY methods=" + ",".join(payload["methods"]), flush=True)
            else:
                if payload.get("event") == "enter":
                    captured += 1
                print(json.dumps(payload, ensure_ascii=False), flush=True)
                if captured >= args.maximum_events:
                    finished.set()
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

    print(f"Captured uGUITextVoice calls: {captured}", flush=True)
    return 0 if captured else 2


if __name__ == "__main__":
    raise SystemExit(main())
