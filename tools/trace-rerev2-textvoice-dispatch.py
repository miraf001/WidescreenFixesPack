"""Trace player-indexed uGUITextVoice text dispatch calls."""

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
    args = parser.parse_args()

    javascript = r"""
const dispatch = ptr("0x00959C60");
let hits = 0;

function readPointer(address) {
    try {
        return address.readPointer();
    } catch (_) {
        return NULL;
    }
}

function readText(address) {
    const values = [];
    if (address.isNull())
        return values;
    for (const candidate of [address, readPointer(address), readPointer(address.add(4)), readPointer(address.add(8))]) {
        if (candidate.isNull())
            continue;
        try {
            const value = candidate.readUtf8String(192);
            if (value && value.length > 1)
                values.push({ pointer: candidate.toString(), encoding: "utf8", value: value });
        } catch (_) {
        }
        try {
            const value = candidate.readUtf16String(96);
            if (value && value.length > 1)
                values.push({ pointer: candidate.toString(), encoding: "utf16", value: value });
        } catch (_) {
        }
    }
    return values;
}

Interceptor.attach(dispatch, {
    onEnter(args) {
        hits++;
        const manager = this.context.ecx;
        send({
            event: "dispatch",
            hit: hits,
            manager: manager.toString(),
            player: args[0].toInt32(),
            payload: args[1].toString(),
            slot0: readPointer(manager.add(0x4d0)).toString(),
            slot1: readPointer(manager.add(0x4d4)).toString(),
            textCandidates: readText(args[1])
        });
    }
});

send({ event: "ready", pid: Process.id });
"""

    session = frida.attach(args.pid)
    script = session.create_script(javascript)
    finished = threading.Event()
    events = 0

    def on_message(message, data) -> None:
        nonlocal events
        if message.get("type") == "send":
            payload = message.get("payload", {})
            print(json.dumps(payload, ensure_ascii=False), flush=True)
            if payload.get("event") == "dispatch":
                events += 1
                if events >= 12:
                    finished.set()
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                finished.set()

    script.on("message", on_message)
    script.load()
    try:
        finished.wait(args.timeout_seconds)
    finally:
        session.detach()
    print(f"Captured dispatch events: {events}", flush=True)
    return 0 if events else 2


if __name__ == "__main__":
    raise SystemExit(main())
