"""Count native uGUITextVoice state-machine calls by controller address."""

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
    parser.add_argument("--seconds", type=float, default=5.0)
    args = parser.parse_args()

    javascript = r"""
const textVoiceVtable = ptr("0x013BEF30");
const counts = {};

function readPointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}

Interceptor.attach(ptr("0x00968DF0"), {
    onEnter() {
        const object = this.context.ecx;
        if (!readPointer(object).equals(textVoiceVtable))
            return;
        const key = object.toString();
        counts[key] = (counts[key] || 0) + 1;
    }
});

setInterval(function () {
    const snapshot = {};
    for (const key in counts)
        snapshot[key] = counts[key];
    send({ event: "counts", controllers: snapshot });
}, 500);

send({ event: "ready", pid: Process.id });
"""

    session = frida.attach(args.pid)
    script = session.create_script(javascript)
    finished = threading.Event()
    latest: dict[str, int] = {}

    def on_message(message, data) -> None:
        nonlocal latest
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "counts":
                latest = payload.get("controllers", {})
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                finished.set()

    script.on("message", on_message)
    script.load()
    try:
        finished.wait(args.seconds)
    finally:
        session.detach()

    print(json.dumps(latest, sort_keys=True), flush=True)
    return 0 if latest else 2


if __name__ == "__main__":
    raise SystemExit(main())
