"""Create one uGUITextVoice, link it beside the native instance, and observe it."""

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
    parser.add_argument("--owner", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    args = parser.parse_args()

    javascript = r"""
const transformEntry = ptr("0x00E18040");
const targetOwner = ptr("__TARGET_OWNER__");
const textVoiceVtable = ptr("0x013BEF30");
const createTextVoice = new NativeFunction(
    ptr("0x00967B50"), "pointer", []);

let creating = false;
let clone = NULL;
let cloneCalls = 0;

function readPointer(address) {
    try {
        return address.readPointer();
    } catch (_) {
        return NULL;
    }
}

function describeClone(event) {
    send({
        event: event,
        clone: clone.toString(),
        vtable: readPointer(clone).toString(),
        expectedVtable: textVoiceVtable.toString(),
        root: readPointer(clone.add(0xf4)).toString(),
        guiObject: readPointer(clone.add(0x2c0)).toString(),
        textObject: readPointer(clone.add(0x2c4)).toString(),
        callbackTable: readPointer(clone.add(0x258)).toString(),
        next: readPointer(clone.add(0x14)).toString(),
        previous: readPointer(clone.add(0x18)).toString()
    });
}

Interceptor.attach(transformEntry, {
    onEnter() {
        if (creating)
            return;
        const object = this.context.ecx;

        if (clone.isNull() && object.equals(targetOwner)) {
            creating = true;
            try {
                clone = createTextVoice();
                if (!clone.isNull()) {
                    const oldNext = readPointer(targetOwner.add(0x14));
                    clone.add(0x14).writePointer(oldNext);
                    clone.add(0x18).writePointer(targetOwner);
                    if (!oldNext.isNull())
                        oldNext.add(0x18).writePointer(clone);
                    targetOwner.add(0x14).writePointer(clone);
                }
                describeClone("created");
                setTimeout(() => describeClone("status-1s"), 1000);
                setTimeout(() => describeClone("status-5s"), 5000);
            } catch (error) {
                send({ event: "create-error", description: String(error), stack: error.stack });
            }
            creating = false;
            return;
        }

        if (!clone.isNull() && object.equals(clone)) {
            cloneCalls++;
            if (cloneCalls <= 4)
                send({ event: "clone-transform", clone: clone.toString(), hit: cloneCalls });
        }
    }
});

send({ event: "ready", targetOwner: targetOwner.toString() });
""".replace("__TARGET_OWNER__", f"0x{args.owner:08x}")

    session = frida.attach(args.pid)
    script = session.create_script(javascript)
    finished = threading.Event()
    created = False

    def on_message(message, data) -> None:
        nonlocal created
        if message.get("type") == "send":
            payload = message.get("payload", {})
            print(json.dumps(payload), flush=True)
            if payload.get("event") == "created":
                created = payload.get("clone") != "0x0"
            elif payload.get("event") == "create-error":
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

    return 0 if created else 2


if __name__ == "__main__":
    raise SystemExit(main())
