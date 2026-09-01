"""Trace active uGUITextVoice nodes at the RE:Rev2 GUI traversal boundary."""

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
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--maximum-hits", type=int, default=16)
    parser.add_argument("--rearm-on-leave", action="store_true")
    args = parser.parse_args()

    javascript = r"""
const traversalAddress = ptr("0x00E67E20");
const textVoiceVtable = ptr("0x013BEF30");
const maximumHits = %d;
const rearmOnLeave = %s;
let hitCount = 0;

function readPointer(address) {
    try {
        return address.readPointer();
    } catch (_) {
        return NULL;
    }
}

function readU32(address) {
    try {
        return address.readU32();
    } catch (_) {
        return 0;
    }
}

function captureTree(root) {
    const result = { visited: 0, active: [] };
    const pending = [];
    const first = readPointer(root.add(0x60));
    if (!first.isNull())
        pending.push(first);

    while (pending.length !== 0 && result.visited < 2048) {
        const node = pending.pop();
        result.visited++;
        const flags = readU32(node.add(0x54));
        if ((flags & 0x00100000) !== 0 && result.active.length < 128)
            result.active.push({ node: node.toString(), flags: "0x" + flags.toString(16) });

        const sibling = readPointer(node.add(0x64));
        const child = readPointer(node.add(0x60));
        if (!sibling.isNull() && !sibling.equals(node))
            pending.push(sibling);
        if (!child.isNull() && !child.equals(node))
            pending.push(child);
    }
    return result;
}

const listener = Interceptor.attach(traversalAddress, {
    onEnter() {
        this.activeNodes = [];
        if (hitCount >= maximumHits)
            return;

        const root = this.context.ecx;
        const first = readPointer(root.add(0x60));
        if (first.isNull())
            return;
        const owner = readPointer(first.add(0x6c));
        if (owner.isNull() || !readPointer(owner).equals(textVoiceVtable))
            return;

        const tree = captureTree(root);
        if (tree.active.length === 0)
            return;

        this.activeNodes = tree.active.map(item => ptr(item.node));
        hitCount++;
        send({
            event: "active-traversal",
            hit: hitCount,
            root: root.toString(),
            owner: owner.toString(),
            returnAddress: this.returnAddress.toString(),
            visited: tree.visited,
            active: tree.active
        });
    },
    onLeave() {
        if (!rearmOnLeave || this.activeNodes.length === 0)
            return;

        for (const node of this.activeNodes) {
            try {
                node.add(0x54).writeU32(node.add(0x54).readU32() | 0x00100000);
            } catch (_) {
            }
        }
    }
});

send({ event: "ready", address: traversalAddress.toString() });
""" % (args.maximum_hits, "true" if args.rearm_on_leave else "false")

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
                print(f"READY address={payload['address']}", flush=True)
            elif payload.get("event") == "active-traversal":
                captured += 1
                print(json.dumps(payload), flush=True)
                if captured >= args.maximum_hits:
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

    print(f"Captured active traversals: {captured}", flush=True)
    return 0 if captured else 2


if __name__ == "__main__":
    raise SystemExit(main())
