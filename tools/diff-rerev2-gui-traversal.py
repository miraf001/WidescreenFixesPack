"""Diff uGUITextVoice state across one native GUI traversal."""

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
    parser.add_argument("--owner", type=lambda value: int(value, 0), default=0)
    args = parser.parse_args()

    javascript = r"""
const entryAddress = ptr("0x00E18040");
const traversalAddress = ptr("0x00E67E20");
const textVoiceVtable = ptr("0x013BEF30");
const targetOwner = ptr("__TARGET_OWNER__");
let captured = false;
const pendingByThread = new Map();

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

function readF32(address) {
    try {
        return address.readFloat();
    } catch (_) {
        return null;
    }
}

function readTransform(builder) {
    const transform = readPointer(builder.add(0x1818));
    if (transform.isNull())
        return { pointer: transform.toString(), values: [] };
    return {
        pointer: transform.toString(),
        values: [0, 4, 8, 12].map(offset => readF32(transform.add(offset)))
    };
}

function snapshot(address, size, label) {
    if (address.isNull())
        return null;
    try {
        const range = Process.findRangeByAddress(address);
        if (range === null || range.protection.indexOf("r") === -1 ||
            address.add(size).compare(range.base.add(range.size)) > 0)
            return null;
        return {
            address: address,
            label: label,
            size: size,
            bytes: Array.from(new Uint8Array(address.readByteArray(size)))
        };
    } catch (_) {
        return null;
    }
}

function collectTree(root) {
    const result = [];
    const pending = [root];
    const seen = new Set();
    while (pending.length !== 0 && result.length < 256) {
        const node = pending.pop();
        const key = node.toString();
        if (node.isNull() || seen.has(key))
            continue;
        seen.add(key);
        result.push(node);
        const child = readPointer(node.add(0x60));
        const sibling = readPointer(node.add(0x64));
        if (!sibling.isNull() && !sibling.equals(node))
            pending.push(sibling);
        if (!child.isNull() && !child.equals(node))
            pending.push(child);
    }
    return result;
}

function findTextVoiceOwner(nodes) {
    for (const node of nodes) {
        const owner = readPointer(node.add(0x6c));
        if (owner.isNull())
            continue;
        const vtable = readPointer(owner);
        if (!vtable.isNull() && vtable.equals(textVoiceVtable))
            return owner;
    }
    return NULL;
}

function getTextVoiceOwner(object) {
    if (!object.isNull() && readPointer(object).equals(textVoiceVtable))
        return object;
    const owner = readPointer(object.add(0x6c));
    if (!owner.isNull() && readPointer(owner).equals(textVoiceVtable))
        return owner;
    return NULL;
}

function diffSnapshot(item) {
    let after;
    try {
        after = Array.from(new Uint8Array(item.address.readByteArray(item.size)));
    } catch (_) {
        return { label: item.label, address: item.address.toString(), unreadable: true };
    }
    const changes = [];
    for (let offset = 0; offset < item.size; offset += 4) {
        let changed = false;
        for (let index = 0; index < 4 && offset + index < item.size; index++) {
            if (item.bytes[offset + index] !== after[offset + index]) {
                changed = true;
                break;
            }
        }
        if (!changed)
            continue;
        const beforeValue = (
            item.bytes[offset] |
            (item.bytes[offset + 1] << 8) |
            (item.bytes[offset + 2] << 16) |
            (item.bytes[offset + 3] << 24)
        ) >>> 0;
        const afterValue = (
            after[offset] |
            (after[offset + 1] << 8) |
            (after[offset + 2] << 16) |
            (after[offset + 3] << 24)
        ) >>> 0;
        changes.push({
            offset: "0x" + offset.toString(16),
            before: "0x" + beforeValue.toString(16).padStart(8, "0"),
            after: "0x" + afterValue.toString(16).padStart(8, "0")
        });
    }
    return {
        label: item.label,
        address: item.address.toString(),
        changes: changes
    };
}

Interceptor.attach(entryAddress, {
    onEnter(args) {
        this.captureThreadId = Process.getCurrentThreadId();
        this.hasPendingCapture = false;
        if (captured)
            return;

        const object = this.context.ecx;
        const owner = getTextVoiceOwner(object);
        if (owner.isNull())
            return;
        if (!targetOwner.isNull() && !owner.equals(targetOwner))
            return;

        const root = readPointer(owner.add(0xf4));
        if (root.isNull())
            return;
        const nodes = collectTree(root);
        const treeOwner = findTextVoiceOwner(nodes);
        if (treeOwner.isNull() || !treeOwner.equals(owner))
            return;

        const active = nodes.filter(node => (readU32(node.add(0x54)) & 0x00100000) !== 0);
        const context = args[0];
        const builder = readPointer(context.add(4));
        const snapshots = [];
        for (let index = 0; index < nodes.length; index++) {
            const item = snapshot(nodes[index], 0x100, "node[" + index + "]");
            if (item !== null)
                snapshots.push(item);
        }
        for (const [address, size, label] of [
            [owner, 0x180, "controller"],
            [context, 0x200, "render-context"],
            [builder, 0x1900, "command-builder"]
        ]) {
            const item = snapshot(address, size, label);
            if (item !== null)
                snapshots.push(item);
        }

        const state = {
            root: root,
            owner: owner,
            contextPointer: context,
            builder: builder,
            nodes: nodes,
            active: active,
            snapshots: snapshots,
            passes: []
        };
        pendingByThread.set(this.captureThreadId, state);
        this.hasPendingCapture = true;
    },
    onLeave() {
        if (!this.hasPendingCapture)
            return;

        const state = pendingByThread.get(this.captureThreadId);
        if (!captured && state !== undefined && state.passes.length !== 0) {
            captured = true;
            const outerDiffs = state.snapshots.map(diffSnapshot)
                .filter(item => item.unreadable || item.changes.length !== 0);
            send({
                event: "diff",
                phase: "complete hooked uGUITextVoice call",
                root: state.root.toString(),
                owner: state.owner.toString(),
                context: state.contextPointer.toString(),
                builder: state.builder.toString(),
                nodes: state.nodes.map(node => node.toString()),
                active: state.active.map(node => node.toString()),
                passCount: state.passes.length,
                passes: state.passes,
                outerDiffs: outerDiffs
            });
        }
        pendingByThread.delete(this.captureThreadId);
    }
});

Interceptor.attach(traversalAddress, {
    onEnter() {
        this.captureState = null;
        if (captured)
            return;
        const threadId = Process.getCurrentThreadId();
        const state = pendingByThread.get(threadId);
        if (state === undefined || !this.context.ecx.equals(state.root))
            return;
        this.captureThreadId = threadId;
        this.captureState = state;
        this.passIndex = state.passes.length + 1;
        this.passFlagsBefore = readU32(state.contextPointer.add(0x08));
        this.viewportOriginX = readU32(ptr("0x015DDFD8"));
        this.transform = readTransform(state.builder);
        this.passSnapshots = state.snapshots.map(item =>
            snapshot(item.address, item.size, item.label)
        ).filter(item => item !== null);
    },
    onLeave() {
        if (this.captureState === null || captured)
            return;

        const state = this.captureState;
        const diffs = this.passSnapshots.map(diffSnapshot)
            .filter(item => item.unreadable || item.changes.length !== 0);
        state.passes.push({
            index: this.passIndex,
            renderFlagsBefore: "0x" + this.passFlagsBefore.toString(16).padStart(8, "0"),
            renderFlagsAfter: "0x" + readU32(state.contextPointer.add(0x08)).toString(16).padStart(8, "0"),
            viewportOriginX: this.viewportOriginX,
            transform: this.transform,
            diffs: diffs
        });
    }
});

send({
    event: "ready",
    entryAddress: entryAddress.toString(),
    traversalAddress: traversalAddress.toString()
});
"""
    javascript = javascript.replace("__TARGET_OWNER__", f"0x{args.owner:08x}")

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
                    "READY "
                    f"entry={payload['entryAddress']} "
                    f"traversal={payload['traversalAddress']}",
                    flush=True,
                )
            elif payload.get("event") == "diff":
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
        print("Stopping traversal diff.", flush=True)
    finally:
        session.detach()

    if captured is None:
        print("No active uGUITextVoice traversal captured.", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
