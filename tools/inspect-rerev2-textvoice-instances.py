"""Enumerate live RE:Rev2 uGUITextVoice instances and their same-class links."""

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
    args = parser.parse_args()

    javascript = r"""
const textVoiceVtable = ptr("0x013BEF30");
const pattern = "30 ef 3b 01";

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

function readable(address, size) {
    if (address.isNull())
        return false;
    try {
        const range = Process.findRangeByAddress(address);
        return range !== null && range.protection.indexOf("r") !== -1 &&
            address.add(size).compare(range.base.add(range.size)) <= 0;
    } catch (_) {
        return false;
    }
}

function collectTree(root) {
    const pending = [root];
    const seen = new Set();
    const nodes = [];
    while (pending.length !== 0 && nodes.length < 2048) {
        const node = pending.pop();
        const key = node.toString();
        if (node.isNull() || seen.has(key) || !readable(node, 0x70))
            continue;
        seen.add(key);
        nodes.push({
            address: key,
            flags: "0x" + readU32(node.add(0x54)).toString(16).padStart(8, "0"),
            owner: readPointer(node.add(0x6c)).toString()
        });
        const child = readPointer(node.add(0x60));
        const sibling = readPointer(node.add(0x64));
        if (!sibling.isNull() && !sibling.equals(node))
            pending.push(sibling);
        if (!child.isNull() && !child.equals(node))
            pending.push(child);
    }
    return nodes;
}

function inspectInstance(object) {
    const links = [];
    const readablePointers = [];
    for (let offset = 4; offset < 0x180; offset += 4) {
        const value = readPointer(object.add(offset));
        if (value.isNull())
            continue;
        if (readable(value, 4)) {
            readablePointers.push({
                offset: "0x" + offset.toString(16),
                value: value.toString(),
                first: "0x" + readU32(value).toString(16).padStart(8, "0")
            });
            if (readPointer(value).equals(textVoiceVtable))
                links.push({ offset: "0x" + offset.toString(16), value: value.toString() });
        }
    }

    const root = readPointer(object.add(0xf4));
    return {
        object: object.toString(),
        root: root.toString(),
        rootTree: readable(root, 0x70) ? collectTree(root) : [],
        sameClassLinks: links,
        readablePointers: readablePointers
    };
}

setImmediate(function () {
    const found = new Map();
    for (const protection of ["rw-", "rwx"]) {
        const ranges = Process.enumerateRanges({ protection: protection, coalesce: true });
        for (const range of ranges) {
            let matches = [];
            try {
                matches = Memory.scanSync(range.base, range.size, pattern);
            } catch (_) {
                continue;
            }
            for (const match of matches)
                found.set(match.address.toString(), match.address);
        }
    }

    const instances = Array.from(found.values())
        .map(inspectInstance)
        .sort((left, right) => ptr(left.object).compare(ptr(right.object)));
    send({ event: "instances", count: instances.length, instances: instances });
});
"""

    finished = threading.Event()
    result: dict | None = None
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal result
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "instances":
                result = payload
                print(json.dumps(payload, indent=2), flush=True)
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

    return 0 if result is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
