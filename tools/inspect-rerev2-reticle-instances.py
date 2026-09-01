"""Enumerate live RE:Rev2 uGUIReticle controller instances and GUI trees."""

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
const classes = [
    { name: "uGUIReticleBase", vtable: ptr("0x013A3868"), pattern: "68 38 3a 01" },
    { name: "uGUIReticleNatalia", vtable: ptr("0x013A3A10"), pattern: "10 3a 3a 01" },
    { name: "uGUIReticleScope", vtable: ptr("0x013A3B70"), pattern: "70 3b 3a 01" },
    { name: "uGUIReticleThrow", vtable: ptr("0x013A3CA8"), pattern: "a8 3c 3a 01" }
];

function readPointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}

function readU32(address) {
    try { return address.readU32(); } catch (_) { return 0; }
}

function readF32(address) {
    try { return address.readFloat(); } catch (_) { return null; }
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

function cleanFloat(value) {
    if (value === null || !Number.isFinite(value) || Math.abs(value) > 100000)
        return null;
    return Math.round(value * 10000) / 10000;
}

function collectTree(root, owner) {
    const pending = [root];
    const seen = new Set();
    const nodes = [];
    while (pending.length !== 0 && nodes.length < 2048) {
        const node = pending.pop();
        const key = node.toString();
        if (node.isNull() || seen.has(key) || !readable(node, 0x70))
            continue;
        seen.add(key);
        const nodeOwner = readPointer(node.add(0x6c));
        nodes.push({
            address: key,
            flags: "0x" + readU32(node.add(0x54)).toString(16).padStart(8, "0"),
            owner: nodeOwner.toString(),
            isTargetOwner: nodeOwner.equals(owner),
            floats30To5c: Array.from({ length: 12 }, (_, index) =>
                cleanFloat(readF32(node.add(0x30 + index * 4))))
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

function inspectInstance(object, classInfo) {
    const root = readPointer(object.add(0xf4));
    const controllerFields = [];
    for (let offset = 0x100; offset < 0x340; offset += 4) {
        const asFloat = cleanFloat(readF32(object.add(offset)));
        const asU32 = readU32(object.add(offset));
        if ((asFloat !== null && asFloat !== 0) || asU32 !== 0) {
            controllerFields.push({
                offset: "0x" + offset.toString(16),
                u32: "0x" + asU32.toString(16).padStart(8, "0"),
                f32: asFloat
            });
        }
    }
    return {
        className: classInfo.name,
        object: object.toString(),
        root: root.toString(),
        tree: readable(root, 0x70) ? collectTree(root, object) : [],
        controllerFields: controllerFields
    };
}

setImmediate(function () {
    const found = [];
    for (const classInfo of classes) {
        const addresses = new Map();
        for (const protection of ["rw-", "rwx"]) {
            for (const range of Process.enumerateRanges({ protection: protection, coalesce: true })) {
                let matches = [];
                try { matches = Memory.scanSync(range.base, range.size, classInfo.pattern); }
                catch (_) { continue; }
                for (const match of matches)
                    addresses.set(match.address.toString(), match.address);
            }
        }
        for (const object of addresses.values())
            found.push(inspectInstance(object, classInfo));
    }
    found.sort((left, right) => ptr(left.object).compare(ptr(right.object)));
    send({ event: "instances", count: found.length, instances: found });
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
