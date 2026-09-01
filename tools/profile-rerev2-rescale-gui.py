"""Profile GUI owners passing through the focused RE:Rev2 RESCALE hook."""

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


def number(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=number, required=True)
    parser.add_argument("--function", type=number, required=True)
    parser.add_argument("--seconds", type=float, default=5.0)
    args = parser.parse_args()

    javascript = r"""
const target = ptr("%s");
const durationMilliseconds = %d;
const groups = new Map();
const identificationCache = new Map();

function readPointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}

function readS32(address) {
    try { return address.readS32(); } catch (_) { return null; }
}

function readClassName(controller) {
    if (controller.isNull())
        return null;
    const vtable = readPointer(controller);
    if (vtable.isNull())
        return null;
    try {
        const value = vtable.add(0x1b8).readUtf8String(96);
        if (value !== null && /^u[A-Za-z0-9_]+$/.test(value))
            return value;
    } catch (_) {
    }
    return null;
}

function identify(object) {
    const objectKey = object.toString();
    const cached = identificationCache.get(objectKey);
    if (cached !== undefined)
        return cached;

    const directName = readClassName(object);
    if (directName !== null) {
        const result = { controller: object, className: directName, relation: "direct" };
        identificationCache.set(objectKey, result);
        return result;
    }

    for (const offset of [0x6c, 0x74]) {
        const owner = readPointer(object.add(offset));
        const ownerName = readClassName(owner);
        if (ownerName !== null) {
            const result = {
                controller: owner,
                className: ownerName,
                relation: "+0x" + offset.toString(16)
            };
            identificationCache.set(objectKey, result);
            return result;
        }
    }

    // Most RESCALE callbacks receive a GUI tree root. Its controller is stored
    // on one of the child nodes rather than on the root itself.
    const pending = [];
    const firstChild = readPointer(object.add(0x60));
    if (!firstChild.isNull())
        pending.push(firstChild);
    const visited = new Set();
    while (pending.length !== 0 && visited.size < 512) {
        const node = pending.pop();
        const nodeKey = node.toString();
        if (node.isNull() || visited.has(nodeKey))
            continue;
        visited.add(nodeKey);

        for (const offset of [0x6c, 0x74]) {
            const owner = readPointer(node.add(offset));
            const ownerName = readClassName(owner);
            if (ownerName !== null) {
                const result = {
                    controller: owner,
                    className: ownerName,
                    relation: "tree node " + nodeKey + "+0x" + offset.toString(16)
                };
                identificationCache.set(objectKey, result);
                return result;
            }
        }

        const child = readPointer(node.add(0x60));
        const sibling = readPointer(node.add(0x64));
        if (!sibling.isNull() && !sibling.equals(node))
            pending.push(sibling);
        if (!child.isNull() && !child.equals(node))
            pending.push(child);
    }

    const result = { controller: NULL, className: "<unknown>", relation: "none" };
    identificationCache.set(objectKey, result);
    return result;
}

function collectInterestingStrings(controller) {
    if (controller.isNull())
        return [];
    const result = new Set();
    for (let offset = 0; offset < 0x320; offset += Process.pointerSize) {
        const candidate = readPointer(controller.add(offset));
        if (candidate.isNull())
            continue;
        try {
            const value = candidate.readUtf8String(128);
            if (value === null || value.length < 3 || value.length > 120)
                continue;
            if (!/^[\x20-\x7e]+$/.test(value))
                continue;
            if (/(gui|menu|pause|hud|common|inventory|option|txt|voice|reticle)/i.test(value))
                result.add("+0x" + offset.toString(16) + "=" + value);
        } catch (_) {
        }
    }
    return Array.from(result).slice(0, 16);
}

Interceptor.attach(target, {
    onEnter() {
        const object = this.context.ecx;
        const identified = identify(object);
        let bounds = "unreadable";
        let builder = NULL;
        try {
            const context = this.context.esp.add(4).readPointer();
            builder = readPointer(context.add(4));
            if (!builder.isNull()) {
                const left = readS32(builder.add(47 * 4));
                const top = readS32(builder.add(48 * 4));
                const right = readS32(builder.add(49 * 4));
                const bottom = readS32(builder.add(50 * 4));
                bounds = left + "," + top + "," + right + "," + bottom;
            }
        } catch (_) {
        }

        const key = identified.className + "|" + identified.controller + "|" + bounds;
        let group = groups.get(key);
        if (group === undefined) {
            group = {
                className: identified.className,
                controller: identified.controller.toString(),
                relation: identified.relation,
                object: object.toString(),
                builder: builder.toString(),
                bounds: bounds,
                returnAddress: this.returnAddress.toString(),
                strings: collectInterestingStrings(identified.controller),
                calls: 0
            };
            groups.set(key, group);
        }
        group.calls++;
    }
});

setTimeout(function () {
    const rows = Array.from(groups.values());
    rows.sort((left, right) => right.calls - left.calls);
    send({ event: "summary", groups: rows });
}, durationMilliseconds);

send({ event: "ready", target: target.toString() });
""" % (hex(args.function), max(1, round(args.seconds * 1000)))

    finished = threading.Event()
    result: dict | None = None
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal result
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print(f"READY target={payload['target']}", flush=True)
            elif payload.get("event") == "summary":
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
        finished.wait(args.seconds + 5.0)
    finally:
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass

    return 0 if result is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
