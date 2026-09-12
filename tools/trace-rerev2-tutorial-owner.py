"""Trace RE:Rev2 <TUTR ...> expansion and its per-player context.

Read-only Frida diagnostic.  It records the parser instance, tutorial token,
owner field used by the native gamepad path, and the two global input-mode
branches.  Press Enter to detach.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import typing

import typing_extensions

for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name,
                getattr(typing_extensions, compatibility_name))

import frida


AGENT = r"""
const parserEntry = ptr("0x009523D0");
const keyboardGate1 = ptr("0x009525F7");
const keyboardGate2 = ptr("0x0095265B");
const configPointer = ptr("0x0157D120");
const modePointer = ptr("0x0157AE00");

function safePointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}

function safeU32(address) {
    try { return address.readU32(); } catch (_) { return null; }
}

function safeString(address) {
    try {
        if (address.isNull()) return null;
        return address.readUtf8String(96);
    } catch (_) { return null; }
}

function state() {
    const config = safePointer(configPointer);
    const mode = safePointer(modePointer);
    return {
        inputMode: config.isNull() ? null : safeU32(config.add(0x15c4bc)),
        promptMode: config.isNull() ? null : safeU32(config.add(0x15c4c0)),
        splitMode: mode.isNull() ? null : safeU32(mode.add(0x8f0)),
        splitState: mode.isNull() ? null : safeU32(mode.add(0x8f4)),
        primaryAssignment: mode.isNull() ? null : safeU32(mode.add(0x8f8)),
        secondaryAssignment: mode.isNull() ? null : safeU32(mode.add(0x8fc))
    };
}

function parserInfo(context) {
    return {
        parser: context.toString(),
        owner1708: context.isNull() ? null : safeU32(context.add(0x1708)),
        owner2ac: context.isNull() ? null : safeU32(context.add(0x2ac))
    };
}

const listeners = [];
listeners.push(Interceptor.attach(parserEntry, {
    onEnter(args) {
        const context = this.context.ecx;
        send(Object.assign({
            event: "parser-entry",
            token: safeString(args[0]),
            destination: args[1].toString(),
            caller: this.returnAddress.toString()
        }, parserInfo(context), state()));
    }
}));

function traceGate(address, name) {
    listeners.push(Interceptor.attach(address, {
        onEnter() {
            const context = safePointer(this.context.esp.add(0x18));
            send(Object.assign({
                event: name,
                eax: this.context.eax.toString(),
                caller: this.returnAddress.toString()
            }, parserInfo(context), state()));
        }
    }));
}

traceGate(keyboardGate1, "keyboard-gate-1");
traceGate(keyboardGate2, "keyboard-gate-2");

rpc.exports = {
    dispose() {
        listeners.forEach(listener => listener.detach());
        send({event: "disposed"});
    }
};

send(Object.assign({event: "ready"}, state()));
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", type=str)
    args = parser.parse_args()

    output = open(args.output, "a", encoding="utf-8") if args.output else None
    session = frida.attach(args.pid)
    script = session.create_script(AGENT)
    ready = threading.Event()

    def emit(payload: object) -> None:
        row = json.dumps(payload, ensure_ascii=False)
        print(row, flush=True)
        if output:
            output.write(row + "\n")
            output.flush()

    def on_message(message: dict[str, object], _data: bytes | None) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            emit(payload)
            if isinstance(payload, dict) and payload.get("event") == "ready":
                ready.set()
        else:
            emit(message)
            ready.set()

    script.on("message", on_message)
    script.load()
    try:
        if not ready.wait(5):
            raise RuntimeError("trace did not report ready")
        print("Tutorial owner trace active; press Enter to detach.", flush=True)
        sys.stdin.readline()
    finally:
        try:
            script.exports_sync.dispose()
        finally:
            session.detach()
            if output:
                output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
