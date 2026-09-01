"""Capture one RE:Rev2 D3D9 frame and summarize its draw-call signatures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
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
    parser.add_argument("--maximum-draws", type=int, default=12000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    javascript = r"""
const renderer = ptr("0x015E0388").readPointer();
const device = renderer.add(0x98).readPointer();
const vtable = device.readPointer();
const maximumDraws = %d;

function method(index, returnType, argumentTypes) {
    const address = vtable.add(index * Process.pointerSize).readPointer();
    return {
        address: address,
        call: new NativeFunction(address, returnType, argumentTypes, "stdcall")
    };
}

const getRenderTarget = method(38, "int", ["pointer", "uint", "pointer"]);
const getViewport = method(48, "int", ["pointer", "pointer"]);
const getTexture = method(64, "int", ["pointer", "uint", "pointer"]);
const getVertexDeclaration = method(88, "int", ["pointer", "pointer"]);
const getFvf = method(90, "int", ["pointer", "pointer"]);
const getVertexShader = method(93, "int", ["pointer", "pointer"]);
const getStreamSource = method(
    101, "int", ["pointer", "uint", "pointer", "pointer", "pointer"]);
const getIndices = method(105, "int", ["pointer", "pointer"]);
const getPixelShader = method(108, "int", ["pointer", "pointer"]);

const presentAddress = vtable.add(17 * Process.pointerSize).readPointer();
const drawMethods = [
    { name: "DrawPrimitive", index: 81 },
    { name: "DrawIndexedPrimitive", index: 82 },
    { name: "DrawPrimitiveUP", index: 83 },
    { name: "DrawIndexedPrimitiveUP", index: 84 }
];

const pointerOutput = Memory.alloc(Process.pointerSize);
const viewportOutput = Memory.alloc(24);
const offsetOutput = Memory.alloc(4);
const strideOutput = Memory.alloc(4);
const fvfOutput = Memory.alloc(4);
const releaseCache = new Map();
let captureState = 0;
let sequence = 0;
let truncated = false;
const signatures = new Map();

function releaseObject(object) {
    if (object.isNull())
        return;
    try {
        const address = object.readPointer().add(2 * Process.pointerSize).readPointer();
        const key = address.toString();
        let release = releaseCache.get(key);
        if (release === undefined) {
            release = new NativeFunction(address, "uint", ["pointer"], "stdcall");
            releaseCache.set(key, release);
        }
        release(object);
    } catch (_) {
    }
}

function getObject(getter, extraArgument) {
    pointerOutput.writePointer(NULL);
    const hr = extraArgument === undefined
        ? getter.call(device, pointerOutput)
        : getter.call(device, extraArgument, pointerOutput);
    return hr < 0 ? NULL : pointerOutput.readPointer();
}

function collectState() {
    getViewport.call(device, viewportOutput);
    const viewport = [
        viewportOutput.readU32(),
        viewportOutput.add(4).readU32(),
        viewportOutput.add(8).readU32(),
        viewportOutput.add(12).readU32()
    ];

    const vertexShader = getObject(getVertexShader);
    const pixelShader = getObject(getPixelShader);
    const texture = getObject(getTexture, 0);
    const renderTarget = getObject(getRenderTarget, 0);
    const declaration = getObject(getVertexDeclaration);
    const indices = getObject(getIndices);

    pointerOutput.writePointer(NULL);
    offsetOutput.writeU32(0);
    strideOutput.writeU32(0);
    const streamHr = getStreamSource.call(
        device, 0, pointerOutput, offsetOutput, strideOutput);
    const stream = streamHr < 0 ? NULL : pointerOutput.readPointer();

    fvfOutput.writeU32(0);
    getFvf.call(device, fvfOutput);

    const result = {
        viewport: viewport,
        vertexShader: vertexShader.toString(),
        pixelShader: pixelShader.toString(),
        texture0: texture.toString(),
        renderTarget: renderTarget.toString(),
        declaration: declaration.toString(),
        fvf: fvfOutput.readU32(),
        stream: stream.toString(),
        streamOffset: offsetOutput.readU32(),
        stride: strideOutput.readU32(),
        indices: indices.toString()
    };

    for (const object of [
        vertexShader, pixelShader, texture, renderTarget, declaration, stream, indices]) {
        releaseObject(object);
    }
    return result;
}

function primitiveArguments(name, args) {
    if (name === "DrawPrimitive") {
        return [args[1].toUInt32(), args[2].toUInt32(), args[3].toUInt32()];
    }
    if (name === "DrawIndexedPrimitive") {
        return [
            args[1].toUInt32(), args[2].toInt32(), args[3].toUInt32(),
            args[4].toUInt32(), args[5].toUInt32(), args[6].toUInt32()
        ];
    }
    if (name === "DrawPrimitiveUP") {
        return [args[1].toUInt32(), args[2].toUInt32(), args[4].toUInt32()];
    }
    return [
        args[1].toUInt32(), args[2].toUInt32(), args[3].toUInt32(),
        args[4].toUInt32(), args[6].toUInt32(), args[8].toUInt32()
    ];
}

const listeners = [];
for (const drawMethod of drawMethods) {
    const address = vtable.add(drawMethod.index * Process.pointerSize).readPointer();
    listeners.push(Interceptor.attach(address, {
        onEnter(args) {
            if (captureState !== 1 || !args[0].equals(device))
                return;
            if (sequence >= maximumDraws) {
                truncated = true;
                return;
            }

            const state = collectState();
            const drawArgs = primitiveArguments(drawMethod.name, args);
            const key = JSON.stringify([
                drawMethod.name, drawArgs, state.viewport, state.vertexShader,
                state.pixelShader, state.texture0, state.renderTarget,
                state.declaration, state.fvf, state.stream, state.streamOffset,
                state.stride, state.indices, this.returnAddress.toString()
            ]);
            let signature = signatures.get(key);
            if (signature === undefined) {
                signature = {
                    method: drawMethod.name,
                    arguments: drawArgs,
                    viewport: state.viewport,
                    vertexShader: state.vertexShader,
                    pixelShader: state.pixelShader,
                    texture0: state.texture0,
                    renderTarget: state.renderTarget,
                    declaration: state.declaration,
                    fvf: state.fvf,
                    stream: state.stream,
                    streamOffset: state.streamOffset,
                    stride: state.stride,
                    indices: state.indices,
                    returnAddress: this.returnAddress.toString(),
                    count: 0,
                    firstSequence: sequence,
                    lastSequence: sequence
                };
                signatures.set(key, signature);
            }
            signature.count++;
            signature.lastSequence = sequence;
            sequence++;
        }
    }));
}

const presentListener = Interceptor.attach(presentAddress, {
    onEnter(args) {
        if (!args[0].equals(device))
            return;
        if (captureState === 0) {
            captureState = 1;
            return;
        }
        if (captureState !== 1)
            return;

        captureState = 2;
        send({
            event: "frame",
            draws: sequence,
            truncated: truncated,
            signatures: Array.from(signatures.values())
        });
    }
});

send({
    event: "ready",
    device: device.toString(),
    present: presentAddress.toString(),
    draws: drawMethods.map(item => ({
        name: item.name,
        address: vtable.add(item.index * Process.pointerSize).readPointer().toString()
    }))
});
""" % args.maximum_draws

    finished = threading.Event()
    result: dict[str, object] | None = None

    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal result
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print(json.dumps(payload), flush=True)
            elif payload.get("event") == "frame":
                result = payload
                finished.set()
        else:
            print(json.dumps(message), flush=True)
            if message.get("type") == "error":
                finished.set()

    script.on("message", on_message)
    script.load()
    try:
        finished.wait(args.timeout_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()

    if result is None:
        print("No complete frame captured.", flush=True)
        return 2

    serialized = json.dumps(result, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
        print(
            f"Captured {result['draws']} draws and "
            f"{len(result['signatures'])} signatures to {args.output}.",
            flush=True,
        )
    else:
        print(serialized, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
