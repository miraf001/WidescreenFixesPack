"""Replay RE:Rev2 subtitle batches over the final D3D9 backbuffer."""

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
const renderer = ptr("0x015E0388").readPointer();
const device = renderer.add(0x98).readPointer();
const vtable = device.readPointer();

function deviceMethod(index, returnType, argumentTypes) {
    const address = vtable.add(index * Process.pointerSize).readPointer();
    return {
        address: address,
        call: new NativeFunction(address, returnType, argumentTypes, "stdcall")
    };
}

const getBackBuffer = deviceMethod(
    18, "int", ["pointer", "uint", "uint", "uint", "pointer"]);
const setRenderTarget = deviceMethod(37, "int", ["pointer", "uint", "pointer"]);
const getRenderTarget = deviceMethod(38, "int", ["pointer", "uint", "pointer"]);
const setDepthStencil = deviceMethod(39, "int", ["pointer", "pointer"]);
const getDepthStencil = deviceMethod(40, "int", ["pointer", "pointer"]);
const setViewport = deviceMethod(47, "int", ["pointer", "pointer"]);
const getViewport = deviceMethod(48, "int", ["pointer", "pointer"]);
const setRenderState = deviceMethod(57, "int", ["pointer", "uint", "uint"]);
const createStateBlock = deviceMethod(59, "int", ["pointer", "uint", "pointer"]);
const setVertexDeclaration = deviceMethod(87, "int", ["pointer", "pointer"]);
const getVertexDeclaration = deviceMethod(88, "int", ["pointer", "pointer"]);
const getStreamSource = deviceMethod(
    101, "int", ["pointer", "uint", "pointer", "pointer", "pointer"]);
const getIndices = deviceMethod(105, "int", ["pointer", "pointer"]);

const setConstantsAddress = vtable.add(94 * Process.pointerSize).readPointer();
const drawIndexedAddress = vtable.add(82 * Process.pointerSize).readPointer();
const drawIndexedUpAddress = vtable.add(84 * Process.pointerSize).readPointer();
const endSceneAddress = vtable.add(42 * Process.pointerSize).readPointer();
const drawIndexedUp = new NativeFunction(
    drawIndexedUpAddress, "int",
    ["pointer", "uint", "uint", "uint", "uint", "pointer", "uint",
     "pointer", "uint"], "stdcall");

const pointerOutput = Memory.alloc(Process.pointerSize);
const viewportOutput = Memory.alloc(24);
const rightViewport = Memory.alloc(24);
const offsetOutput = Memory.alloc(4);
const strideOutput = Memory.alloc(4);
const pending = new Map();
let captured = [];
let replayInProgress = false;
let replayCount = 0;
let firstFailure = null;

function closeTo(value, target, epsilon) {
    return Math.abs(value - target) <= epsilon;
}

function releaseObject(object) {
    if (object === null || object === undefined || object.isNull())
        return;
    try {
        const releaseAddress = object.readPointer()
            .add(2 * Process.pointerSize).readPointer();
        const release = new NativeFunction(
            releaseAddress, "uint", ["pointer"], "stdcall");
        release(object);
    } catch (_) {
    }
}

function stateBlockApply(block) {
    const applyAddress = block.readPointer()
        .add(5 * Process.pointerSize).readPointer();
    return new NativeFunction(
        applyAddress, "int", ["pointer"], "stdcall")(block);
}

function releaseCapture(capture) {
    if (capture === undefined)
        return;
    for (const object of [
        capture.stateBlock, capture.vertexDeclaration, capture.renderTarget]) {
        releaseObject(object);
    }
}

function clearCaptured() {
    for (const capture of captured)
        releaseCapture(capture);
    captured = [];
}

function copyIndexedGeometry(args, stream, streamOffset, stride, indices) {
    const primitiveType = args[1].toUInt32();
    const baseVertexIndex = args[2].toInt32();
    const startIndex = args[5].toUInt32();
    const primitiveCount = args[6].toUInt32();
    const indexCount = primitiveType === 5 ? primitiveCount + 2 : primitiveCount * 3;
    if (indexCount === 0 || indexCount > 4096 || stride === 0)
        return null;

    const indexDescription = Memory.alloc(20);
    const lockedOutput = Memory.alloc(Process.pointerSize);
    const indexVtable = indices.readPointer();
    const getIndexDescription = new NativeFunction(
        indexVtable.add(13 * Process.pointerSize).readPointer(),
        "int", ["pointer", "pointer"], "stdcall");
    const lockIndices = new NativeFunction(
        indexVtable.add(11 * Process.pointerSize).readPointer(),
        "int", ["pointer", "uint", "uint", "pointer", "uint"], "stdcall");
    const unlockIndices = new NativeFunction(
        indexVtable.add(12 * Process.pointerSize).readPointer(),
        "int", ["pointer"], "stdcall");
    if (getIndexDescription(indices, indexDescription) < 0)
        return null;
    const indexFormat = indexDescription.readU32();
    const indexSize = indexFormat === 101 ? 2 : (indexFormat === 102 ? 4 : 0);
    if (indexSize === 0)
        return null;

    lockedOutput.writePointer(NULL);
    if (lockIndices(
            indices, startIndex * indexSize, indexCount * indexSize,
            lockedOutput, 0x10) < 0)
        return null;
    const lockedIndices = lockedOutput.readPointer();
    const indexData = Memory.alloc(indexCount * indexSize);
    let minimumIndex = 0xffffffff;
    let maximumIndex = 0;
    for (let index = 0; index < indexCount; index++) {
        const value = indexSize === 2
            ? lockedIndices.add(index * 2).readU16()
            : lockedIndices.add(index * 4).readU32();
        minimumIndex = Math.min(minimumIndex, value);
        maximumIndex = Math.max(maximumIndex, value);
        if (indexSize === 2)
            indexData.add(index * 2).writeU16(value);
        else
            indexData.add(index * 4).writeU32(value);
    }
    unlockIndices(indices);

    const firstVertex = baseVertexIndex + minimumIndex;
    const vertexCount = maximumIndex - minimumIndex + 1;
    if (firstVertex < 0 || vertexCount === 0 || vertexCount > 100000)
        return null;

    const streamVtable = stream.readPointer();
    const lockVertices = new NativeFunction(
        streamVtable.add(11 * Process.pointerSize).readPointer(),
        "int", ["pointer", "uint", "uint", "pointer", "uint"], "stdcall");
    const unlockVertices = new NativeFunction(
        streamVtable.add(12 * Process.pointerSize).readPointer(),
        "int", ["pointer"], "stdcall");
    lockedOutput.writePointer(NULL);
    const vertexBytes = vertexCount * stride;
    if (lockVertices(
            stream, streamOffset + firstVertex * stride, vertexBytes,
            lockedOutput, 0x10) < 0)
        return null;
    const vertexData = Memory.alloc(vertexBytes);
    Memory.copy(vertexData, lockedOutput.readPointer(), vertexBytes);
    unlockVertices(stream);

    if (minimumIndex !== 0) {
        for (let index = 0; index < indexCount; index++) {
            if (indexSize === 2)
                indexData.add(index * 2).writeU16(
                    indexData.add(index * 2).readU16() - minimumIndex);
            else
                indexData.add(index * 4).writeU32(
                    indexData.add(index * 4).readU32() - minimumIndex);
        }
    }

    return {
        primitiveType: primitiveType,
        primitiveCount: primitiveCount,
        indexData: indexData,
        indexFormat: indexFormat,
        vertexData: vertexData,
        vertexCount: vertexCount,
        stride: stride
    };
}

Interceptor.attach(setConstantsAddress, {
    onEnter(args) {
        if (replayInProgress || !args[0].equals(device))
            return;
        const startRegister = args[1].toUInt32();
        const data = args[2];
        const vectorCount = args[3].toUInt32();
        if (data.isNull() || vectorCount > 256)
            return;

        for (let vectorIndex = 0; vectorIndex < vectorCount; vectorIndex++) {
            const row = data.add(vectorIndex * 16);
            let values;
            try {
                values = [
                    row.readFloat(), row.add(4).readFloat(),
                    row.add(8).readFloat(), row.add(12).readFloat()
                ];
            } catch (_) {
                return;
            }
            if (!closeTo(values[0], 0.0013020834, 0.00001) ||
                !closeTo(values[1], -0.0018518518, 0.00001) ||
                !closeTo(values[2], 0.16666669, 0.02) ||
                !closeTo(values[3], 2.0, 0.02)) {
                continue;
            }

            clearCaptured();
            pending.set(Process.getCurrentThreadId(), 2);
            break;
        }
    }
});

Interceptor.attach(drawIndexedAddress, {
    onEnter(args) {
        if (replayInProgress || !args[0].equals(device))
            return;
        const threadId = Process.getCurrentThreadId();
        let remaining = pending.get(threadId);
        if (remaining === undefined)
            return;

        getViewport.call(device, viewportOutput);
        if (viewportOutput.readU32() !== 0 ||
            viewportOutput.add(4).readU32() !== 0 ||
            viewportOutput.add(8).readU32() !== 960 ||
            viewportOutput.add(12).readU32() !== 1080) {
            pending.delete(threadId);
            clearCaptured();
            return;
        }

        pointerOutput.writePointer(NULL);
        const stateHr = createStateBlock.call(device, 1, pointerOutput);
        const stateBlock = stateHr < 0 ? NULL : pointerOutput.readPointer();

        pointerOutput.writePointer(NULL);
        getVertexDeclaration.call(device, pointerOutput);
        const vertexDeclaration = pointerOutput.readPointer();

        pointerOutput.writePointer(NULL);
        offsetOutput.writeU32(0);
        strideOutput.writeU32(0);
        getStreamSource.call(
            device, 0, pointerOutput, offsetOutput, strideOutput);
        const stream = pointerOutput.readPointer();

        pointerOutput.writePointer(NULL);
        getIndices.call(device, pointerOutput);
        const indices = pointerOutput.readPointer();

        pointerOutput.writePointer(NULL);
        getRenderTarget.call(device, 0, pointerOutput);
        const renderTarget = pointerOutput.readPointer();

        const geometry = stream.isNull() || indices.isNull()
            ? null
            : copyIndexedGeometry(
                args, stream, offsetOutput.readU32(), strideOutput.readU32(), indices);

        if (stateBlock.isNull() || vertexDeclaration.isNull() ||
            renderTarget.isNull() || geometry === null) {
            for (const object of [
                stateBlock, vertexDeclaration, stream, indices, renderTarget])
                releaseObject(object);
            pending.delete(threadId);
            clearCaptured();
            firstFailure = firstFailure || "capture-state";
            return;
        }

        captured.push({
            stateBlock: stateBlock,
            vertexDeclaration: vertexDeclaration,
            renderTarget: renderTarget,
            geometry: geometry
        });
        releaseObject(stream);
        releaseObject(indices);

        remaining--;
        if (remaining > 0)
            pending.set(threadId, remaining);
        else
            pending.delete(threadId);
    }
});

Interceptor.attach(endSceneAddress, {
    onEnter(args) {
        if (replayInProgress || !args[0].equals(device) || captured.length !== 2)
            return;

        replayInProgress = true;
        pointerOutput.writePointer(NULL);
        const restoreStateHr = createStateBlock.call(device, 1, pointerOutput);
        const restoreState = restoreStateHr < 0 ? NULL : pointerOutput.readPointer();

        pointerOutput.writePointer(NULL);
        getRenderTarget.call(device, 0, pointerOutput);
        const originalRenderTarget = pointerOutput.readPointer();
        pointerOutput.writePointer(NULL);
        getDepthStencil.call(device, pointerOutput);
        const originalDepthStencil = pointerOutput.readPointer();
        pointerOutput.writePointer(NULL);
        const backBufferHr = getBackBuffer.call(device, 0, 0, 0, pointerOutput);
        const backBuffer = backBufferHr < 0 ? NULL : pointerOutput.readPointer();

        let replayHr = -1;
        if (!restoreState.isNull() && !backBuffer.isNull()) {
            replayHr = 0;
            for (const capture of captured) {
                replayHr |= stateBlockApply(capture.stateBlock);
                replayHr |= setRenderTarget.call(device, 0, capture.renderTarget);
                replayHr |= setDepthStencil.call(device, NULL);
                Memory.copy(rightViewport, viewportOutput, 24);
                rightViewport.writeU32(960);
                rightViewport.add(4).writeU32(0);
                rightViewport.add(8).writeU32(960);
                rightViewport.add(12).writeU32(1080);
                rightViewport.add(16).writeFloat(0.0);
                rightViewport.add(20).writeFloat(1.0);
                replayHr |= setViewport.call(device, rightViewport);
                replayHr |= setRenderState.call(device, 7, 0);
                replayHr |= setRenderState.call(device, 52, 0);
                replayHr |= setRenderState.call(device, 152, 0);
                replayHr |= setRenderState.call(device, 174, 0);
                replayHr |= setVertexDeclaration.call(
                    device, capture.vertexDeclaration);
                const geometry = capture.geometry;
                replayHr |= drawIndexedUp(
                    device, geometry.primitiveType, 0, geometry.vertexCount,
                    geometry.primitiveCount, geometry.indexData,
                    geometry.indexFormat, geometry.vertexData, geometry.stride);
            }

            replayHr |= stateBlockApply(restoreState);
            if (!originalRenderTarget.isNull())
                replayHr |= setRenderTarget.call(device, 0, originalRenderTarget);
            replayHr |= setDepthStencil.call(device, originalDepthStencil);
        } else {
            firstFailure = firstFailure || "end-scene-state";
        }

        releaseObject(restoreState);
        releaseObject(originalRenderTarget);
        releaseObject(originalDepthStencil);
        releaseObject(backBuffer);
        clearCaptured();
        replayInProgress = false;
        replayCount++;

        if (replayCount <= 3) {
            send({
                event: "overlay-replay",
                replay: replayCount,
                result: replayHr,
                failure: firstFailure,
                endScene: endSceneAddress.toString(),
                backBuffer: backBuffer.toString()
            });
        }
    }
});

send({
    event: "ready",
    device: device.toString(),
    drawIndexed: drawIndexedAddress.toString(),
    endScene: endSceneAddress.toString()
});
"""

    session = frida.attach(args.pid)
    script = session.create_script(javascript)
    finished = threading.Event()
    replayed = 0

    def on_message(message, data) -> None:
        nonlocal replayed
        if message.get("type") == "send":
            payload = message.get("payload", {})
            print(json.dumps(payload), flush=True)
            if payload.get("event") == "overlay-replay":
                replayed += 1
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

    print(f"Overlay replay reports: {replayed}", flush=True)
    return 0 if replayed else 2


if __name__ == "__main__":
    raise SystemExit(main())
