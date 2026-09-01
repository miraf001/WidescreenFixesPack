"""Link the RE:Rev2 subtitle transform upload to its following D3D9 draw call."""

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
    parser.add_argument("--maximum-hits", type=int, default=8)
    parser.add_argument("--report-limit", type=int, default=8)
    parser.add_argument("--following-draws", type=int, default=1)
    parser.add_argument("--duplicate-right-viewport", action="store_true")
    parser.add_argument("--inspect-vertices", action="store_true")
    args = parser.parse_args()

    javascript = r"""
const renderer = ptr("0x015E0388").readPointer();
const device = renderer.add(0x98).readPointer();
const vtable = device.readPointer();
const maximumHits = %d;
const reportLimit = %d;
const followingDraws = %d;
const duplicateRightViewport = %s;
const inspectVertices = %s;
const setConstantsAddress = vtable.add(94 * Process.pointerSize).readPointer();
const setViewportAddress = vtable.add(47 * Process.pointerSize).readPointer();
const getViewportAddress = vtable.add(48 * Process.pointerSize).readPointer();
const getRenderTargetAddress = vtable.add(38 * Process.pointerSize).readPointer();
const getRenderStateAddress = vtable.add(58 * Process.pointerSize).readPointer();
const setRenderStateAddress = vtable.add(57 * Process.pointerSize).readPointer();
const getScissorRectAddress = vtable.add(76 * Process.pointerSize).readPointer();
const getVertexShaderAddress = vtable.add(93 * Process.pointerSize).readPointer();
const getPixelShaderAddress = vtable.add(108 * Process.pointerSize).readPointer();
const getTextureAddress = vtable.add(64 * Process.pointerSize).readPointer();
const getStreamSourceAddress = vtable.add(101 * Process.pointerSize).readPointer();
const getIndicesAddress = vtable.add(105 * Process.pointerSize).readPointer();
const getViewport = new NativeFunction(
    getViewportAddress, "int", ["pointer", "pointer"], "stdcall");
const getRenderTarget = new NativeFunction(
    getRenderTargetAddress, "int", ["pointer", "uint", "pointer"], "stdcall");
const getRenderState = new NativeFunction(
    getRenderStateAddress, "int", ["pointer", "uint", "pointer"], "stdcall");
const setRenderState = new NativeFunction(
    setRenderStateAddress, "int", ["pointer", "uint", "uint"], "stdcall");
const getScissorRect = new NativeFunction(
    getScissorRectAddress, "int", ["pointer", "pointer"], "stdcall");
const setViewport = new NativeFunction(
    setViewportAddress, "int", ["pointer", "pointer"], "stdcall");
const getVertexShader = new NativeFunction(
    getVertexShaderAddress, "int", ["pointer", "pointer"], "stdcall");
const getPixelShader = new NativeFunction(
    getPixelShaderAddress, "int", ["pointer", "pointer"], "stdcall");
const getTexture = new NativeFunction(
    getTextureAddress, "int", ["pointer", "uint", "pointer"], "stdcall");
const getStreamSource = new NativeFunction(
    getStreamSourceAddress, "int",
    ["pointer", "uint", "pointer", "pointer", "pointer"], "stdcall");
const getIndices = new NativeFunction(
    getIndicesAddress, "int", ["pointer", "pointer"], "stdcall");
const viewportOutput = Memory.alloc(24);
const pointerOutput = Memory.alloc(Process.pointerSize);
const streamOffsetOutput = Memory.alloc(4);
const strideOutput = Memory.alloc(4);
const duplicateViewport = Memory.alloc(24);
const surfaceDescription = Memory.alloc(32);
const renderStateOutput = Memory.alloc(4);
const scissorOutput = Memory.alloc(16);
const pending = new Map();
let hitCount = 0;
let duplicateInProgress = false;

function closeTo(value, target, epsilon) {
    return Math.abs(value - target) <= epsilon;
}

function releaseObject(object) {
    if (object.isNull())
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

function getObject(getter, extraArgument) {
    pointerOutput.writePointer(NULL);
    const hr = extraArgument === undefined
        ? getter(device, pointerOutput)
        : getter(device, extraArgument, pointerOutput);
    return hr < 0 ? NULL : pointerOutput.readPointer();
}

function drawArguments(name, args) {
    if (name === "DrawPrimitive")
        return [args[1].toUInt32(), args[2].toUInt32(), args[3].toUInt32()];
    if (name === "DrawIndexedPrimitive") {
        return [
            args[1].toUInt32(), args[2].toInt32(), args[3].toUInt32(),
            args[4].toUInt32(), args[5].toUInt32(), args[6].toUInt32()
        ];
    }
    if (name === "DrawPrimitiveUP")
        return [args[1].toUInt32(), args[2].toUInt32(), args[4].toUInt32()];
    return [
        args[1].toUInt32(), args[2].toUInt32(), args[3].toUInt32(),
        args[4].toUInt32(), args[6].toUInt32(), args[8].toUInt32()
    ];
}

function inspectIndexedGeometry(args, stream, streamOffset, stride) {
    if (!inspectVertices || stream.isNull() || stride === 0)
        return null;

    const indices = getObject(getIndices);
    if (indices.isNull())
        return { error: "no-index-buffer" };

    const indexDescription = Memory.alloc(20);
    const indexPointerOutput = Memory.alloc(Process.pointerSize);
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

    const formatHr = getIndexDescription(indices, indexDescription);
    const format = formatHr < 0 ? 0 : indexDescription.readU32();
    const indexSize = format === 101 ? 2 : (format === 102 ? 4 : 0);
    const primitiveType = args[1].toUInt32();
    const primitiveCount = args[6].toUInt32();
    const indexCount = primitiveType === 5 ? primitiveCount + 2 : primitiveCount * 3;
    const startIndex = args[5].toUInt32();
    if (indexSize === 0 || indexCount === 0 || indexCount > 4096) {
        releaseObject(indices);
        return { error: "unsupported-index-buffer", format: format, count: indexCount };
    }

    indexPointerOutput.writePointer(NULL);
    const indexLockHr = lockIndices(
        indices, startIndex * indexSize, indexCount * indexSize,
        indexPointerOutput, 0x10);
    if (indexLockHr < 0) {
        releaseObject(indices);
        return { error: "index-lock", hr: indexLockHr };
    }

    const indexData = indexPointerOutput.readPointer();
    const usedIndices = [];
    let minimumIndex = 0xffffffff;
    let maximumIndex = 0;
    for (let index = 0; index < indexCount; index++) {
        const value = indexSize === 2
            ? indexData.add(index * 2).readU16()
            : indexData.add(index * 4).readU32();
        usedIndices.push(value);
        minimumIndex = Math.min(minimumIndex, value);
        maximumIndex = Math.max(maximumIndex, value);
    }
    unlockIndices(indices);
    releaseObject(indices);

    const baseVertexIndex = args[2].toInt32();
    const firstVertex = baseVertexIndex + minimumIndex;
    const vertexCount = maximumIndex - minimumIndex + 1;
    if (firstVertex < 0 || vertexCount > 100000)
        return { error: "vertex-range", first: firstVertex, count: vertexCount };

    const vertexPointerOutput = Memory.alloc(Process.pointerSize);
    const streamVtable = stream.readPointer();
    const lockVertices = new NativeFunction(
        streamVtable.add(11 * Process.pointerSize).readPointer(),
        "int", ["pointer", "uint", "uint", "pointer", "uint"], "stdcall");
    const unlockVertices = new NativeFunction(
        streamVtable.add(12 * Process.pointerSize).readPointer(),
        "int", ["pointer"], "stdcall");
    vertexPointerOutput.writePointer(NULL);
    const vertexOffset = streamOffset + firstVertex * stride;
    const vertexLockHr = lockVertices(
        stream, vertexOffset, vertexCount * stride, vertexPointerOutput, 0x10);
    if (vertexLockHr < 0)
        return { error: "vertex-lock", hr: vertexLockHr };

    const vertexData = vertexPointerOutput.readPointer();
    const uniqueIndices = Array.from(new Set(usedIndices));
    const componentCount = Math.floor(stride / 4);
    const minimum = new Array(componentCount).fill(Number.POSITIVE_INFINITY);
    const maximum = new Array(componentCount).fill(Number.NEGATIVE_INFINITY);
    const samples = [];
    for (const vertexIndex of uniqueIndices) {
        const vertex = vertexData.add((vertexIndex - minimumIndex) * stride);
        const values = [];
        for (let component = 0; component < componentCount; component++) {
            const value = vertex.add(component * 4).readFloat();
            values.push(value);
            if (Number.isFinite(value)) {
                minimum[component] = Math.min(minimum[component], value);
                maximum[component] = Math.max(maximum[component], value);
            }
        }
        if (samples.length < 12)
            samples.push({ index: vertexIndex, values: values });
    }
    unlockVertices(stream);

    return {
        format: format,
        indexSize: indexSize,
        indexCount: indexCount,
        uniqueVertices: uniqueIndices.length,
        indexRange: [minimumIndex, maximumIndex],
        vertexOffset: vertexOffset,
        stride: stride,
        componentMinimum: minimum,
        componentMaximum: maximum,
        samples: samples
    };
}

const setListener = Interceptor.attach(setConstantsAddress, {
    onEnter(args) {
        if (hitCount >= maximumHits || !args[0].equals(device))
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

            const threadId = Process.getCurrentThreadId();
            pending.set(threadId, {
                remaining: followingDraws,
                register: startRegister + vectorIndex,
                constants: values,
                setReturnAddress: this.returnAddress.toString(),
                setBacktrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 12).map(DebugSymbol.fromAddress).map(String)
            });
            break;
        }
    }
});

const drawMethods = [
    { name: "DrawPrimitive", index: 81 },
    { name: "DrawIndexedPrimitive", index: 82 },
    { name: "DrawPrimitiveUP", index: 83 },
    { name: "DrawIndexedPrimitiveUP", index: 84 }
];
const drawListeners = [];
for (const drawMethod of drawMethods) {
    const drawAddress = vtable.add(drawMethod.index * Process.pointerSize).readPointer();
    drawListeners.push(Interceptor.attach(drawAddress, {
        onEnter(args) {
            if (duplicateInProgress || hitCount >= maximumHits || !args[0].equals(device))
                return;
            const threadId = Process.getCurrentThreadId();
            const marker = pending.get(threadId);
            if (marker === undefined)
                return;
            marker.remaining--;
            if (marker.remaining > 0)
                pending.set(threadId, marker);
            else
                pending.delete(threadId);

            getViewport(device, viewportOutput);
            const vertexShader = getObject(getVertexShader);
            const pixelShader = getObject(getPixelShader);
            const texture = getObject(getTexture, 0);
            const renderTarget = getObject(getRenderTarget, 0);
            let renderTargetSize = [0, 0];
            if (!renderTarget.isNull()) {
                try {
                    const getDescriptionAddress = renderTarget.readPointer()
                        .add(12 * Process.pointerSize).readPointer();
                    const getDescription = new NativeFunction(
                        getDescriptionAddress, "int", ["pointer", "pointer"], "stdcall");
                    if (getDescription(renderTarget, surfaceDescription) >= 0) {
                        renderTargetSize = [
                            surfaceDescription.add(24).readU32(),
                            surfaceDescription.add(28).readU32()
                        ];
                    }
                } catch (_) {
                }
            }
            pointerOutput.writePointer(NULL);
            streamOffsetOutput.writeU32(0);
            strideOutput.writeU32(0);
            getStreamSource(
                device, 0, pointerOutput, streamOffsetOutput, strideOutput);
            const stream = pointerOutput.readPointer();
            const geometry = drawMethod.name === "DrawIndexedPrimitive"
                ? inspectIndexedGeometry(
                    args, stream, streamOffsetOutput.readU32(), strideOutput.readU32())
                : null;
            getRenderState(device, 174, renderStateOutput);
            const scissorEnabled = renderStateOutput.readU32();
            getScissorRect(device, scissorOutput);
            const scissor = [
                scissorOutput.readS32(), scissorOutput.add(4).readS32(),
                scissorOutput.add(8).readS32(), scissorOutput.add(12).readS32()
            ];
            getRenderState(device, 152, renderStateOutput);
            const clipPlaneMask = renderStateOutput.readU32();
            getRenderState(device, 52, renderStateOutput);
            const stencilEnabled = renderStateOutput.readU32();
            getRenderState(device, 7, renderStateOutput);
            const depthEnabled = renderStateOutput.readU32();

            let duplicated = false;
            let duplicateViewportResult = 0;
            let duplicateDrawResult = 0;
            if (duplicateRightViewport &&
                drawMethod.name === "DrawIndexedPrimitive" &&
                viewportOutput.readU32() === 0 &&
                viewportOutput.add(4).readU32() === 0 &&
                viewportOutput.add(8).readU32() === 960 &&
                viewportOutput.add(12).readU32() === 1080) {
                Memory.copy(duplicateViewport, viewportOutput, 24);
                duplicateViewport.writeU32(960);
                duplicateViewportResult = setViewport(device, duplicateViewport);
                setRenderState(device, 52, 0);
                const duplicateDraw = new NativeFunction(
                    drawAddress, "int",
                    ["pointer", "uint", "int", "uint", "uint", "uint", "uint"],
                    "stdcall");
                duplicateInProgress = true;
                duplicateDrawResult = duplicateDraw(
                    device, args[1].toUInt32(), args[2].toInt32(),
                    args[3].toUInt32(), args[4].toUInt32(),
                    args[5].toUInt32(), args[6].toUInt32());
                duplicateInProgress = false;
                setRenderState(device, 52, stencilEnabled);
                setViewport(device, viewportOutput);
                duplicated = true;
            }

            hitCount++;
            if (hitCount <= reportLimit) send({
                event: "subtitle-command",
                hit: hitCount,
                register: marker.register,
                constants: marker.constants,
                setReturnAddress: marker.setReturnAddress,
                setBacktrace: marker.setBacktrace,
                method: drawMethod.name,
                drawAddress: drawAddress.toString(),
                drawArguments: drawArguments(drawMethod.name, args),
                drawReturnAddress: this.returnAddress.toString(),
                drawBacktrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0, 12).map(DebugSymbol.fromAddress).map(String),
                viewport: [
                    viewportOutput.readU32(), viewportOutput.add(4).readU32(),
                    viewportOutput.add(8).readU32(), viewportOutput.add(12).readU32()
                ],
                vertexShader: vertexShader.toString(),
                pixelShader: pixelShader.toString(),
                texture0: texture.toString(),
                renderTarget: renderTarget.toString(),
                renderTargetSize: renderTargetSize,
                stream: stream.toString(),
                streamOffset: streamOffsetOutput.readU32(),
                stride: strideOutput.readU32()
                ,duplicated: duplicated,
                duplicateViewportResult: duplicateViewportResult,
                duplicateDrawResult: duplicateDrawResult,
                scissorEnabled: scissorEnabled,
                scissor: scissor,
                clipPlaneMask: clipPlaneMask,
                stencilEnabled: stencilEnabled,
                depthEnabled: depthEnabled
                ,geometry: geometry
            });

            for (const object of [
                vertexShader, pixelShader, texture, renderTarget, stream])
                releaseObject(object);
        }
    }));
}

send({
    event: "ready",
    device: device.toString(),
    setConstants: setConstantsAddress.toString()
});
""" % (
        args.maximum_hits,
        args.report_limit,
        args.following_draws,
        "true" if args.duplicate_right_viewport else "false",
        "true" if args.inspect_vertices else "false",
    )

    finished = threading.Event()
    captured = 0
    session = frida.attach(args.pid)
    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        nonlocal captured
        if message.get("type") == "send":
            payload = message.get("payload", {})
            print(json.dumps(payload), flush=True)
            if payload.get("event") == "subtitle-command":
                captured += 1
                if captured >= args.maximum_hits:
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

    print(f"Captured subtitle commands: {captured}", flush=True)
    return 0 if captured else 2


if __name__ == "__main__":
    raise SystemExit(main())
