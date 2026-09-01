"""Find RE:Rev2 DrawPrimitive calls carrying the split-screen subtitle transform."""

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
    parser.add_argument("--maximum-hits", type=int, default=24)
    parser.add_argument("--duplicate", action="store_true")
    parser.add_argument("--full-scissor", action="store_true")
    args = parser.parse_args()

    javascript = r"""
const rendererPointer = ptr("0x015E0388");
const renderer = rendererPointer.readPointer();
const device = renderer.add(0x98).readPointer();
const vtable = device.readPointer();
const drawPrimitiveAddress = vtable.add(81 * Process.pointerSize).readPointer();
const getVertexShaderAddress = vtable.add(93 * Process.pointerSize).readPointer();
const setVertexConstantsAddress = vtable.add(94 * Process.pointerSize).readPointer();
const getVertexConstantsAddress = vtable.add(95 * Process.pointerSize).readPointer();
const getViewportAddress = vtable.add(48 * Process.pointerSize).readPointer();
const getRenderStateAddress = vtable.add(58 * Process.pointerSize).readPointer();
const getScissorRectAddress = vtable.add(76 * Process.pointerSize).readPointer();
const setScissorRectAddress = vtable.add(75 * Process.pointerSize).readPointer();
const getVertexShader = new NativeFunction(
    getVertexShaderAddress, "int", ["pointer", "pointer"], "stdcall");
const getVertexConstants = new NativeFunction(
    getVertexConstantsAddress, "int", ["pointer", "uint", "pointer", "uint"], "stdcall");
const setVertexConstants = new NativeFunction(
    setVertexConstantsAddress, "int", ["pointer", "uint", "pointer", "uint"], "stdcall");
const getViewport = new NativeFunction(
    getViewportAddress, "int", ["pointer", "pointer"], "stdcall");
const getRenderState = new NativeFunction(
    getRenderStateAddress, "int", ["pointer", "uint", "pointer"], "stdcall");
const getScissorRect = new NativeFunction(
    getScissorRectAddress, "int", ["pointer", "pointer"], "stdcall");
const setScissorRect = new NativeFunction(
    setScissorRectAddress, "int", ["pointer", "pointer"], "stdcall");
const drawPrimitive = new NativeFunction(
    drawPrimitiveAddress, "int", ["pointer", "uint", "uint", "uint"], "stdcall");
const constants = Memory.alloc(64 * 16);
const shaderOutput = Memory.alloc(Process.pointerSize);
const viewportOutput = Memory.alloc(24);
const scissorEnabledOutput = Memory.alloc(4);
const scissorOutput = Memory.alloc(16);
const fullScissor = Memory.alloc(16);
fullScissor.writeS32(0);
fullScissor.add(4).writeS32(0);
fullScissor.add(8).writeS32(1920);
fullScissor.add(12).writeS32(1080);
const maximumHits = %d;
const duplicate = %s;
const useFullScissor = %s;
let hitCount = 0;
let duplicateInProgress = false;

function closeTo(value, target, epsilon) {
    return Math.abs(value - target) <= epsilon;
}

const listener = Interceptor.attach(drawPrimitiveAddress, {
    onEnter(args) {
        if (duplicateInProgress || hitCount >= maximumHits || !args[0].equals(device))
            return;

        const hr = getVertexConstants(device, 0, constants, 64);
        if (hr < 0)
            return;

        for (let registerIndex = 0; registerIndex < 64; registerIndex++) {
            const row = constants.add(registerIndex * 16);
            const xScale = row.readFloat();
            const yScale = row.add(4).readFloat();
            const xTranslation = row.add(8).readFloat();
            const yTranslation = row.add(12).readFloat();
            if (!closeTo(xScale, 0.0013020834, 0.00001) ||
                !closeTo(yScale, -0.0018518518, 0.00001) ||
                !(closeTo(xTranslation, -0.8333333, 0.02) ||
                  closeTo(xTranslation, 0.16666669, 0.02)))
                continue;

            shaderOutput.writePointer(NULL);
            getVertexShader(device, shaderOutput);
            const shader = shaderOutput.readPointer();
            getViewport(device, viewportOutput);
            const viewport = [
                viewportOutput.readU32(),
                viewportOutput.add(4).readU32(),
                viewportOutput.add(8).readU32(),
                viewportOutput.add(12).readU32()
            ];
            getRenderState(device, 174, scissorEnabledOutput);
            getScissorRect(device, scissorOutput);
            const scissorEnabled = scissorEnabledOutput.readU32();
            const scissor = [
                scissorOutput.readS32(),
                scissorOutput.add(4).readS32(),
                scissorOutput.add(8).readS32(),
                scissorOutput.add(12).readS32()
            ];

            let duplicated = false;
            if (duplicate && viewport[0] === 0 && viewport[1] === 0 &&
                viewport[2] === 1920 && viewport[3] === 1080) {
                const shifted = Memory.alloc(16);
                shifted.writeFloat(xScale);
                shifted.add(4).writeFloat(yScale);
                shifted.add(8).writeFloat(xTranslation + 1.0);
                shifted.add(12).writeFloat(yTranslation);
                setVertexConstants(device, registerIndex, shifted, 1);
                if (useFullScissor)
                    setScissorRect(device, fullScissor);
                duplicateInProgress = true;
                drawPrimitive(
                    device, args[1].toUInt32(), args[2].toUInt32(), args[3].toUInt32());
                duplicateInProgress = false;
                if (useFullScissor)
                    setScissorRect(device, scissorOutput);
                setVertexConstants(device, registerIndex, row, 1);
                duplicated = true;
            }

            hitCount++;
            send({
                event: "subtitle-draw",
                hit: hitCount,
                drawPrimitive: drawPrimitiveAddress.toString(),
                primitiveType: args[1].toUInt32(),
                startVertex: args[2].toUInt32(),
                primitiveCount: args[3].toUInt32(),
                register: registerIndex,
                constants: [xScale, yScale, xTranslation, yTranslation],
                viewport: viewport,
                scissorEnabled: scissorEnabled,
                scissor: scissor,
                duplicated: duplicated,
                vertexShader: shader.toString(),
                returnAddress: this.returnAddress.toString()
            });
            if (hitCount >= maximumHits)
                listener.detach();
            break;
        }
    }
});

send({
    event: "ready",
    device: device.toString(),
    drawPrimitive: drawPrimitiveAddress.toString(),
    getVertexConstants: getVertexConstantsAddress.toString()
});
""" % (
        args.maximum_hits,
        "true" if args.duplicate else "false",
        "true" if args.full_scissor else "false",
    )

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
                print(json.dumps(payload), flush=True)
            elif payload.get("event") == "subtitle-draw":
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

    print(f"Captured subtitle draws: {captured}", flush=True)
    return 0 if captured else 2


if __name__ == "__main__":
    raise SystemExit(main())
