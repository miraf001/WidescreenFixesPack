"""Preserve the game-selected screen-0 camera across our W/2 rebuild.

Memory-only RE:Rev2 experiment.  It targets only the exact UpdateLayout call
inside the currently loaded FusionFix ASI and accepts only the known normal or
event camera classes.  The listener disappears when this process exits.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import threading
import time
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name, getattr(typing_extensions, compatibility_name))

ROOT = Path(__file__).resolve().parents[1]
FRIDA_PATH = ROOT / "out" / "toolchain" / "frida-17.5.1"
if FRIDA_PATH.is_dir():
    sys.path.insert(0, str(FRIDA_PATH))

import frida  # noqa: E402


SCRIPT = r"""
'use strict';

const module = Process.getModuleByName('ResidentEvilRevelations2.FusionFix.asi');
const targetedReturn = module.base.add(0x1b7a6);
const updateLayout = ptr('0x004AE570');
const normalCameraVtable = ptr('0x01264F30');
const eventCameraVtable = ptr('0x01264FE0');
let enabled = true;
let targetedCalls = 0;
let acceptedCameras = 0;
let restoredCameras = 0;
let unchangedCameras = 0;

function safePointer(address) {
    try { return address.readPointer(); } catch (_) { return NULL; }
}
function validCamera(camera) {
    if (camera.isNull()) return false;
    const vtable = safePointer(camera);
    return vtable.equals(normalCameraVtable) || vtable.equals(eventCameraVtable);
}

const listener = Interceptor.attach(updateLayout, {
    onEnter(_) {
        this.accepted = false;
        if (!enabled || !this.returnAddress.equals(targetedReturn)) return;
        targetedCalls++;
        const graphics = this.context.ecx;
        const camera = safePointer(graphics.add(0x34));
        if (!validCamera(camera)) {
            send({event: 'target.no-valid-camera', targetedCalls,
                graphics: graphics.toString(), camera: camera.toString(),
                vtable: camera.isNull() ? '0x0' : safePointer(camera).toString()});
            return;
        }
        this.accepted = true;
        this.graphics = graphics;
        this.camera = camera;
        acceptedCameras++;
        send({event: 'target.capture', targetedCalls, acceptedCameras,
            camera: camera.toString(), vtable: safePointer(camera).toString()});
    },
    onLeave(_) {
        if (!enabled || !this.accepted) return;
        if (!validCamera(this.camera)) {
            send({event: 'target.camera-expired', camera: this.camera.toString()});
            return;
        }
        const slot = this.graphics.add(0x34);
        const current = safePointer(slot);
        if (current.equals(this.camera)) {
            unchangedCameras++;
            send({event: 'target.unchanged', unchangedCameras,
                camera: current.toString()});
            return;
        }
        slot.writePointer(this.camera);
        restoredCameras++;
        send({event: 'target.restored', restoredCameras,
            overwrittenCamera: current.toString(), restoredCamera: this.camera.toString(),
            vtable: safePointer(this.camera).toString()});
    }
});

rpc.exports = {
    status() {
        return {targetedCalls, acceptedCameras, restoredCameras, unchangedCameras};
    },
    stop() {
        enabled = false;
        listener.detach();
        return {targetedCalls, acceptedCameras, restoredCameras, unchangedCameras};
    }
};

send({event: 'ready', pid: Process.id, moduleBase: module.base.toString(),
    targetedReturn: targetedReturn.toString()});
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=1200.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = args.output.open("w", encoding="utf-8", buffering=1)
    ready = threading.Event()
    detached = threading.Event()
    errors: list[dict[str, object]] = []
    session = frida.attach(args.pid)
    session.on("detached", lambda *unused: detached.set())
    script = session.create_script(SCRIPT)

    def on_message(message: dict[str, object], data: bytes | None) -> None:
        output.write(json.dumps(message, ensure_ascii=False) + "\n")
        if message.get("type") == "send":
            payload = message.get("payload", {})
            print(json.dumps(payload, ensure_ascii=False), flush=True)
            if isinstance(payload, dict) and payload.get("event") == "ready":
                ready.set()
        else:
            errors.append(message)
            print(json.dumps(message, ensure_ascii=False), flush=True)
            ready.set()

    script.on("message", on_message)
    script.load()
    if not ready.wait(5) or errors:
        raise RuntimeError("small-cutscene camera test failed to initialize")
    print(f"TEST_READY output={args.output}", flush=True)

    try:
        detached.wait(args.seconds)
    except KeyboardInterrupt:
        pass
    finally:
        if not detached.is_set():
            try:
                status = script.exports_sync.stop()
                print(json.dumps(status, ensure_ascii=False), flush=True)
            finally:
                script.unload()
                session.detach()
        output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
