"""Temporarily replay the active pause-menu controller one viewport to the right.

This is a live-memory experiment only.  The Frida hook lives for the requested
time and restores the controller position after every replay; it does not
modify the ASI, game files, source target, or vtable slots.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import struct
import threading
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(typing, compatibility_name, getattr(typing_extensions, compatibility_name))

import frida


PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
CHUNK_SIZE = 1024 * 1024
COMMON_MENU_VTABLE = 0x013950C8 - 0x58
RENDER_ROOT_OFFSET = 0xF4
OWNER_OFFSET = 0x6C
GAME_STATE_POINTER = 0x015DE88C
SPLIT_WIDTH_OFFSET = 0x50
RESCALE_ENTRY = 0x00E18040


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def read_memory(kernel32, process, address: int, size: int) -> bytes | None:
    buffer = ctypes.create_string_buffer(size)
    transferred = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        process, ctypes.c_void_p(address), buffer, size, ctypes.byref(transferred)
    ) or transferred.value != size:
        return None
    return buffer.raw


def find_active_common_menu(pid: int) -> tuple[int, int]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t)
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        state_bytes = read_memory(kernel32, process, GAME_STATE_POINTER, 4)
        if state_bytes is None:
            raise RuntimeError("cannot read game-state pointer")
        state = struct.unpack("<I", state_bytes)[0]
        split_bytes = read_memory(kernel32, process, state + SPLIT_WIDTH_OFFSET, 4)
        if split_bytes is None:
            raise RuntimeError("cannot read live split width")
        split_width = struct.unpack("<I", split_bytes)[0]
        if split_width <= 0:
            raise RuntimeError("split screen is not active")

        pattern = struct.pack("<I", COMMON_MENU_VTABLE)
        info = MEMORY_BASIC_INFORMATION()
        address = 0
        matches: list[int] = []
        while address < 0x1_0000_0000:
            result = kernel32.VirtualQueryEx(
                process, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
            )
            if not result:
                break
            base, size = int(info.BaseAddress or 0), int(info.RegionSize)
            protection = int(info.Protect) & 0xFF
            if (
                info.State == MEM_COMMIT and info.Type == MEM_PRIVATE and
                protection in READABLE_PROTECTIONS and not (info.Protect & PAGE_GUARD)
            ):
                offset = 0
                while offset < size:
                    data = read_memory(kernel32, process, base + offset, min(CHUNK_SIZE, size - offset))
                    if data is not None:
                        start = 0
                        while True:
                            index = data.find(pattern, start)
                            if index < 0:
                                break
                            candidate = base + offset + index
                            if candidate % 4 == 0:
                                controller = read_memory(kernel32, process, candidate, RENDER_ROOT_OFFSET + 4)
                                if controller is not None:
                                    root = struct.unpack_from("<I", controller, RENDER_ROOT_OFFSET)[0]
                                    root_data = read_memory(kernel32, process, root, OWNER_OFFSET + 4) if root else None
                                    if root_data is not None and struct.unpack_from("<I", root_data, OWNER_OFFSET)[0] == candidate:
                                        matches.append(candidate)
                            start = index + 1
                    offset += CHUNK_SIZE
            next_address = base + size
            if next_address <= address:
                break
            address = next_address
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one active uGUICommonMenu, found {len(matches)}")
        return matches[0], split_width
    finally:
        kernel32.CloseHandle(process)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=40.0)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 60:
        parser.error("--seconds must be between 1 and 60")

    controller, split_width = find_active_common_menu(args.pid)
    javascript = r"""
const target = ptr("__TARGET__");
const controller = ptr("__CONTROLLER__");
const shiftX = __SHIFT_X__;
const replay = new NativeFunction(target, "void", ["pointer", "pointer", "pointer"], "fastcall");
const recursiveThreads = new Set();
let originalCalls = 0;
let replayCalls = 0;
let stopped = false;

const listener = Interceptor.attach(target, {
    onEnter() {
        const threadId = Process.getCurrentThreadId();
        this.menuThread = threadId;
        this.menuReplay = recursiveThreads.has(threadId);
        this.menuTarget = !this.menuReplay && this.context.ecx.equals(controller);
        if (!this.menuTarget)
            return;
        this.object = this.context.ecx;
        this.edx = this.context.edx;
        this.a2 = this.context.esp.add(4).readPointer();
        try {
            this.originalX = this.object.add(0x40).readFloat();
        } catch (error) {
            stopped = true;
            send({ event: "error", message: "cannot read CommonMenu X: " + String(error) });
            return;
        }
        originalCalls++;
    },
    onLeave() {
        if (!this.menuTarget || stopped)
            return;
        recursiveThreads.add(this.menuThread);
        try {
            this.object.add(0x40).writeFloat(this.originalX + shiftX);
            replay(this.object, this.edx, this.a2);
            replayCalls++;
        } catch (error) {
            stopped = true;
            send({ event: "error", message: String(error) });
        } finally {
            try { this.object.add(0x40).writeFloat(this.originalX); } catch (_) {}
            recursiveThreads.delete(this.menuThread);
        }
    }
});

setInterval(function () {
    send({ event: "counts", original: originalCalls, replay: replayCalls, stopped: stopped });
}, 500);
send({ event: "ready", controller: controller.toString(), shiftX: shiftX });
""".replace("__TARGET__", hex(RESCALE_ENTRY)).replace(
        "__CONTROLLER__", hex(controller)
    ).replace("__SHIFT_X__", repr(float(split_width)))

    session = frida.attach(args.pid)
    script = session.create_script(javascript)
    finished = threading.Event()
    latest: dict[str, object] = {}

    def on_message(message, data) -> None:
        nonlocal latest
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("event") == "ready":
                print(f"READY controller={payload['controller']} shiftX={payload['shiftX']}", flush=True)
            elif payload.get("event") == "counts":
                latest = payload
            elif payload.get("event") == "error":
                print(payload["message"], flush=True)
                finished.set()
        else:
            print(message, flush=True)
            if message.get("type") == "error":
                finished.set()

    script.on("message", on_message)
    script.load()
    try:
        finished.wait(args.seconds)
    finally:
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass
    print(latest, flush=True)
    return 0 if int(latest.get("replay", 0)) > 0 and not latest.get("stopped") else 2


if __name__ == "__main__":
    raise SystemExit(main())
