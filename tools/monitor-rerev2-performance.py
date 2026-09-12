"""Low-overhead long-running RE:Rev2 Present/CPU/memory monitor.

The target is never mutated.  One Frida callback records each D3D9 Present
timestamp and emits an aggregate sample at a configurable interval.  Process
metrics are collected out of process when an aggregate arrives.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
from pathlib import Path
import queue
import sys
import threading
import time
import typing

import typing_extensions


for compatibility_name in ("NotRequired", "Required"):
    if not hasattr(typing, compatibility_name):
        setattr(
            typing,
            compatibility_name,
            getattr(typing_extensions, compatibility_name),
        )


ROOT = Path(__file__).resolve().parents[1]
FRIDA_PATH = ROOT / "out" / "toolchain" / "frida-17.5.1"
if FRIDA_PATH.is_dir():
    sys.path.insert(0, str(FRIDA_PATH))

import frida  # noqa: E402


PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010


class FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    def ticks(self) -> int:
        return (int(self.high) << 32) | int(self.low)


class ProcessMemoryCountersEx(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class ProcessMetrics:
    def __init__(self, pid: int) -> None:
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
        ]
        self.kernel32.GetProcessTimes.restype = wintypes.BOOL
        self.kernel32.GetProcessHandleCount.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.kernel32.GetProcessHandleCount.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCountersEx),
            wintypes.DWORD,
        ]
        self.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        self.handle = self.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self.logical_processors = max(1, int(ctypes.windll.kernel32.GetActiveProcessorCount(0xFFFF)))
        self.last_wall = time.monotonic()
        self.last_cpu = self._cpu_seconds()

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None

    def _cpu_seconds(self) -> float:
        creation = FileTime()
        exit_time = FileTime()
        kernel = FileTime()
        user = FileTime()
        if not self.kernel32.GetProcessTimes(
            self.handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return (kernel.ticks() + user.ticks()) / 10_000_000.0

    def sample(self) -> dict[str, float | int | None]:
        now = time.monotonic()
        cpu = self._cpu_seconds()
        elapsed = max(now - self.last_wall, 1e-9)
        cpu_cores = (cpu - self.last_cpu) / elapsed
        self.last_wall = now
        self.last_cpu = cpu

        memory = ProcessMemoryCountersEx()
        memory.cb = ctypes.sizeof(memory)
        memory_ok = self.psapi.GetProcessMemoryInfo(
            self.handle, ctypes.byref(memory), memory.cb
        )
        handles = wintypes.DWORD()
        handles_ok = self.kernel32.GetProcessHandleCount(
            self.handle, ctypes.byref(handles)
        )
        return {
            "cpu_cores": round(cpu_cores, 3),
            "cpu_machine_percent": round(
                100.0 * cpu_cores / self.logical_processors, 2
            ),
            "working_set_mb": (
                round(memory.WorkingSetSize / (1024.0 * 1024.0), 1)
                if memory_ok
                else None
            ),
            "private_mb": (
                round(memory.PrivateUsage / (1024.0 * 1024.0), 1)
                if memory_ok
                else None
            ),
            "handles": int(handles.value) if handles_ok else None,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--duration-seconds", type=float, default=0.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.interval_seconds < 1.0:
        raise RuntimeError("interval must be at least one second")

    messages: queue.Queue[dict[str, object]] = queue.Queue()
    detached = threading.Event()
    metrics = ProcessMetrics(args.pid)
    session = frida.attach(args.pid)
    session.on("detached", lambda *unused: detached.set())

    javascript = r"""
const intervalMs = %d;
const renderer = ptr("0x015E0388").readPointer();
const device = renderer.add(0x98).readPointer();
const vtable = device.readPointer();
const present = vtable.add(17 * Process.pointerSize).readPointer();
const kernel32 = Process.getModuleByName("kernel32.dll");
const qpc = new NativeFunction(
    kernel32.getExportByName("QueryPerformanceCounter"), "bool", ["pointer"]);
const qpf = new NativeFunction(
    kernel32.getExportByName("QueryPerformanceFrequency"), "bool", ["pointer"]);
const counter = Memory.alloc(8);
const frequencyOutput = Memory.alloc(8);
qpf(frequencyOutput);
const frequency = frequencyOutput.readS64().toNumber();

function nowTicks() {
    qpc(counter);
    return counter.readS64().toNumber();
}

function percentile(sorted, fraction) {
    if (sorted.length === 0)
        return 0.0;
    const index = Math.min(
        sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
    return sorted[index];
}

let intervals = [];
let frameCount = 0;
let lastTicks = 0;
let sampleStartTicks = nowTicks();

const listener = Interceptor.attach(present, {
    onEnter(args) {
        if (!args[0].equals(device))
            return;
        const ticks = nowTicks();
        if (lastTicks !== 0) {
            const milliseconds = (ticks - lastTicks) * 1000.0 / frequency;
            if (milliseconds > 0.0 && milliseconds < 10000.0)
                intervals.push(milliseconds);
        }
        lastTicks = ticks;
        frameCount++;
    }
});

const timer = setInterval(() => {
    const endTicks = nowTicks();
    const seconds = (endTicks - sampleStartTicks) / frequency;
    const sorted = intervals.slice().sort((a, b) => a - b);
    const total = intervals.reduce((sum, value) => sum + value, 0.0);
    const average = intervals.length ? total / intervals.length : 0.0;
    const p99 = percentile(sorted, 0.99);
    const p999 = percentile(sorted, 0.999);
    function drops(threshold) {
        return intervals.filter(value => value > threshold).length;
    }
    send({
        event: "sample",
        interval_seconds: seconds,
        frames: frameCount,
        fps: seconds > 0.0 ? frameCount / seconds : 0.0,
        frame_time_ms: {
            average: average,
            p50: percentile(sorted, 0.50),
            p95: percentile(sorted, 0.95),
            p99: p99,
            p999: p999,
            maximum: sorted.length ? sorted[sorted.length - 1] : 0.0
        },
        low_fps: {
            one_percent: p99 > 0.0 ? 1000.0 / p99 : 0.0,
            point_one_percent: p999 > 0.0 ? 1000.0 / p999 : 0.0
        },
        gaps: {
            over_16_7_ms: drops(16.7),
            over_25_ms: drops(25.0),
            over_33_3_ms: drops(33.3),
            over_50_ms: drops(50.0),
            over_100_ms: drops(100.0)
        }
    });
    intervals = [];
    frameCount = 0;
    sampleStartTicks = endTicks;
}, intervalMs);

send({
    event: "ready",
    device: device.toString(),
    present: present.toString(),
    frequency: frequency
});

rpc.exports.dispose = function () {
    clearInterval(timer);
    listener.detach();
};
""" % int(args.interval_seconds * 1000.0)

    script = session.create_script(javascript)

    def on_message(message, data) -> None:
        if message.get("type") == "send":
            messages.put(message.get("payload", {}))
        else:
            messages.put({"event": "frida_error", "message": message})

    script.on("message", on_message)
    script.load()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    try:
        with args.output.open("a", encoding="utf-8") as log:
            while not detached.is_set():
                if args.duration_seconds and time.monotonic() - start >= args.duration_seconds:
                    break
                try:
                    payload = messages.get(timeout=1.0)
                except queue.Empty:
                    continue
                if payload.get("event") == "ready":
                    print(
                        f"monitor ready pid={args.pid} present={payload.get('present')} "
                        f"log={args.output}",
                        flush=True,
                    )
                    continue
                if payload.get("event") != "sample":
                    print(json.dumps(payload, ensure_ascii=False), flush=True)
                    continue

                payload.update(metrics.sample())
                payload["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
                payload["elapsed_seconds"] = round(time.monotonic() - start, 3)
                log.write(json.dumps(payload, separators=(",", ":")) + "\n")
                log.flush()
                frame = payload["frame_time_ms"]
                low = payload["low_fps"]
                gaps = payload["gaps"]
                print(
                    f"t={payload['elapsed_seconds']:7.1f}s "
                    f"fps={payload['fps']:7.2f} "
                    f"1%%={low['one_percent']:6.1f} "
                    f"0.1%%={low['point_one_percent']:6.1f} "
                    f"p99={frame['p99']:6.2f}ms max={frame['maximum']:7.2f}ms "
                    f">33ms={gaps['over_33_3_ms']:3d} >50ms={gaps['over_50_ms']:3d} "
                    f">100ms={gaps['over_100_ms']:3d} "
                    f"cpu={payload['cpu_cores']:5.2f} cores "
                    f"ws={payload['working_set_mb']:7.1f}MB",
                    flush=True,
                )
    except KeyboardInterrupt:
        pass
    finally:
        try:
            script.exports_sync.dispose()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        metrics.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
