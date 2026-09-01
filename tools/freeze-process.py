"""Freeze a Windows process on its current frame and advance it in short pulses."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import time


PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
VK_F7 = 0x76
VK_F11 = 0x7A
VK_F12 = 0x7B


def check_ntstatus(status: int, operation: str) -> None:
    if status < 0:
        raise RuntimeError(f"{operation} failed with NTSTATUS 0x{status & 0xFFFFFFFF:08X}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument(
        "--pulse-ms",
        type=int,
        default=50,
        help="Milliseconds to resume for each F12 pulse (default: 50).",
    )
    args = parser.parse_args()

    if not 1 <= args.pulse_ms <= 1000:
        raise RuntimeError("pulse-ms must be between 1 and 1000.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    user32 = ctypes.WinDLL("user32", use_last_error=True)

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtSuspendProcess.restype = wintypes.LONG
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = wintypes.LONG
    user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user32.GetAsyncKeyState.restype = ctypes.c_short

    process = kernel32.OpenProcess(
        PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        args.pid,
    )
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())

    suspended = False

    def suspend() -> None:
        nonlocal suspended
        if suspended:
            return
        check_ntstatus(ntdll.NtSuspendProcess(process), "NtSuspendProcess")
        suspended = True
        print("FROZEN", flush=True)

    def resume() -> None:
        nonlocal suspended
        if not suspended:
            return
        check_ntstatus(ntdll.NtResumeProcess(process), "NtResumeProcess")
        suspended = False
        print("RUNNING", flush=True)

    try:
        print(
            f"Attached to PID {args.pid}. F11 freezes/toggles, F12 advances "
            f"{args.pulse_ms} ms and freezes again, F7 resumes. Ctrl+C exits safely.",
            flush=True,
        )
        while True:
            exit_code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(process, ctypes.byref(exit_code)):
                raise ctypes.WinError(ctypes.get_last_error())
            if exit_code.value != STILL_ACTIVE:
                print(f"Process exited with code {exit_code.value}.", flush=True)
                break

            if user32.GetAsyncKeyState(VK_F11) & 1:
                if suspended:
                    resume()
                else:
                    suspend()
            if user32.GetAsyncKeyState(VK_F12) & 1:
                resume()
                time.sleep(args.pulse_ms / 1000.0)
                suspend()
                print(f"PULSE {args.pulse_ms} ms", flush=True)
            if user32.GetAsyncKeyState(VK_F7) & 1:
                resume()

            time.sleep(0.005)
    except KeyboardInterrupt:
        print("Stopping freeze controller.", flush=True)
    finally:
        try:
            resume()
        finally:
            kernel32.CloseHandle(process)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
