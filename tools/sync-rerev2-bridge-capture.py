"""Temporary live bridge-capture/native-input coordination (no device emulation).

Read our bridge's capture flag via its private IPC window. Only on a change,
route the game's existing device selector to gamepad-only or native auto mode.
No per-frame game callback, new game thread, HUD change, or bridge restart.
Normal exit, bridge exit, IPC timeout and --mode stop restore native auto mode.
After a forcibly killed relay, --mode stop repairs its exact backed-up branch.
Stop this relay BEFORE restoring the parent input-owner experiment.
"""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time

spec = importlib.util.spec_from_file_location("owner", Path(__file__).with_name("test-rerev2-input-owner-live.py"))
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
hud, base = owner.hud, owner.base
AUTO = base.PATCHED
# One unconditional JMP; the trailing NOP is unreachable, not an executed
# NOP sled. Both install/restore replace the complete native six-byte JE site.
GAMEPAD = b"\xe9" + hud.u32(0x9886A7 - base.SITE - 5) + b"\x90"


def choose_gate(captured):
    return GAMEPAD if captured else AUTO


def save_state(path, value):
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def set_gate(process, desired):
    actual = process.read(base.SITE, 6)
    if actual not in (AUTO, GAMEPAD):
        raise RuntimeError("Input selector changed by another patch; no writes performed")
    if actual != desired:
        hud.transact(process, [(base.SITE, actual, desired)], guards=owner.GUARDS)


class IPC:
    def __init__(self, bridge_pid, game_pid, created):
        self.u = ctypes.WinDLL("user32", use_last_error=True)
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.u.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
        self.u.FindWindowExW.restype = wintypes.HWND
        self.u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.u.GetWindowThreadProcessId.restype = wintypes.DWORD
        self.u.IsWindow.argtypes = [wintypes.HWND]
        self.u.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
            wintypes.LPARAM, wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
        self.u.SendMessageTimeoutW.restype = ctypes.c_ssize_t
        self.k.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        self.k.CreateEventW.restype = wintypes.HANDLE
        self.k.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
        self.k.OpenEventW.restype = wintypes.HANDLE
        self.k.SetEvent.argtypes = [wintypes.HANDLE]
        self.k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        self.k.CreateMutexW.restype = wintypes.HANDLE
        self.k.ReleaseMutex.argtypes = [wintypes.HANDLE]
        self.k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.k.WaitForSingleObject.restype = wintypes.DWORD
        self.k.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.name = f"Local\\RER2BridgeCapture-{game_pid}-{created}"
        self.bridge_pid = bridge_pid
        self.window = self.u.FindWindowExW(wintypes.HWND(-3), None, f"RER2GamepadBridge-{bridge_pid}", None)

    def capture(self):
        pid = wintypes.DWORD()
        self.u.GetWindowThreadProcessId(self.window, ctypes.byref(pid))
        if pid.value != self.bridge_pid:
            raise RuntimeError("Bridge window closed or changed owner")
        result = ctypes.c_size_t()
        if not self.u.SendMessageTimeoutW(self.window, 0x8052, 1, 0, 2, 100, ctypes.byref(result)):
            return False  # fail open: a hung bridge must not lock native input
        if not result.value & 1:
            raise RuntimeError("Bridge does not support capture-status IPC")
        return bool(result.value & 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True, help="rerev2 PID")
    parser.add_argument("--bridge-pid", type=int)
    parser.add_argument("--parent-state", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mode", choices=("run", "inspect", "stop"), default="inspect")
    args = parser.parse_args()
    parent = json.loads(args.parent_state.read_text())
    state = json.loads(args.state.read_text()) if args.state.exists() else None
    process = hud.Process(args.pid, args.mode != "inspect")
    event = mutex = None
    ipc = None
    owns_gate = False
    try:
        identity = process.identity()
        if parent["pid"] != args.pid or parent["identity"] != identity or parent["status"] != "applied":
            raise RuntimeError("The confirmed input-owner experiment is not active in this process")
        if state and (state["pid"] != args.pid or state["identity"] != identity):
            raise RuntimeError("Relay state belongs to another game process instance")
        asi = Path(identity["image"]).parent / "scripts/ResidentEvilRevelations2.FusionFix.asi"
        if hashlib.sha256(asi.read_bytes()).hexdigest() != hud.ASI_HASH:
            raise RuntimeError("Only the verified Debug build is supported")
        for a, b in owner.GUARDS:
            process.expect(a, b)
        for a, b in owner.blobs(parent["allocation"]):
            process.expect(a, b)
        for a, _, b in owner.patches(parent["allocation"]):
            if a != base.SITE:
                process.expect(a, b)
        if args.mode == "run":
            if state or not args.bridge_pid:
                raise RuntimeError("Run requires --bridge-pid and a fresh state path")
            process.expect(base.SITE, AUTO)
            ipc = IPC(args.bridge_pid, args.pid, identity["created"])
            ipc.capture() # verify bridge before touching the game
            mutex = ipc.k.CreateMutexW(None, True, ipc.name + "-owner")
            hud.Process.check(mutex)
            if ctypes.get_last_error() == 183:
                ipc.k.CloseHandle(mutex)
                mutex = None
                raise RuntimeError("A capture relay already owns this process")
            event = ipc.k.CreateEventW(None, True, False, ipc.name + "-stop")
            hud.Process.check(event)
            state = {"pid": args.pid, "identity": identity, "bridgePid": args.bridge_pid,
                     "relayPid": os.getpid(), "status": "running", "site": hex(base.SITE),
                     "autoBytes": AUTO.hex(), "gamepadBytes": GAMEPAD.hex(),
                     "parentState": str(args.parent_state.resolve())}
            args.state.parent.mkdir(parents=True, exist_ok=True)
            with args.state.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2)
            owns_gate = True
            previous = None
            print(f"Capture relay running: game {args.pid}, bridge {args.bridge_pid}", flush=True)
            while ipc.k.WaitForSingleObject(event, 20) == 258:
                code = wintypes.DWORD()
                if not ipc.k.GetExitCodeProcess(process.handle, ctypes.byref(code)) or code.value != 259:
                    break
                if not ipc.u.IsWindow(ipc.window):
                    break
                captured = ipc.capture()
                set_gate(process, choose_gate(captured))
                if captured != previous:
                    print(f"capture={captured}; native selector={'gamepad only' if captured else 'auto, P1 keyboard/mouse allowed'}", flush=True)
                    previous = captured
        elif args.mode == "stop":
            if not state:
                raise RuntimeError("No relay state to stop or restore")
            ipc = IPC(state["bridgePid"], args.pid, identity["created"])
            event = ipc.k.OpenEventW(2, False, ipc.name + "-stop")
            if event:
                hud.Process.check(ipc.k.SetEvent(event))
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    if json.loads(args.state.read_text())["status"] == "restored":
                        break
                    time.sleep(.025)
                else:
                    raise RuntimeError("Relay has not acknowledged stop; do not run a second writer")
            else:
                set_gate(process, AUTO) # recover after a forcibly terminated relay
                state["status"] = "restored"
                save_state(args.state, state)
            print("Native P1 auto input restored; owner/HUD hooks unchanged.")
        else:
            code = process.read(base.SITE, 6)
            if code not in (AUTO, GAMEPAD):
                raise RuntimeError("Unexpected native device selector")
            print(json.dumps({"relay": state, "selector": "gamepad only" if code == GAMEPAD else "auto",
                              **base.snapshot(process)}, indent=2))
    finally:
        cleanup_error = None
        try:
            if owns_gate:
                try:
                    set_gate(process, AUTO)
                    state["status"] = "restored"
                    print("Relay stopped; native auto input restored.", flush=True)
                except OSError:
                    state["status"] = "game-exited-or-unreadable"
                except Exception as error:
                    state["status"] = "restore-refused"
                    state["restoreError"] = str(error)
                    cleanup_error = error
                finally:
                    save_state(args.state, state)
        finally:
            if event:
                ipc.k.CloseHandle(event)
            if mutex:
                ipc.k.ReleaseMutex(mutex)
                ipc.k.CloseHandle(mutex)
            process.close()
        if cleanup_error:
            raise RuntimeError("Native selector changed externally; automatic restore was refused") from cleanup_error


if __name__ == "__main__":
    main()
