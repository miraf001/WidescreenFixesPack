"""CLI control of our bridge's private message window, never of the game UI."""
import argparse
import ctypes
from ctypes import wintypes
import json
import importlib.util
from pathlib import Path

from gamepad_demo import (CONTROL_MESSAGE, CMD_STATUS, CMD_START, CMD_STOP,
                          CMD_RELEASE, CMD_QUIT, CMD_GAME_PID, CMD_PAD)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True, help="Our bridge's Python PID")
    parser.add_argument("--command", choices=("status", "start", "stop", "release", "quit"), required=True)
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--pad", type=int, choices=(1, 2), help="Bridge device number, which is NOT necessarily the game player number")
    parser.add_argument("--game-pid", type=int, help="Required for start; only send pad input while this game is foreground")
    args = parser.parse_args()
    if args.command == "start" and (not args.game_pid or not 1 <= args.seconds <= 300):
        parser.error("Start requires --game-pid and a duration of 1..300 seconds")
    if args.command == "start":
        # Read-only build-specific co-op guard; never send test sticks to SP.
        spec = importlib.util.spec_from_file_location("hud", Path(__file__).with_name("test-rerev2-sp-hud-live.py"))
        hud = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hud)
        game = hud.Process(args.game_pid, False)
        try:
            game.identity()  # rejects any executable other than rerev2.exe
            mode = game.integer(hud.MODE_POINTER)
            if not mode or game.integer(mode + 0x8F0) != 1 or game.integer(mode + 0x8F4) != 1:
                raise RuntimeError("Rejoin co-op before starting the P2 demo; no input was sent")
        finally:
            game.close()
    api = ctypes.WinDLL("user32", use_last_error=True)
    api.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
    api.FindWindowExW.restype = wintypes.HWND
    api.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    api.GetWindowThreadProcessId.restype = wintypes.DWORD
    api.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
                                      wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
    api.SendMessageTimeoutW.restype = ctypes.c_ssize_t
    name = f"RER2GamepadBridge-{args.pid}"
    window = api.FindWindowExW(wintypes.HWND(-3), None, name, name)
    if not window:
        raise RuntimeError("Bridge control window not found (new bridge version required)")
    owner = wintypes.DWORD()
    api.GetWindowThreadProcessId(window, ctypes.byref(owner))
    if owner.value != args.pid:
        raise RuntimeError("Window belongs to a different process")

    def send(command, value=0):
        result = ctypes.c_size_t()
        if not api.SendMessageTimeoutW(window, CONTROL_MESSAGE, command, value, 0x2, 2000, ctypes.byref(result)):
            raise RuntimeError("Bridge did not acknowledge within two seconds")
        if not result.value:
            raise RuntimeError("Command rejected or old bridge version still running")
        return result.value

    if args.command == "start":
        if args.pad is not None:
            send(CMD_PAD, args.pad - 1)
        send(CMD_GAME_PID, args.game_pid)
    commands = {"status": CMD_STATUS, "start": CMD_START, "stop": CMD_STOP, "release": CMD_RELEASE, "quit": CMD_QUIT}
    result = send(commands[args.command], args.seconds if args.command == "start" else 0)
    print(json.dumps({"bridgePid": args.pid, "captureEnabled": bool(result & 2), "demoRunning": bool(result & 4),
                      "demoBridgePad": (2 if result & 8 else 1) if result & 16 else "legacy hardcoded 2",
                      "f2Mode": "cycle" if result & 32 else "toggle" if result & 16 else "stop"}))


if __name__ == "__main__":
    main()
