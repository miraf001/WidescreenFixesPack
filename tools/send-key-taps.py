"""Send precise virtual-key taps through Windows SendInput.

Used only for controlled bridge diagnostics after the user has selected the
intended virtual controller.  The bridge's low-level hook receives these just
like physical keys and suppresses mapped keys from other applications.
"""

from __future__ import annotations

import argparse
import ctypes
import time
from ctypes import wintypes


INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002


class KEYBDINPUT(ctypes.Structure):
    _fields_ = (
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    )


class MOUSEINPUT(ctypes.Structure):
    _fields_ = (
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    )


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = (
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    )


class INPUT_UNION(ctypes.Union):
    # INPUT's cbSize is ABI-fixed to the largest union member.  Keeping only
    # KEYBDINPUT produces 32 bytes instead of the required 40 on x64.
    _fields_ = (("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT))


class INPUT(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = (("type", wintypes.DWORD), ("value", INPUT_UNION))


def send(user32, key: int, up: bool) -> None:
    value = INPUT(type=INPUT_KEYBOARD)
    value.ki = KEYBDINPUT(key, 0, KEYEVENTF_KEYUP if up else 0, 0, 0)
    if user32.SendInput(1, ctypes.byref(value), ctypes.sizeof(INPUT)) != 1:
        raise ctypes.WinError(ctypes.get_last_error())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--hold-ms", type=float, default=120.0)
    parser.add_argument("--interval-ms", type=float, default=500.0)
    args = parser.parse_args()
    if not 1 <= args.key <= 0xFE or not 1 <= args.count <= 100:
        raise RuntimeError("Invalid key or tap count")
    if not 10 <= args.hold_ms <= 5000 or not args.hold_ms <= args.interval_ms <= 10000:
        raise RuntimeError("Require 10 <= hold-ms <= interval-ms")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT
    for index in range(args.count):
        send(user32, args.key, False)
        time.sleep(args.hold_ms / 1000.0)
        send(user32, args.key, True)
        if index + 1 < args.count:
            time.sleep((args.interval_ms - args.hold_ms) / 1000.0)
    print(f"sent key=0x{args.key:02X} count={args.count} holdMs={args.hold_ms:g}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
