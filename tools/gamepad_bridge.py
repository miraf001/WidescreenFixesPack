"""Route one keyboard to either of two persistent virtual XInput gamepads."""

from __future__ import annotations

import argparse
import configparser
import ctypes
from ctypes import wintypes
import math
import os
from pathlib import Path
import queue
import sys
import threading
import time
import winsound

import vgamepad as vg
from gamepad_demo import (CONTROL_MESSAGE, CMD_STATUS, CMD_START, CMD_STOP,
                          CMD_RELEASE, CMD_QUIT, CMD_GAME_PID, CMD_PAD, demo_input)


WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
HC_ACTION = 0
WM_INPUT = 0x00FF
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WM_MOUSEMOVE = 0x0200
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP = 0x0205
WM_MOUSEWHEEL = 0x020A
WM_XBUTTONDOWN = 0x020B
WM_XBUTTONUP = 0x020C
LLKHF_ALTDOWN = 0x20
RID_INPUT = 0x10000003
RIM_TYPEMOUSE = 0
RIDEV_INPUTSINK = 0x00000100
HID_USAGE_PAGE_GENERIC = 0x01
HID_USAGE_GENERIC_MOUSE = 0x02
RI_MOUSE_WHEEL = 0x0400
RI_MOUSE_HWHEEL = 0x0800
RI_MOUSE_BUTTON_1_DOWN = 0x0001
RI_MOUSE_BUTTON_1_UP = 0x0002
RI_MOUSE_BUTTON_2_DOWN = 0x0004
RI_MOUSE_BUTTON_2_UP = 0x0008
RI_MOUSE_BUTTON_4_DOWN = 0x0040
RI_MOUSE_BUTTON_4_UP = 0x0080
RI_MOUSE_BUTTON_5_DOWN = 0x0100
RI_MOUSE_BUTTON_5_UP = 0x0200
HWND_MESSAGE = ctypes.c_void_p(-3)

VK_F1 = 0x70


def _key_codes() -> dict[str, int]:
    result = {chr(code): code for code in range(ord("A"), ord("Z") + 1)}
    result.update({str(number): ord(str(number)) for number in range(10)})
    result.update({f"F{number}": VK_F1 + number - 1 for number in range(1, 25)})
    result.update(
        {
            "SPACE": 0x20,
            "TAB": 0x09,
            "ENTER": 0x0D,
            "BACKSPACE": 0x08,
            "ESCAPE": 0x1B,
            "UP": 0x26,
            "DOWN": 0x28,
            "LEFT": 0x25,
            "RIGHT": 0x27,
            "LEFTSHIFT": 0xA0,
            "RIGHTSHIFT": 0xA1,
            "LEFTCTRL": 0xA2,
            "RIGHTCTRL": 0xA3,
            "LEFTALT": 0xA4,
            "RIGHTALT": 0xA5,
        }
    )
    return result


KEY_CODES = _key_codes()


LRESULT = ctypes.c_ssize_t
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", wintypes.POINT),
        ("mouseData", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [
        ("usUsagePage", wintypes.USHORT),
        ("usUsage", wintypes.USHORT),
        ("dwFlags", wintypes.DWORD),
        ("hwndTarget", wintypes.HWND),
    ]


class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", wintypes.DWORD),
        ("dwSize", wintypes.DWORD),
        ("hDevice", wintypes.HANDLE),
        ("wParam", wintypes.WPARAM),
    ]


class RAWMOUSEBUTTONFIELDS(ctypes.Structure):
    _fields_ = [("usButtonFlags", wintypes.USHORT), ("usButtonData", wintypes.USHORT)]


class RAWMOUSEBUTTONS(ctypes.Union):
    _anonymous_ = ("fields",)
    _fields_ = [("ulButtons", wintypes.ULONG), ("fields", RAWMOUSEBUTTONFIELDS)]


class RAWMOUSE(ctypes.Structure):
    _anonymous_ = ("buttons",)
    _fields_ = [
        ("usFlags", wintypes.USHORT),
        ("buttons", RAWMOUSEBUTTONS),
        ("ulRawButtons", wintypes.ULONG),
        ("lLastX", wintypes.LONG),
        ("lLastY", wintypes.LONG),
        ("ulExtraInformation", wintypes.ULONG),
    ]


class RAWINPUTDATA(ctypes.Union):
    _fields_ = [("mouse", RAWMOUSE)]


class RAWINPUT(ctypes.Structure):
    _fields_ = [("header", RAWINPUTHEADER), ("data", RAWINPUTDATA)]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HANDLE),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HANDLE),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class BridgeConfig:
    def __init__(self, path: Path, force_no_suppress: bool) -> None:
        parser = configparser.ConfigParser()
        if not parser.read(path, encoding="utf-8"):
            raise RuntimeError(f"Configuration file was not found: {path}")

        self.poll_hz = parser.getint("BRIDGE", "PollHz")
        if not 30 <= self.poll_hz <= 1000:
            raise RuntimeError("BRIDGE.PollHz must be between 30 and 1000.")

        self.initial_player = parser.getint("BRIDGE", "InitialPlayer") - 1
        if self.initial_player not in (0, 1):
            raise RuntimeError("BRIDGE.InitialPlayer must be 1 or 2.")
        self.demo_pad = parser.getint("BRIDGE", "DemoPad", fallback=2) - 1
        if self.demo_pad not in (0, 1):
            raise RuntimeError("BRIDGE.DemoPad must be 1 or 2 (bridge device, not game actor).")

        self.suppress_mapped_keys = (
            parser.getboolean("BRIDGE", "SuppressMappedKeys") and not force_no_suppress
        )
        self.hotkeys = {
            "switch": self._read_key(parser, "HOTKEYS", "SwitchPlayer"),
            "capture": self._read_key(parser, "HOTKEYS", "ToggleCapture"),
            "quit": self._read_key(parser, "HOTKEYS", "Quit"),
            "demo": KEY_CODES[parser.get("HOTKEYS", "ToggleDemo", fallback=
                               parser.get("HOTKEYS", "StopDemo", fallback="F2")).upper()],
        }
        if len(set(self.hotkeys.values())) != len(self.hotkeys):
            raise RuntimeError("HOTKEYS entries must use different keys.")

        self.left_stick = self._read_directions(parser, "LEFT_STICK")
        self.right_stick = self._read_directions(parser, "RIGHT_STICK")
        self.mouse_enabled = parser.getboolean("MOUSE", "Enabled")
        self.mouse_sensitivity_x = parser.getfloat("MOUSE", "SensitivityX")
        self.mouse_sensitivity_y = parser.getfloat("MOUSE", "SensitivityY")
        self.mouse_minimum_output = parser.getfloat("MOUSE", "MinimumOutput")
        self.mouse_smoothing = parser.getfloat("MOUSE", "Smoothing")
        self.mouse_invert_y = parser.getboolean("MOUSE", "InvertY")
        self.suppress_legacy_mouse = (
            parser.getboolean("MOUSE", "SuppressLegacyInput") and not force_no_suppress
        )
        self.map_mouse_buttons = parser.getboolean("MOUSE", "MapButtons")
        self.map_mouse_dpad = parser.getboolean("MOUSE", "MapWheelAndSideButtonsToDPad")
        if self.mouse_sensitivity_x <= 0 or self.mouse_sensitivity_y <= 0:
            raise RuntimeError("MOUSE sensitivity values must be greater than zero.")
        if not 0 <= self.mouse_minimum_output < 1:
            raise RuntimeError("MOUSE.MinimumOutput must be at least zero and below one.")
        if not 0 <= self.mouse_smoothing < 1:
            raise RuntimeError("MOUSE.Smoothing must be at least zero and below one.")
        self.buttons = {
            "a": self._read_key(parser, "BUTTONS", "A"),
            "b": self._read_key(parser, "BUTTONS", "B"),
            "x": self._read_key(parser, "BUTTONS", "X"),
            "y": self._read_key(parser, "BUTTONS", "Y"),
            "left_shoulder": self._read_key(parser, "BUTTONS", "LeftShoulder"),
            "right_shoulder": self._read_key(parser, "BUTTONS", "RightShoulder"),
            "left_thumb": self._read_key(parser, "BUTTONS", "LeftThumb"),
            "right_thumb": self._read_key(parser, "BUTTONS", "RightThumb"),
            "back": self._read_key(parser, "BUTTONS", "Back"),
            "start": self._read_key(parser, "BUTTONS", "Start"),
            "dpad_up": self._read_key(parser, "BUTTONS", "DPadUp"),
            "dpad_down": self._read_key(parser, "BUTTONS", "DPadDown"),
            "dpad_left": self._read_key(parser, "BUTTONS", "DPadLeft"),
            "dpad_right": self._read_key(parser, "BUTTONS", "DPadRight"),
        }
        self.triggers = {
            "left": self._read_key(parser, "TRIGGERS", "Left"),
            "right": self._read_key(parser, "TRIGGERS", "Right"),
        }
        self.mapped_keys = set(self.left_stick.values())
        self.mapped_keys.update(self.right_stick.values())
        self.mapped_keys.update(self.buttons.values())
        self.mapped_keys.update(self.triggers.values())

        hotkey_conflicts = set(self.hotkeys.values()) & self.mapped_keys
        if hotkey_conflicts:
            raise RuntimeError("A HOTKEYS entry is also assigned to a gamepad control.")

    @staticmethod
    def _read_key(parser: configparser.ConfigParser, section: str, option: str) -> int:
        name = parser.get(section, option).strip().upper()
        try:
            return KEY_CODES[name]
        except KeyError as error:
            raise RuntimeError(f"Unsupported key name in {section}.{option}: {name}") from error

    def _read_directions(self, parser: configparser.ConfigParser, section: str) -> dict[str, int]:
        return {
            "up": self._read_key(parser, section, "Up"),
            "down": self._read_key(parser, section, "Down"),
            "left": self._read_key(parser, section, "Left"),
            "right": self._read_key(parser, section, "Right"),
        }


BUTTON_MAP = {
    "a": vg.XUSB_BUTTON.XUSB_GAMEPAD_A,
    "b": vg.XUSB_BUTTON.XUSB_GAMEPAD_B,
    "x": vg.XUSB_BUTTON.XUSB_GAMEPAD_X,
    "y": vg.XUSB_BUTTON.XUSB_GAMEPAD_Y,
    "left_shoulder": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER,
    "right_shoulder": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER,
    "left_thumb": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "right_thumb": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "back": vg.XUSB_BUTTON.XUSB_GAMEPAD_BACK,
    "start": vg.XUSB_BUTTON.XUSB_GAMEPAD_START,
    "dpad_up": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP,
    "dpad_down": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN,
    "dpad_left": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT,
    "dpad_right": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT,
}


class KeyboardGamepadBridge:
    def __init__(self, config: BridgeConfig) -> None:
        self.config = config
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_win32_api()

        self.lock = threading.Lock()
        self.pressed: set[int] = set()
        self.hotkeys_down: set[int] = set()
        self.mouse_delta = [0, 0]
        self.mouse_buttons: set[str] = set()
        self.mouse_dpad_until: dict[str, float] = {}
        self.mouse_stick_output = [0.0, 0.0]
        self.active_player = config.initial_player
        self.capture_enabled = True
        self.demo_started = 0.0
        self.demo_duration = 0.0
        self.demo_game_pid = 0
        self.demo_pad = config.demo_pad
        self.stop_event = threading.Event()
        self.notifications: queue.SimpleQueue[tuple[str, int]] = queue.SimpleQueue()
        self.pads: list[vg.VX360Gamepad] = []
        self.keyboard_hook = None
        self.mouse_hook = None
        self.raw_input_window = None
        self.window_class_name = f"RER2GamepadBridge-{os.getpid()}"
        self.keyboard_hook_callback = HOOKPROC(self._keyboard_hook)
        self.mouse_hook_callback = HOOKPROC(self._mouse_hook)
        self.window_proc_callback = WNDPROC(self._window_proc)
        self.dpad_key_names = {
            self.config.buttons["dpad_up"]: "Up",
            self.config.buttons["dpad_down"]: "Down",
            self.config.buttons["dpad_left"]: "Left",
            self.config.buttons["dpad_right"]: "Right",
        }
        self.dpad_key_controls = {
            self.config.buttons["dpad_up"]: "dpad_up",
            self.config.buttons["dpad_down"]: "dpad_down",
            self.config.buttons["dpad_left"]: "dpad_left",
            self.config.buttons["dpad_right"]: "dpad_right",
        }

    def _configure_win32_api(self) -> None:
        self.user32.GetForegroundWindow.restype = wintypes.HWND
        self.user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                           wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
        self.user32.SetWindowsHookExW.restype = wintypes.HANDLE
        self.user32.CallNextHookEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
        self.user32.CallNextHookEx.restype = LRESULT
        self.user32.UnhookWindowsHookEx.argtypes = [wintypes.HANDLE]
        self.user32.UnhookWindowsHookEx.restype = wintypes.BOOL
        self.user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        self.user32.GetMessageW.restype = wintypes.BOOL
        self.user32.PostQuitMessage.argtypes = [ctypes.c_int]
        self.user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        self.user32.RegisterClassW.restype = wintypes.ATOM
        self.user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HANDLE,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        self.user32.CreateWindowExW.restype = wintypes.HWND
        self.user32.DefWindowProcW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        self.user32.DefWindowProcW.restype = LRESULT
        self.user32.DestroyWindow.argtypes = [wintypes.HWND]
        self.user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        self.user32.RegisterRawInputDevices.argtypes = [
            ctypes.POINTER(RAWINPUTDEVICE),
            wintypes.UINT,
            wintypes.UINT,
        ]
        self.user32.RegisterRawInputDevices.restype = wintypes.BOOL
        self.user32.GetRawInputData.argtypes = [
            wintypes.HANDLE,
            wintypes.UINT,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.UINT),
            wintypes.UINT,
        ]
        self.user32.GetRawInputData.restype = wintypes.UINT
        self.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype = wintypes.HMODULE

    def run(self) -> int:
        self.pads = [vg.VX360Gamepad(), vg.VX360Gamepad()]
        self._neutralize_all()
        # Creation order and XInput slot order need not match after reconnect.
        from vgamepad.win import vigem_client, vigem_commons
        for index, pad in enumerate(self.pads):
            user_index = wintypes.DWORD(0xFFFFFFFF)
            error = vigem_client.vigem_target_x360_get_user_index(pad._busp, pad._devicep, ctypes.byref(user_index))
            if error == vigem_commons.VIGEM_ERRORS.VIGEM_ERROR_NONE:
                print(f"Bridge pad {index + 1}: XInput slot {user_index.value}", flush=True)

        notifier = threading.Thread(target=self._notification_loop, name="bridge-notifier", daemon=True)
        updater = threading.Thread(target=self._update_loop, name="bridge-updater", daemon=True)
        notifier.start()
        updater.start()

        module = self.kernel32.GetModuleHandleW(None)
        try:
            if self.config.mouse_enabled:
                self._create_raw_input_window(module)

            self.keyboard_hook = self.user32.SetWindowsHookExW(
                WH_KEYBOARD_LL, self.keyboard_hook_callback, module, 0
            )
            if not self.keyboard_hook:
                raise ctypes.WinError(ctypes.get_last_error())

            if self.config.mouse_enabled and self.config.suppress_legacy_mouse:
                self.mouse_hook = self.user32.SetWindowsHookExW(
                    WH_MOUSE_LL, self.mouse_hook_callback, module, 0
                )
                if not self.mouse_hook:
                    raise ctypes.WinError(ctypes.get_last_error())

            keyboard_suppression = "on" if self.config.suppress_mapped_keys else "off"
            mouse_mode = "raw mouse -> right stick" if self.config.mouse_enabled else "mouse off"
            self._notify(
                f"Two virtual Xbox 360 controllers connected. Active: P{self.active_player + 1}; "
                f"keyboard suppression: {keyboard_suppression}; {mouse_mode}.",
                self.active_player + 1,
            )
            self._notify("F2: demo pad1 -> pad2 -> off | F8: switch P1/P2 | F9: release/capture inputs | F10: quit", 0)

            message = wintypes.MSG()
            while not self.stop_event.is_set():
                result = self.user32.GetMessageW(ctypes.byref(message), None, 0, 0)
                if result in (0, -1):
                    break
                self.user32.TranslateMessage(ctypes.byref(message))
                self.user32.DispatchMessageW(ctypes.byref(message))
        finally:
            self.stop_event.set()
            if self.mouse_hook:
                self.user32.UnhookWindowsHookEx(self.mouse_hook)
                self.mouse_hook = None
            if self.keyboard_hook:
                self.user32.UnhookWindowsHookEx(self.keyboard_hook)
                self.keyboard_hook = None
            if self.raw_input_window:
                self.user32.DestroyWindow(self.raw_input_window)
                self.raw_input_window = None
                self.user32.UnregisterClassW(self.window_class_name, module)
            updater.join(timeout=2.0)
            self._neutralize_all()
            self.pads.clear()
            self._notify("Virtual controllers disconnected.", 0)
            time.sleep(0.05)
        return 0

    def _keyboard_hook(self, code: int, message: int, data_pointer: int) -> int:
        if code != HC_ACTION:
            return self.user32.CallNextHookEx(self.keyboard_hook, code, message, data_pointer)

        data = ctypes.cast(data_pointer, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        key = int(data.vkCode)
        is_down = message in (WM_KEYDOWN, WM_SYSKEYDOWN)
        is_up = message in (WM_KEYUP, WM_SYSKEYUP)
        if not (is_down or is_up):
            return self.user32.CallNextHookEx(self.keyboard_hook, code, message, data_pointer)

        hotkey_action = next((name for name, value in self.config.hotkeys.items() if value == key), None)
        if hotkey_action:
            with self.lock:
                first_press = is_down and key not in self.hotkeys_down
                if is_down:
                    self.hotkeys_down.add(key)
                else:
                    self.hotkeys_down.discard(key)

                if first_press and hotkey_action == "switch":
                    self._stop_demo()
                    self.active_player = 1 - self.active_player
                    self._clear_input_state()
                    self._notify(f"Active controller: P{self.active_player + 1}", self.active_player + 1)
                elif first_press and hotkey_action == "capture":
                    self._stop_demo()
                    self.capture_enabled = not self.capture_enabled
                    self._clear_input_state()
                    state = "captured" if self.capture_enabled else "released"
                    self._notify(f"Keyboard and mouse {state}.", 1 if self.capture_enabled else -1)
                elif first_press and hotkey_action == "quit":
                    self._clear_input_state()
                    self.stop_event.set()
                    self.user32.PostQuitMessage(0)
                elif first_press and hotkey_action == "demo":
                    self._cycle_demo()
            return 1

        with self.lock:
            capture_enabled = self.capture_enabled

        if not capture_enabled or key not in self.config.mapped_keys:
            return self.user32.CallNextHookEx(self.keyboard_hook, code, message, data_pointer)

        # Preserve Alt-based system shortcuts such as Alt+Tab.
        if data.flags & LLKHF_ALTDOWN:
            return self.user32.CallNextHookEx(self.keyboard_hook, code, message, data_pointer)

        with self.lock:
            first_press = is_down and key not in self.pressed
            if is_down:
                self.pressed.add(key)
            else:
                self.pressed.discard(key)
            if first_press and key in self.dpad_key_names:
                # Latch a tap long enough to cross multiple XInput polls. Some
                # keyboards and game overlays produce very short key pulses.
                self.mouse_dpad_until[self.dpad_key_controls[key]] = time.perf_counter() + 0.18
                self._notify(
                    f"P{self.active_player + 1} D-pad {self.dpad_key_names[key]} (keyboard)", 0
                )

        if self.config.suppress_mapped_keys:
            return 1
        return self.user32.CallNextHookEx(self.keyboard_hook, code, message, data_pointer)

    def _mouse_hook(self, code: int, message: int, data_pointer: int) -> int:
        if code == HC_ACTION:
            with self.lock:
                suppress = self.capture_enabled and self.config.suppress_legacy_mouse
            if suppress and message in {
                WM_MOUSEMOVE,
                WM_LBUTTONDOWN,
                WM_LBUTTONUP,
                WM_RBUTTONDOWN,
                WM_RBUTTONUP,
                WM_MOUSEWHEEL,
                WM_XBUTTONDOWN,
                WM_XBUTTONUP,
            }:
                return 1
        return self.user32.CallNextHookEx(self.mouse_hook, code, message, data_pointer)

    def _create_raw_input_window(self, module: int) -> None:
        window_class = WNDCLASSW()
        window_class.lpfnWndProc = self.window_proc_callback
        window_class.hInstance = module
        window_class.lpszClassName = self.window_class_name
        if not self.user32.RegisterClassW(ctypes.byref(window_class)):
            raise ctypes.WinError(ctypes.get_last_error())

        self.raw_input_window = self.user32.CreateWindowExW(
            0,
            self.window_class_name,
            self.window_class_name,
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            None,
            module,
            None,
        )
        if not self.raw_input_window:
            error = ctypes.get_last_error()
            self.user32.UnregisterClassW(self.window_class_name, module)
            raise ctypes.WinError(error)

        raw_device = RAWINPUTDEVICE(
            usUsagePage=HID_USAGE_PAGE_GENERIC,
            usUsage=HID_USAGE_GENERIC_MOUSE,
            dwFlags=RIDEV_INPUTSINK,
            hwndTarget=self.raw_input_window,
        )
        if not self.user32.RegisterRawInputDevices(
            ctypes.byref(raw_device), 1, ctypes.sizeof(RAWINPUTDEVICE)
        ):
            error = ctypes.get_last_error()
            self.user32.DestroyWindow(self.raw_input_window)
            self.raw_input_window = None
            self.user32.UnregisterClassW(self.window_class_name, module)
            raise ctypes.WinError(error)

    def _window_proc(self, window: int, message: int, wparam: int, lparam: int) -> int:
        if message == CONTROL_MESSAGE:
            with self.lock:
                if wparam == CMD_GAME_PID:
                    if not 0 < lparam <= 0x7FFFFFFF:
                        return 0
                    self._stop_demo()
                    self.demo_game_pid = int(lparam)
                elif wparam == CMD_PAD:
                    if lparam not in (0, 1):
                        return 0
                    self._stop_demo()
                    self.demo_pad = int(lparam)
                elif wparam == CMD_START:
                    if not 1 <= lparam <= 300 or not self.demo_game_pid:
                        return 0
                    # Release native input automatically; do not synthesize F9.
                    self.capture_enabled = False
                    self._clear_input_state()
                    self.demo_started = time.perf_counter()
                    self.demo_duration = float(lparam)
                    self._notify(f"Demo bridge pad {self.demo_pad + 1} running for {lparam}s; F2 cycles; keyboard/mouse released.", 0)
                elif wparam == CMD_STOP:
                    self._stop_demo()
                elif wparam == CMD_RELEASE:
                    self.capture_enabled = False
                    self._clear_input_state()
                elif wparam == CMD_QUIT:
                    self._stop_demo()
                    self._clear_input_state()
                    self.stop_event.set()
                    self.user32.PostQuitMessage(0)
                elif wparam != CMD_STATUS:
                    return 0
                # Nonzero ack + state flags, no pointers or arbitrary code.
                return 49 | (2 if self.capture_enabled else 0) | (4 if self.demo_duration else 0) | (8 if self.demo_pad else 0)
        if message == WM_INPUT:
            self._process_raw_mouse(lparam)
            if wparam == 0:
                self.user32.DefWindowProcW(window, message, wparam, lparam)
            return 0
        return self.user32.DefWindowProcW(window, message, wparam, lparam)

    def _process_raw_mouse(self, raw_input_handle: int) -> None:
        size = wintypes.UINT(0)
        header_size = ctypes.sizeof(RAWINPUTHEADER)
        result = self.user32.GetRawInputData(
            raw_input_handle, RID_INPUT, None, ctypes.byref(size), header_size
        )
        if result != 0 or size.value < ctypes.sizeof(RAWINPUT):
            return

        buffer = ctypes.create_string_buffer(size.value)
        result = self.user32.GetRawInputData(
            raw_input_handle, RID_INPUT, buffer, ctypes.byref(size), header_size
        )
        if result == 0xFFFFFFFF or result != size.value:
            return

        raw = ctypes.cast(buffer, ctypes.POINTER(RAWINPUT)).contents
        if raw.header.dwType != RIM_TYPEMOUSE:
            return

        mouse = raw.data.mouse
        # Absolute-position devices are not suitable as right-stick deltas.
        if mouse.usFlags & 0x0001:
            return

        now = time.perf_counter()
        with self.lock:
            if not self.capture_enabled:
                return

            self.mouse_delta[0] += int(mouse.lLastX)
            self.mouse_delta[1] += int(mouse.lLastY)
            flags = int(mouse.usButtonFlags)

            if flags & RI_MOUSE_BUTTON_1_DOWN:
                self.mouse_buttons.add("left")
            if flags & RI_MOUSE_BUTTON_1_UP:
                self.mouse_buttons.discard("left")
            if flags & RI_MOUSE_BUTTON_2_DOWN:
                self.mouse_buttons.add("right")
            if flags & RI_MOUSE_BUTTON_2_UP:
                self.mouse_buttons.discard("right")
            if flags & RI_MOUSE_BUTTON_4_DOWN:
                self.mouse_buttons.add("x1")
            if flags & RI_MOUSE_BUTTON_4_UP:
                self.mouse_buttons.discard("x1")
            if flags & RI_MOUSE_BUTTON_5_DOWN:
                self.mouse_buttons.add("x2")
            if flags & RI_MOUSE_BUTTON_5_UP:
                self.mouse_buttons.discard("x2")

            if self.config.map_mouse_dpad:
                if flags & RI_MOUSE_WHEEL:
                    wheel = ctypes.c_short(mouse.usButtonData).value
                    name = "dpad_up" if wheel > 0 else "dpad_down"
                    self.mouse_dpad_until[name] = now + 0.15
                    self._notify(
                        f"P{self.active_player + 1} D-pad {'Up' if wheel > 0 else 'Down'} "
                        "(mouse wheel)",
                        0,
                    )
                if flags & RI_MOUSE_HWHEEL:
                    wheel = ctypes.c_short(mouse.usButtonData).value
                    name = "dpad_right" if wheel > 0 else "dpad_left"
                    self.mouse_dpad_until[name] = now + 0.15

    def _clear_input_state(self) -> None:
        self.pressed.clear()
        self.mouse_delta[:] = [0, 0]
        self.mouse_buttons.clear()
        self.mouse_dpad_until.clear()

    def _stop_demo(self) -> None:
        # Called with self.lock held; updater neutralizes P2 on the next tick.
        if self.demo_duration:
            self.demo_duration = 0.0
            self._notify("P2 demo stopped; pads remain connected.", 0)

    def _foreground_coop_pid(self) -> int:
        """Read-only guard for user-triggered F2; never control the game UI."""
        process_id = wintypes.DWORD()
        self.user32.GetWindowThreadProcessId(self.user32.GetForegroundWindow(), ctypes.byref(process_id))
        handle = self.kernel32.OpenProcess(0x1010, False, process_id.value)
        if not handle:
            return 0
        try:
            image = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(image))
            if not self.kernel32.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
                return 0
            if Path(image.value).name.lower() != "rerev2.exe":
                return 0

            def read_int(address):
                value, transferred = ctypes.c_uint32(), ctypes.c_size_t()
                if not self.kernel32.ReadProcessMemory(handle, address, ctypes.byref(value), 4, ctypes.byref(transferred)):
                    return None
                return value.value if transferred.value == 4 else None

            manager = read_int(0x157AE00)
            if manager and read_int(manager + 0x8F0) == 1 and read_int(manager + 0x8F4) == 1:
                return process_id.value
            return 0
        finally:
            self.kernel32.CloseHandle(handle)

    def _cycle_demo(self) -> None:
        # Test-only F2 cycle: off -> bridge pad 1 -> bridge pad 2 -> off.
        # Caller holds self.lock. Both reports reset on every updater tick,
        # so the previously driven pad becomes neutral when selection changes.
        if self.demo_duration and self.demo_pad == 1:
            self._stop_demo()
            return
        game_pid = self._foreground_coop_pid()
        if not game_pid:
            self._stop_demo()
            self._notify("Pad demo needs Revelations 2 co-op in the foreground.", 0)
            return
        self.demo_pad = 1 if self.demo_duration else 0
        self.demo_game_pid = game_pid
        self.demo_started = time.perf_counter()
        self.demo_duration = math.inf
        self.capture_enabled = False
        self._clear_input_state()
        self._notify(f"Demo bridge pad {self.demo_pad + 1} on; F2 cycles; keyboard/mouse released.", self.demo_pad + 1)

    def _update_loop(self) -> None:
        interval = 1.0 / self.config.poll_hz
        mouse_stick = [0.0, 0.0]
        while not self.stop_event.is_set():
            started = time.perf_counter()
            with self.lock:
                pressed = set(self.pressed)
                active_player = self.active_player
                capture_enabled = self.capture_enabled
                elapsed = started - self.demo_started
                if self.demo_duration and (elapsed >= self.demo_duration or capture_enabled):
                    self._stop_demo()
                demo_duration = self.demo_duration
                demo_game_pid = self.demo_game_pid
                demo_pad = self.demo_pad
                mouse_delta = tuple(self.mouse_delta)
                self.mouse_delta[:] = [0, 0]
                mouse_buttons = set(self.mouse_buttons)
                now = time.perf_counter()
                mouse_dpad = {
                    name for name, deadline in self.mouse_dpad_until.items() if deadline > now
                }
                self.mouse_dpad_until = {
                    name: deadline
                    for name, deadline in self.mouse_dpad_until.items()
                    if deadline > now
                }

            if capture_enabled and self.config.mouse_enabled:
                target_x = self._mouse_axis(mouse_delta[0], self.config.mouse_sensitivity_x)
                y_delta = mouse_delta[1] if self.config.mouse_invert_y else -mouse_delta[1]
                target_y = self._mouse_axis(y_delta, self.config.mouse_sensitivity_y)
                smoothing = self.config.mouse_smoothing
                mouse_stick[0] = (mouse_stick[0] * smoothing) + (target_x * (1.0 - smoothing))
                mouse_stick[1] = (mouse_stick[1] * smoothing) + (target_y * (1.0 - smoothing))
                mouse_stick[0] = 0.0 if abs(mouse_stick[0]) < 0.01 else mouse_stick[0]
                mouse_stick[1] = 0.0 if abs(mouse_stick[1]) < 0.01 else mouse_stick[1]
            else:
                mouse_stick[:] = [0.0, 0.0]

            foreground_pid = wintypes.DWORD()
            if demo_duration:
                foreground = self.user32.GetForegroundWindow()
                self.user32.GetWindowThreadProcessId(foreground, ctypes.byref(foreground_pid))
            demo_active = bool(demo_duration and foreground_pid.value == demo_game_pid)

            for index, pad in enumerate(self.pads):
                pad.reset()
                if capture_enabled and index == active_player:
                    self._apply_state(pad, pressed, tuple(mouse_stick), mouse_buttons, mouse_dpad)
                elif demo_active and index == demo_pad:
                    state = demo_input(elapsed, demo_duration)
                    pad.left_joystick_float(x_value_float=state.lx, y_value_float=state.ly)
                    pad.right_joystick_float(x_value_float=state.rx, y_value_float=state.ry)
                    pad.left_trigger(value=state.lt)
                pad.update()

            remaining = interval - (time.perf_counter() - started)
            if remaining > 0:
                self.stop_event.wait(remaining)

    def _apply_state(
        self,
        pad: vg.VX360Gamepad,
        pressed: set[int],
        mouse_stick: tuple[float, float],
        mouse_buttons: set[str],
        mouse_dpad: set[str],
    ) -> None:
        left_x, left_y = self._stick_values(self.config.left_stick, pressed)
        right_x, right_y = self._stick_values(self.config.right_stick, pressed)
        if right_x == 0.0 and right_y == 0.0:
            right_x, right_y = mouse_stick
        pad.left_joystick_float(x_value_float=left_x, y_value_float=left_y)
        pad.right_joystick_float(x_value_float=right_x, y_value_float=right_y)

        for name, button in BUTTON_MAP.items():
            mouse_pressed = name in mouse_dpad
            if self.config.map_mouse_dpad:
                mouse_pressed = mouse_pressed or (name == "dpad_left" and "x1" in mouse_buttons)
                mouse_pressed = mouse_pressed or (name == "dpad_right" and "x2" in mouse_buttons)
            if self.config.buttons[name] in pressed or mouse_pressed:
                pad.press_button(button=button)

        left_trigger = self.config.triggers["left"] in pressed
        right_trigger = self.config.triggers["right"] in pressed
        if self.config.map_mouse_buttons:
            left_trigger = left_trigger or "right" in mouse_buttons
            right_trigger = right_trigger or "left" in mouse_buttons
        pad.left_trigger(value=255 if left_trigger else 0)
        pad.right_trigger(value=255 if right_trigger else 0)

    def _mouse_axis(self, delta: int, sensitivity: float) -> float:
        if delta == 0:
            return 0.0
        magnitude = min(1.0, self.config.mouse_minimum_output + (abs(delta) * sensitivity))
        return math.copysign(magnitude, delta)

    @staticmethod
    def _stick_values(directions: dict[str, int], pressed: set[int]) -> tuple[float, float]:
        x = float((directions["right"] in pressed) - (directions["left"] in pressed))
        y = float((directions["up"] in pressed) - (directions["down"] in pressed))
        if x and y:
            diagonal = 1.0 / math.sqrt(2.0)
            x *= diagonal
            y *= diagonal
        return x, y

    def _neutralize_all(self) -> None:
        for pad in self.pads:
            try:
                pad.reset()
                pad.update()
            except Exception:
                pass

    def _notify(self, message: str, beep_count: int) -> None:
        self.notifications.put((message, beep_count))

    def _notification_loop(self) -> None:
        while not self.stop_event.is_set() or not self.notifications.empty():
            try:
                message, beep_count = self.notifications.get(timeout=0.1)
            except queue.Empty:
                continue
            print(message, flush=True)
            if beep_count < 0:
                winsound.Beep(330, 90)
            else:
                for _ in range(beep_count):
                    winsound.Beep(880, 65)
                    time.sleep(0.04)


def self_test() -> int:
    pads = [vg.VX360Gamepad(), vg.VX360Gamepad()]
    try:
        for pad in pads:
            pad.reset()
            pad.update()
        print("Self-test passed: two virtual Xbox 360 controllers were created and updated.")
    finally:
        for pad in pads:
            pad.reset()
            pad.update()
        pads.clear()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--no-suppress", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--start-released", action="store_true", help="Keep native keyboard/mouse available at startup")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    config = BridgeConfig(args.config.resolve(), args.no_suppress)
    bridge = KeyboardGamepadBridge(config)
    if args.start_released:
        bridge.capture_enabled = False
    return bridge.run()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as error:
        print(f"Gamepad bridge failed: {error}", file=sys.stderr)
        raise SystemExit(1)
