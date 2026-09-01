"""Offline tests: no virtual devices or game process are opened."""
import dataclasses
import importlib.util
import math
from pathlib import Path
import sys
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch
from gamepad_demo import DemoInput, demo_input


class Tests(unittest.TestCase):
    def test_bounded_duration_neutralizes(self):
        for t in (-1, 120, 121, float("inf"), float("nan")):
            self.assertEqual(demo_input(t, 120), DemoInput())

    def test_only_sticks_and_left_trigger_are_available(self):
        self.assertEqual({f.name for f in dataclasses.fields(DemoInput)}, {"lx", "ly", "rx", "ry", "lt"})
        for i in range(1200):
            s = demo_input(i / 100, 120)
            self.assertTrue(all(-0.55 <= getattr(s, k) <= 0.55 for k in ("lx", "ly", "rx", "ry")))
            self.assertIn(s.lt, (0, 255))

    def test_balanced_sequence_and_neutral_pause(self):
        totals = {k: 0.0 for k in ("lx", "ly", "rx", "ry")}
        for i in range(1200):
            s = demo_input((i + 0.5) / 100, 120)
            for k in totals:
                totals[k] += getattr(s, k)
        for value in totals.values():
            self.assertAlmostEqual(value, 0)
        self.assertEqual(demo_input(11.5, 120), DemoInput())


class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Stub vgamepad before importing: never connect to ViGEm or create pads.
        fake = types.ModuleType("vgamepad")
        fake.XUSB_BUTTON = Mock()
        spec = importlib.util.spec_from_file_location("bridge_under_test", Path(__file__).with_name("gamepad_bridge.py"))
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"vgamepad": fake}):
            spec.loader.exec_module(module)
        cls.bridge_class = module.KeyboardGamepadBridge

    def bridge(self):
        b = self.bridge_class.__new__(self.bridge_class)
        b.lock = threading.Lock()
        b.demo_duration, b.demo_started, b.demo_game_pid = 0, 0, 0
        b.demo_pad = 1
        b.capture_enabled = True
        b.pressed, b.mouse_buttons, b.mouse_dpad_until = {1}, {"left"}, {}
        b.mouse_delta = [10, 10]
        b._notify = Mock()
        b._foreground_coop_pid = lambda: 35776
        return b

    def test_f2_cycles_pad1_pad2_off_and_repeats_with_native_keyboard_free(self):
        b = self.bridge()
        b._cycle_demo()
        self.assertTrue(math.isinf(b.demo_duration))
        self.assertEqual(b.demo_pad, 0)
        self.assertFalse(b.capture_enabled)
        self.assertEqual(b.demo_game_pid, 35776)
        self.assertEqual(b.pressed, set())
        self.assertEqual(b.mouse_buttons, set())
        b._cycle_demo()
        self.assertTrue(math.isinf(b.demo_duration))
        self.assertEqual(b.demo_pad, 1)
        self.assertFalse(b.capture_enabled)
        b._cycle_demo()
        self.assertEqual(b.demo_duration, 0)
        self.assertFalse(b.capture_enabled)
        b._cycle_demo()
        self.assertTrue(math.isinf(b.demo_duration))
        self.assertEqual(b.demo_pad, 0)

    def test_f2_refuses_non_game_or_single_player(self):
        b = self.bridge()
        b._foreground_coop_pid = lambda: 0
        b._cycle_demo()
        self.assertEqual(b.demo_duration, 0)
        self.assertTrue(b.capture_enabled)

    def tick(self, foreground=True, expired=False, capture=False, pad_index=1):
        b = self.bridge()
        b.stop_event = threading.Event()
        b.config = types.SimpleNamespace(poll_hz=120, mouse_enabled=False)
        b.active_player = 0
        b.capture_enabled = capture
        b.demo_started = time.perf_counter() - (121 if expired else .5)
        b.demo_duration = 120
        b.demo_game_pid = 35776
        b.demo_pad = pad_index
        b.user32 = Mock()
        b.user32.GetWindowThreadProcessId.side_effect = lambda _w, p: setattr(p._obj, "value", 35776 if foreground else 42)
        b._apply_state = Mock()
        b.pads = [Mock(), Mock()]
        b.pads[1].update.side_effect = b.stop_event.set
        b._update_loop()
        return b

    def test_demo_only_touches_second_pad_sticks_and_lt(self):
        b = self.tick()
        for pad in b.pads:
            pad.reset.assert_called_once()
            pad.update.assert_called_once()
        b.pads[0].left_joystick_float.assert_not_called()
        b.pads[0].right_joystick_float.assert_not_called()
        b.pads[0].left_trigger.assert_not_called()
        b.pads[1].left_joystick_float.assert_called_once_with(x_value_float=0.0, y_value_float=0.55)
        b.pads[1].press_button.assert_not_called()
        b.pads[1].right_trigger.assert_not_called()

    def test_background_expiry_or_capture_neutralizes_demo(self):
        for kwargs in ({"foreground": False}, {"expired": True}, {"capture": True}):
            with self.subTest(**kwargs):
                b = self.tick(**kwargs)
                b.pads[1].left_joystick_float.assert_not_called()
                b.pads[1].right_joystick_float.assert_not_called()
                b.pads[1].left_trigger.assert_not_called()

    def test_swapped_device_assignment_drives_only_selected_pad(self):
        b = self.tick(pad_index=0)
        b.pads[0].left_joystick_float.assert_called_once_with(x_value_float=0.0, y_value_float=0.55)
        b.pads[1].left_joystick_float.assert_not_called()
        b.pads[1].right_joystick_float.assert_not_called()
        b.pads[1].left_trigger.assert_not_called()


if __name__ == "__main__":
    unittest.main()
