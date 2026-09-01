"""Offline tests for the read-only effects probe; no game or injection needed."""

import importlib.util
from pathlib import Path
import struct
import unittest


spec = importlib.util.spec_from_file_location(
    "effects_probe", Path(__file__).with_name("inspect-rerev2-split-effects.py")
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakeReader:
    def __init__(self, split=1, gate=bytes.fromhex("0f841d470000")):
        self.memory = {
            0x886DF0: bytes.fromhex("8b81f4080000c3"),
            0x157AE00: struct.pack("<I", 0x200000),
            0x2008F0: struct.pack("<2I", 1, split),
            0x15DE88C: struct.pack("<I", 0x300000),
            0x300CE0: struct.pack("<I", split),
            0xA7C3B9: gate,
            0xA85C7A: bytes.fromhex("ba060000000f44ca"),
            0x158111C: struct.pack("<I", 0),
            0x15DF97C: struct.pack("<I", 0),
        }

    def read(self, address, length):
        value = self.memory[address]
        if len(value) != length:
            raise AssertionError((address, length, len(value)))
        return value

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]


class EffectsTests(unittest.TestCase):
    def test_native_split_blocks_creation(self):
        state = probe.snapshot(FakeReader())
        self.assertTrue(state["guiSplitPredicate9553D0"])
        self.assertTrue(state["creationBlockedBySplitGate"])
        self.assertIsNone(state["bulletMarks"])

    def test_single_player_not_blocked(self):
        state = probe.snapshot(FakeReader(split=0))
        self.assertFalse(state["guiSplitPredicate9553D0"])
        self.assertFalse(state["creationBlockedBySplitGate"])

    def test_opt_in_patch_does_not_change_split(self):
        state = probe.snapshot(FakeReader(gate=b"\x90" * 6))
        self.assertTrue(state["guiSplitPredicate9553D0"])
        self.assertEqual(state["bulletMarkCreationGate"], "bypassed")
        self.assertFalse(state["creationBlockedBySplitGate"])

    def test_unknown_gate_is_not_assumed_safe(self):
        state = probe.snapshot(FakeReader(gate=b"\xCC" * 6))
        self.assertEqual(state["bulletMarkCreationGate"], "unknown")
        self.assertIsNone(state["creationBlockedBySplitGate"])

    def test_wrong_accessor_is_rejected(self):
        reader = FakeReader()
        reader.memory[0x886DF0] = b"\xCC" * 7
        with self.assertRaises(RuntimeError):
            probe.snapshot(reader)

    def test_exclusion_mask_is_reported_separately(self):
        reader = FakeReader()
        reader.memory.update({
            0x15DF97C: struct.pack("<I", 0x400000),
            0x400000: struct.pack("<I", 0x13D7E48),
            0x400228: struct.pack("<I", 6),
        })
        state = probe.snapshot(reader)
        self.assertEqual(state["effectsManager"]["exclusionTraitMask"], "0x00000006")
        self.assertTrue(state["effectsManager"]["excludesTrait2"])
        self.assertTrue(state["effectsManager"]["excludesTrait4"])

    def test_disabled_filter_code_keeps_split_state(self):
        reader = FakeReader()
        reader.memory[0xA85C7A] = bytes.fromhex("ba000000000f44ca")
        state = probe.snapshot(reader)
        self.assertEqual(state["coopEffectFilterCode"], "disabled")
        self.assertTrue(state["guiSplitPredicate9553D0"])

    def test_unknown_filter_code_is_reported(self):
        reader = FakeReader()
        reader.memory[0xA85C7A] = b"\xCC" * 8
        self.assertEqual(probe.snapshot(reader)["coopEffectFilterCode"], "unknown")


if __name__ == "__main__":
    unittest.main()
