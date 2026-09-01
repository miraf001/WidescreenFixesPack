"""Offline branch/routing checks; no bridge or game process opened."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("capture", Path(__file__).with_name("sync-rerev2-bridge-capture.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "out/toolchain/capstone-5.0.9"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


class Tests(unittest.TestCase):
    def test_capture_uses_native_force_gamepad_path_without_changing_flags(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        instructions = list(decoder.disasm(capture.GAMEPAD, capture.base.SITE))
        self.assertEqual([i.mnemonic for i in instructions], ["jmp", "nop"])
        self.assertEqual(instructions[0].operands[0].imm, 0x9886A7)
        self.assertEqual(len(capture.GAMEPAD), 6)

    def test_released_input_keeps_confirmed_parent_autodetection(self):
        self.assertEqual(capture.choose_gate(False), capture.owner.base.PATCHED)
        self.assertEqual(capture.choose_gate(True), capture.GAMEPAD)

    def test_only_patch_on_change(self):
        process = Mock()
        process.read.return_value = capture.AUTO
        with patch.object(capture.hud, "transact") as transact:
            capture.set_gate(process, capture.AUTO)
            transact.assert_not_called()
            capture.set_gate(process, capture.GAMEPAD)
            transact.assert_called_once_with(process, [(capture.base.SITE, capture.AUTO, capture.GAMEPAD)], guards=capture.owner.GUARDS)

    def test_refuse_foreign_code_without_writes(self):
        process = Mock()
        process.read.return_value = b"\xcc" * 6
        with patch.object(capture.hud, "transact") as transact:
            with self.assertRaises(RuntimeError):
                capture.set_gate(process, capture.AUTO)
            transact.assert_not_called()

    def test_restore_only_the_capture_branch(self):
        process = Mock()
        process.read.return_value = capture.GAMEPAD
        with patch.object(capture.hud, "transact") as transact:
            capture.set_gate(process, capture.AUTO)
            transact.assert_called_once_with(process, [(capture.base.SITE, capture.GAMEPAD, capture.AUTO)], guards=capture.owner.GUARDS)


if __name__ == "__main__":
    unittest.main()
