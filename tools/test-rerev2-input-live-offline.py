"""Offline checks for the exact co-op input autodetection branch replacement."""
import importlib.util
from pathlib import Path
import sys
import unittest

spec = importlib.util.spec_from_file_location("input_live", Path(__file__).with_name("test-rerev2-input-live.py"))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "out/toolchain/capstone-5.0.9"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


class Tests(unittest.TestCase):
    def test_single_instruction_both_directions(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        for code, target in ((live.ORIGINAL, 0x9886A7), (live.PATCHED, 0x988622)):
            instructions = list(decoder.disasm(code, live.SITE))
            self.assertEqual(len(instructions), 1)
            self.assertEqual(instructions[0].size, 6)
            self.assertEqual(instructions[0].mnemonic, "je")
            self.assertEqual(instructions[0].operands[0].imm, target)

    def test_only_the_split_skip_displacement_changes(self):
        self.assertEqual([i for i, (a, b) in enumerate(zip(live.ORIGINAL, live.PATCHED)) if a != b], [2])
        self.assertEqual(live.SITE, 0x98861C)
        guards = dict(live.GUARDS)
        self.assertIn(bytes.fromhex("83 b8 f0 08 00 00 01"), guards[0x988610])
        self.assertEqual(guards[0xA15521], bytes.fromhex("83 be 20 79 00 00 00"))


if __name__ == "__main__":
    unittest.main()
