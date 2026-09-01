"""Offline instruction-boundary and isolation checks for the Flash extension."""
import importlib.util
from pathlib import Path
import sys
import unittest

spec = importlib.util.spec_from_file_location("flash", Path(__file__).with_name("test-rerev2-flash-live.py"))
flash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flash)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "out/toolchain/capstone-5.0.9"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


class Tests(unittest.TestCase):
    def fixture(self):
        return {"allocation": 0x31000000, "core": 0x58AA1C40, "parentAspect": 0x32000000,
                "stretch": {"trees": [{"controller": 0x1000, "vtable": flash.FLASH[1],
                                       "root": 0x2000, "resource": 0x3000}],
                            "nodes": [{"node": 0x2100, "owner": 0x1000, "vtable": 0x141D330}]}}

    def test_three_nonoverlapping_code_slots(self):
        state = self.fixture()
        blobs = flash.code_blobs(state)
        for (address, code), limit in zip(blobs, (0x31000400, 0x31000800, 0x31001000)):
            self.assertLessEqual(address + len(code), limit)

    def test_chained_aspect_success_and_fallback_are_separate(self):
        state = self.fixture()
        address, code = flash.code_blobs(state)[2]
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        instructions = list(decoder.disasm(code, address))
        self.assertEqual(sum(i.size for i in instructions), len(code))
        boundaries = {i.address for i in instructions}
        exits = []
        for index, ins in enumerate(instructions):
            if ins.mnemonic.startswith("j") and ins.operands[0].imm not in boundaries:
                exits.append(ins.operands[0].imm)
                self.assertEqual([i.mnemonic for i in instructions[index-2:index]], ["pop", "popfd"])
                self.assertEqual(instructions[index-2].op_str, "edx")
        self.assertEqual(exits, [state["parentAspect"], flash.hud.GEOMETRY_X_LOAD + 9])
        self.assertEqual([i.op_str for i in instructions if i.mnemonic == "movss"],
                         ["xmm1, dword ptr [eax + ecx*8 + 0x1cc]"])

    def test_patch_scope_and_parent_return(self):
        state = self.fixture()
        patches = flash.code_patches(state)
        self.assertEqual([p[0] for p in patches], [0x8E838E, 0x139B5B0, 0x139B57C, 0xE6308A])
        self.assertEqual(patches[0][1:], (b"\x84", b"\x30"))
        self.assertEqual(patches[-1][1], flash.hud.aspect_redirect(state["parentAspect"]))
        self.assertEqual(flash.FLASH[5], (2,))


if __name__ == "__main__":
    unittest.main()
