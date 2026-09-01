"""Offline x86 tests; no game process or virtual controller is opened."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "out/toolchain/unicorn-2.1.3"))
sys.path.insert(0, str(ROOT / "out/toolchain/capstone-5.0.9"))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_WRITE
from unicorn import x86_const as x
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

spec = importlib.util.spec_from_file_location("reticle", Path(__file__).with_name("test-rerev2-reticle-live.py"))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
h = live.hud
A, C, R, N, RESOURCE, TABLE, MODE, STACK, FALLBACK = (
    0x3000000, 0x4000000, 0x4001000, 0x4001100, 0x4002000,
    0x4003000, 0x5000000, 0x6000000, 0x7000000)
GPRS = [getattr(x, "UC_X86_REG_" + name) for name in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP")]
XMMS = [getattr(x, "UC_X86_REG_XMM" + str(i)) for i in range(8)]


def fixture():
    return {"allocation": A, "core": 0x58AA1C40, "parentAspect": FALLBACK,
            "stretch": {"trees": [{"controller": C, "vtable": live.RETICLE[1],
                                   "root": R, "resource": RESOURCE}],
                        "nodes": [{"node": N, "owner": C, "vtable": 0x141D330}]}}


def machine(split=1):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = set()
    for address, size in ((A, 0x2000), (C, 0x4000), (MODE, 4096), (STACK, 4096),
                          (FALLBACK, 4096), (h.MODE_POINTER & ~4095, 4096),
                          (h.GEOMETRY_X_LOAD & ~4095, 4096), (live.RETICLE[2] & ~4095, 4096)):
        for page in range(address, address + size, 4096):
            if page not in pages:
                uc.mem_map(page, 4096)
                pages.add(page)
    for addr, data in ((h.MODE_POINTER, h.u32(MODE)), (MODE + 0x8F0, h.u32(split) * 2),
                       (C, h.u32(live.RETICLE[1])), (C + 0xF0, h.u32(RESOURCE) + h.u32(R)),
                       (C + 0xF8, h.u32(TABLE)), (TABLE, h.u32(N)), (N, h.u32(0x141D330)),
                       (N + 0x6C, h.u32(C))):
        uc.mem_write(addr, data)
    for index, reg in enumerate(GPRS + XMMS):
        uc.reg_write(reg, 0x12345600 + index)
    uc.reg_write(x.UC_X86_REG_ESP, STACK + 0x800)
    uc.reg_write(x.UC_X86_REG_EFLAGS, 0x602)
    for addr, code in live.code_blobs(fixture()):
        uc.mem_write(addr, code)
    return uc


class Tests(unittest.TestCase):
    def test_exact_patch_scope(self):
        patches = live.code_patches(fixture())
        self.assertEqual([p[0] for p in patches], [0x94FC3C, 0x13A38C0, 0x13A388C, 0xE6308A])
        self.assertEqual(patches[0][1:], (b"\x84", b"\x30"))
        self.assertNotEqual(live.LAYOUT_TEST, live.RETICLE[3] + 5)
        self.assertEqual(live.RETICLE[5], (0,))
        self.assertEqual(patches[-1][1], h.aspect_redirect(FALLBACK))

    def test_code_slots_and_branch_boundaries(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        for (address, code), limit in zip(live.code_blobs(fixture()), (A + 0x400, A + 0x800, A + 4096)):
            instructions = list(decoder.disasm(code, address))
            self.assertEqual(sum(i.size for i in instructions), len(code))
            self.assertLessEqual(address + len(code), limit)
            boundaries = {i.address for i in instructions}
            for ins in instructions:
                if ins.mnemonic.startswith("j"):
                    self.assertIn(ins.operands[0].imm, boundaries | {FALLBACK, h.GEOMETRY_X_LOAD + 9, fixture()["core"], h.DRAW_ENTRY})

    def test_layout_instruction_selects_native_sp_branch(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        instructions = list(decoder.disasm(bytes.fromhex("30c0743b"), live.LAYOUT_TEST))
        self.assertEqual([i.mnemonic for i in instructions], ["xor", "je"])
        self.assertEqual(instructions[0].op_str, "al, al")
        self.assertEqual(instructions[1].op_str, "0x94fc7b")

    def check_update(self, split, flags, expected, foreign=False):
        uc = machine(split)
        uc.mem_write(N + 0x80, h.u32(flags))
        uc.mem_write(N + 0x54, h.u32(0x40000B))
        if foreign:
            uc.mem_write(N + 0x6C, h.u32(C + 0x100))
        # Stub the unmodified updater's ABI, not the game logic itself.
        uc.mem_write(live.RETICLE[2], b"\xB8" + h.u32(0x87654321) + b"\xC3")
        uc.mem_write(STACK + 0x800, h.u32(FALLBACK))
        uc.reg_write(x.UC_X86_REG_ECX, C)
        preserved = [x.UC_X86_REG_EAX, x.UC_X86_REG_EBX, x.UC_X86_REG_ESI, x.UC_X86_REG_EDI, x.UC_X86_REG_EBP] + XMMS
        before = [uc.reg_read(r) for r in preserved]
        before[0] = 0x87654321  # Preserve native RETURN EAX, not pre-call EAX.
        writes = []
        uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u, _a, addr, size, _v, _d: writes.append((addr, size)))
        uc.emu_start(A + live.UPDATE_OFFSET, FALLBACK, count=100)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EIP), FALLBACK)
        self.assertEqual(before, [uc.reg_read(r) for r in preserved])
        self.assertEqual(uc.reg_read(x.UC_X86_REG_ESP), STACK + 0x804)
        self.assertEqual(struct.unpack("<I", uc.mem_read(N + 0x80, 4))[0], expected)
        for address, size in writes:
            self.assertTrue(STACK <= address < address + size <= STACK + 4096 or
                            (address, size) in ((N + 0x80, 4), (N + 0x54, 4), (A + 0x1004, 4)))

    def test_mp_selector_and_sp_restore(self):
        self.check_update(1, 0xFF150002, 0xFF120002)
        self.check_update(1, 0xFF120002, 0xFF120002)
        self.check_update(0, 0xFF120002, 0xFF150002)
        self.check_update(0, 0xFF150002, 0xFF150002)

    def test_update_ignores_foreign_nodes_and_other_selectors(self):
        self.check_update(1, 0xFF150002, 0xFF150002, foreign=True)
        self.check_update(1, 0xFF170002, 0xFF170002)

    def check_geometry(self, width, height, split=1, wrong_node=False):
        uc = machine(split)
        sx, sy = width / 1280, height / 720
        uc.mem_write(C + 0x1D8, struct.pack("<2f", sx, sy))
        # Previous chain eventually performs the original instruction.
        native = h.GEOMETRY_X_BYTES + b"\xE9" + h.u32((h.GEOMETRY_X_LOAD + 9 - (FALLBACK + 14)) & 0xFFFFFFFF)
        uc.mem_write(FALLBACK, native)
        uc.reg_write(x.UC_X86_REG_EAX, C)
        uc.reg_write(x.UC_X86_REG_ECX, 2)
        uc.reg_write(x.UC_X86_REG_ESI, N + (0x100 if wrong_node else 0))
        before = [uc.reg_read(r) for r in GPRS]
        xmm_before = [uc.reg_read(r) for r in XMMS]
        flags_before = uc.reg_read(x.UC_X86_REG_EFLAGS)
        uc.emu_start(A + live.ASPECT_OFFSET, h.GEOMETRY_X_LOAD + 9, count=100)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EIP), h.GEOMETRY_X_LOAD + 9)
        self.assertEqual(before, [uc.reg_read(r) for r in GPRS])
        self.assertEqual(flags_before, uc.reg_read(x.UC_X86_REG_EFLAGS))
        expected = sy if split and not wrong_node else sx
        self.assertEqual(uc.reg_read(x.UC_X86_REG_XMM1), struct.unpack("<I", struct.pack("<f", expected))[0])
        for i in (0, 2, 3, 4, 5, 6, 7):
            self.assertEqual(uc.reg_read(XMMS[i]), xmm_before[i])
        # Position mapping is independent from shape, not a post-render offset.
        self.assertAlmostEqual(640 * sx, width / 2)
        self.assertAlmostEqual(360 * sy, height / 2)

    def test_geometry_uses_height_on_narrow_normal_and_ultrawide_viewports(self):
        for width, height in ((960, 1080), (1280, 720), (1920, 1080), (2560, 1440), (3440, 1440), (3840, 1080)):
            with self.subTest(width=width, height=height):
                self.check_geometry(width, height)

    def test_geometry_keeps_sp_and_unmatched_hud_on_previous_chain(self):
        self.check_geometry(960, 1080, split=0)
        self.check_geometry(960, 1080, wrong_node=True)


if __name__ == "__main__":
    unittest.main()
