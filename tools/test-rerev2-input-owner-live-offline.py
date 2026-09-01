"""Execute ownership thunks OFFLINE; never open a game or emulate controllers.

Unicorn here is only an x86 CPU test harness. Portable dependency:
python -m pip install --only-binary=:all: --no-deps --target out/toolchain/unicorn-2.1.3 unicorn==2.1.3
"""
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

spec = importlib.util.spec_from_file_location("owner", Path(__file__).with_name("test-rerev2-input-owner-live.py"))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)

THUNK, COUNTER = 0x2000000, 0x2002000
CFG, ACTOR, MANAGER, MODE, STACK = 0x3000000, 0x4000000, 0x5000000, 0x6000000, 0x7000000
GPRS = {name: getattr(x, "UC_X86_REG_" + name.upper())
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")}
REGISTERS = list(GPRS.values()) + [getattr(x, "UC_X86_REG_XMM" + str(i)) for i in range(8)]


def run_case(gate, split=1, assignment=0, actor_index=0, predicate=True, missing_manager=False, missing_mode=False):
    site, actor_reg, original = gate
    original = bytes.fromhex(original)
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for address, size in ((site & ~4095, 4096), (THUNK, 0x3000), (CFG, 0x160000),
                          (ACTOR, 0x20000), (MANAGER, 4096), (MODE, 4096), (STACK, 4096),
                          (live.hud.MODE_POINTER & ~4095, 4096), (live.ACTOR_MANAGER & ~4095, 4096)):
        uc.mem_map(address, size)
    uc.mem_write(site, original)
    uc.mem_write(THUNK, live.make_thunk(THUNK, COUNTER, gate))
    for index, reg in enumerate(REGISTERS):
        uc.reg_write(reg, (0xABCDEF00 + index) if index < 8 else (0x123456789ABCDEFFEDCBA9876543210 + index))
    uc.reg_write(x.UC_X86_REG_ESP, STACK + 0x800)
    uc.reg_write(x.UC_X86_REG_EFLAGS, 0x602) # preserve DF as well as normal flags
    actor = ACTOR + actor_index * 0x10000
    if gate[0] != 0xA14ECA:
        uc.reg_write(x.UC_X86_REG_EAX if original[1] == 0xB8 else x.UC_X86_REG_ECX, CFG)
        uc.mem_write(CFG + 0x15C4BC, struct.pack("<I", int(predicate)))
    else:
        uc.mem_write(actor + 0x7920, struct.pack("<I", 0 if predicate else 1))
    uc.reg_write(GPRS[actor_reg], actor)
    uc.mem_write(live.hud.MODE_POINTER, struct.pack("<I", 0 if missing_mode else MODE))
    uc.mem_write(live.ACTOR_MANAGER, struct.pack("<I", 0 if missing_manager else MANAGER))
    uc.mem_write(MODE + 0x8F0, struct.pack("<I", split))
    uc.mem_write(MODE + 0x8F8, struct.pack("<I", assignment))
    for i in range(2):
        uc.mem_write(MANAGER + 0x20 + i * 4, struct.pack("<I", ACTOR + i * 0x10000))
        uc.mem_write(ACTOR + i * 0x10000 + 0x790C, bytes([i]))
    before = [uc.reg_read(reg) for reg in REGISTERS]
    initial_flags = uc.reg_read(x.UC_X86_REG_EFLAGS)
    uc.emu_start(site, site + len(original), count=2)
    native_flags = uc.reg_read(x.UC_X86_REG_EFLAGS)
    for reg, value in zip(REGISTERS, before):
        uc.reg_write(reg, value)
    uc.reg_write(x.UC_X86_REG_EFLAGS, initial_flags)
    writes = []
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u, _a, addr, size, _value, _data: writes.append((addr, size)))
    uc.emu_start(THUNK, site + len(original), count=100)
    return {"before": before, "after": [uc.reg_read(reg) for reg in REGISTERS],
            "nativeFlags": native_flags, "flags": uc.reg_read(x.UC_X86_REG_EFLAGS),
            "ip": uc.reg_read(x.UC_X86_REG_EIP), "writes": writes,
            "counters": struct.unpack("<3I", uc.mem_read(COUNTER, 12))}


class Tests(unittest.TestCase):
    def check_case(self, gate, blocked=False, **kwargs):
        result = run_case(gate, **kwargs)
        self.assertEqual(result["before"], result["after"])
        self.assertEqual(result["ip"], gate[0] + len(bytes.fromhex(gate[2])))
        expected = result["nativeFlags"] & ~0x40 if blocked else result["nativeFlags"]
        self.assertEqual(result["flags"], expected)
        for address, size in result["writes"]:
            self.assertTrue(STACK <= address < address + size <= STACK + 4096 or
                            COUNTER <= address < address + size <= COUNTER + 12)
        self.assertEqual(result["counters"][1], int(blocked))
        return result

    def test_all_primary_paths_keep_native_input_and_registers(self):
        for gate in live.GATES:
            with self.subTest(site=hex(gate[0])):
                self.assertEqual(self.check_case(gate)["counters"], (1, 0, 0))

    def test_all_secondary_paths_take_original_gamepad_branch(self):
        for gate in live.GATES:
            with self.subTest(site=hex(gate[0])):
                self.check_case(gate, actor_index=1, blocked=True)

    def test_assignment_is_not_hardcoded_to_claire_or_slot_zero(self):
        for gate in live.GATES:
            with self.subTest(site=hex(gate[0])):
                self.check_case(gate, assignment=1, actor_index=1)
                self.check_case(gate, assignment=1, actor_index=0, blocked=True)

    def test_single_player_is_unchanged_for_either_actor(self):
        for gate in live.GATES:
            for actor in (0, 1):
                with self.subTest(site=hex(gate[0]), actor=actor):
                    self.assertEqual(self.check_case(gate, split=0, actor_index=actor)["counters"], (0, 0, 1))

    def test_original_false_result_is_preserved(self):
        for gate in live.GATES:
            with self.subTest(site=hex(gate[0])):
                self.assertEqual(self.check_case(gate, predicate=False, actor_index=1)["counters"], (0, 0, 1))

    def test_missing_or_invalid_primary_actor_fails_closed_in_coop(self):
        for gate in live.GATES:
            for assignment in (7, 8, 0xFFFFFFFF):
                with self.subTest(site=hex(gate[0]), assignment=assignment):
                    self.check_case(gate, assignment=assignment, blocked=True)
            self.check_case(gate, missing_manager=True, blocked=True)

    def test_missing_mode_uses_native_behavior(self):
        for gate in live.GATES:
            self.check_case(gate, missing_mode=True)

    def test_complete_original_instructions_and_bounded_redirects(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        sites = [g[0] for g in live.GATES]
        self.assertEqual(len(set(sites)), len(sites))
        for i, gate in enumerate(live.GATES):
            site, _, original = gate
            decoded = list(decoder.disasm(bytes.fromhex(original), site))
            self.assertEqual(len(decoded), 1)
            self.assertEqual(decoded[0].mnemonic, "cmp")
            address = THUNK + i * 256
            code = live.make_thunk(address, COUNTER, gate)
            instructions = list(decoder.disasm(code, address))
            self.assertEqual(sum(d.size for d in instructions), len(code))
            self.assertLessEqual(len(code), 256)
            boundaries = {d.address for d in instructions}
            for d in instructions:
                if d.mnemonic.startswith("j"):
                    self.assertIn(d.operands[0].imm, boundaries | {site + len(bytes.fromhex(original))})
            patch = live.redirect(site, address, len(bytes.fromhex(original)))
            redirect = next(decoder.disasm(patch, site))
            self.assertEqual(redirect.mnemonic, "jmp")
            self.assertEqual(redirect.operands[0].imm, address)


if __name__ == "__main__":
    unittest.main()
