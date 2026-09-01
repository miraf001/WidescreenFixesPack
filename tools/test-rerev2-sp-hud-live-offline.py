"""Offline checks for the exact native thunk and transactional live-HUD patcher."""

import importlib.util
from pathlib import Path
from contextlib import nullcontext
import struct
import sys
import unittest

spec = importlib.util.spec_from_file_location("hud_live", Path(__file__).with_name("test-rerev2-sp-hud-live.py"))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "out/toolchain/capstone-5.0.9"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM


class FakeProcess:
    def __init__(self):
        self.memory = {1: b"a", 2: b"b"}
        self.calls = 0
        self.fail_once = False

    def suspended(self):
        return nullcontext()

    def expect(self, address, expected):
        if self.memory[address] != expected:
            raise RuntimeError("Mismatch")

    def integer(self, address):
        return struct.unpack("<I", self.memory[address])[0]

    def read(self, address, size):
        return self.memory[address][:size]

    def patch(self, address, value):
        self.calls += 1
        self.memory[address] = value
        if self.fail_once and self.calls == 2:
            raise RuntimeError("Simulated failure after write")


class Tests(unittest.TestCase):
    @staticmethod
    def stretch_fixture(flags):
        process = FakeProcess()
        process.memory.update({0x1000: live.u32(0x139AE20),
                               0x10F0: live.u32(0x3000) + live.u32(0x2000),
                               0x206C: live.u32(0x1000),
                               0x2100: live.u32(0x141D330),
                               0x216C: live.u32(0x1000),
                               0x2154: live.u32(0x40000B),
                               0x2180: live.u32(flags), 0x1170: live.u32(960)})
        state = {"allocation": 0x30000000, "stretch": {"status": "applied",
                 "trees": [{"controller": 0x1000, "root": 0x2000, "resource": 0x3000, "vtable": 0x139AE20}],
                 "nodes": [{"node": 0x2100, "owner": 0x1000, "vtable": 0x141D330,
                            "before": 0xFF150002, "after": 0xFF120002}]}}
        return process, state

    def test_aspect_instruction_and_redirect_cover_one_complete_instruction(self):
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        original = list(decoder.disasm(live.GEOMETRY_X_BYTES, live.GEOMETRY_X_LOAD))
        self.assertEqual(len(original), 1)
        self.assertEqual(original[0].mnemonic, "movss")
        redirect = live.aspect_redirect(0x32000000)
        self.assertEqual(len(redirect), len(live.GEOMETRY_X_BYTES))
        self.assertEqual(live.GEOMETRY_X_LOAD + 5 + struct.unpack("<i", redirect[1:5])[0], 0x32000000)
        self.assertEqual(redirect[5:], b"\x90" * 4)

    def test_aspect_branches_target_instruction_boundaries(self):
        _, state = self.stretch_fixture(0xFF120002)
        address = 0x32000000
        code = live.make_aspect_thunk(address, address + 4096, state["stretch"])
        decoder = Cs(CS_ARCH_X86, CS_MODE_32)
        decoder.detail = True
        instructions = list(decoder.disasm(code, address))
        self.assertEqual(sum(i.size for i in instructions), len(code))
        boundaries = {i.address for i in instructions}
        exits = []
        for item in instructions:
            if item.mnemonic.startswith("j"):
                self.assertEqual(item.operands[0].type, X86_OP_IMM)
                target = item.operands[0].imm
                if target not in boundaries:
                    exits.append(target)
        self.assertEqual(exits, [live.GEOMETRY_X_LOAD + len(live.GEOMETRY_X_BYTES)])
        self.assertEqual([i.mnemonic for i in instructions[:2]], ["pushfd", "push"])
        self.assertEqual([i.mnemonic for i in instructions[-3:]], ["pop", "popfd", "jmp"])
        self.assertEqual(instructions[1].op_str, "edx")
        self.assertEqual(instructions[-3].op_str, "edx")
        self.assertFalse(any(i.mnemonic == "call" for i in instructions))
        loads = [i.op_str for i in instructions if i.mnemonic == "movss"]
        self.assertEqual(loads, ["xmm1, dword ptr [eax + ecx*8 + 0x1cc]",
                                 "xmm1, dword ptr [eax + ecx*8 + 0x1c8]"])
        self.assertTrue(all(i.mnemonic in ("pushfd", "push", "cmp", "jne", "mov", "test",
                                           "je", "jmp", "lock inc", "movss", "pop", "popfd")
                            for i in instructions))
        for item in instructions:
            if item.mnemonic == "mov":
                self.assertEqual(item.op_str, "edx, dword ptr [0x157ae00]")
            if item.mnemonic == "lock inc":
                self.assertEqual(item.op_str, "dword ptr [0x32001000]")
        self.assertLess(len(code), 4096)

    def test_aspect_contains_instance_ownership_and_mode_guards(self):
        _, state = self.stretch_fixture(0xFF120002)
        code = live.make_aspect_thunk(0x32000000, 0x32001000, state["stretch"])
        for fragment in ("83 f9 02", "83 ba f0 08 00 00 01", "83 ba f4 08 00 00 01",
                         "3d 00 10 00 00", "81 38 20 ae 39 01",
                         "81 b8 f0 00 00 00 00 30 00 00", "81 b8 f4 00 00 00 00 20 00 00",
                         "81 fe 00 21 00 00", "81 3e 30 d3 41 01"):
            self.assertIn(bytes.fromhex(fragment), code)

    def test_aspect_restore_keeps_existing_sp_layout_and_refreshes(self):
        process, state = self.stretch_fixture(0xFF120002)
        state["aspect"] = {"status": "applied", "allocation": 0x32000000}
        process.memory[live.GEOMETRY_X_LOAD] = live.aspect_redirect(0x32000000)
        live.restore_aspect(process, state)
        self.assertEqual(process.memory[live.GEOMETRY_X_LOAD], live.GEOMETRY_X_BYTES)
        self.assertEqual(process.integer(0x1170), 0xFFFFFFFF)
        self.assertEqual(process.integer(0x2180), 0xFF120002)
        self.assertEqual(state["aspect"]["status"], "restored")
        self.assertEqual(state["stretch"]["status"], "applied")

    def test_aspect_restore_rejects_unexpected_code(self):
        process, state = self.stretch_fixture(0xFF120002)
        state["aspect"] = {"status": "applied", "allocation": 0x32000000}
        process.memory[live.GEOMETRY_X_LOAD] = bytes(9)
        with self.assertRaises(RuntimeError):
            live.restore_aspect(process, state)
        self.assertEqual(process.calls, 0)

    def test_aspect_restore_removes_hook_even_when_old_tree_is_stale(self):
        process, state = self.stretch_fixture(0xFF120002)
        state["aspect"] = {"status": "applied", "allocation": 0x32000000}
        process.memory[live.GEOMETRY_X_LOAD] = live.aspect_redirect(0x32000000)
        process.memory[0x1000] = live.u32(0)
        live.restore_aspect(process, state)
        self.assertEqual(process.memory[live.GEOMETRY_X_LOAD], live.GEOMETRY_X_BYTES)
        self.assertEqual(state["aspect"]["status"], "restored")
        self.assertIn("cacheRefreshWarning", state["aspect"])
        self.assertEqual(process.integer(0x1170), 960)

    def test_restore_selector_preserves_later_native_flags(self):
        for flags in (0xEF120123, 0xEF150123):
            process, state = self.stretch_fixture(flags)
            live.restore_stretch(process, state)
            self.assertEqual(process.integer(0x2180), 0xEF150123)
            self.assertEqual(process.integer(0x2154), 0x41000B)
            self.assertEqual(state["stretch"]["status"], "restored")

    def test_restore_also_removes_native_update_hooks(self):
        process, state = self.stretch_fixture(0xFF120002)
        state["stretch"]["updateHookStatus"] = "applied"
        for index, (_, vtable, _, _, _, _) in enumerate(live.DEFINITIONS):
            process.memory[vtable + 0x24] = live.u32(live.scale_update_address(state["allocation"], index))
        live.restore_stretch(process, state)
        for _, vtable, updater, _, _, _ in live.DEFINITIONS:
            self.assertEqual(process.integer(vtable + 0x24), updater)

    def test_refresh_invalidates_cache_not_actual_viewport_or_nodes(self):
        process, state = self.stretch_fixture(0xFF120002)
        live.refresh_stretch(process, state)
        self.assertEqual(process.integer(0x1170), 0xFFFFFFFF)
        self.assertEqual(process.integer(0x2180), 0xFF120002)

    def test_scale_update_thunks_preserve_call_contract_and_bound_scope(self):
        for index, (_, _, updater, _, _, nodes) in enumerate(live.DEFINITIONS):
            address = live.scale_update_address(0x30000000, index)
            code = live.make_scale_update_thunk(address, 0x30001020 + index * 4, updater, nodes)
            self.assertEqual(code[:5], bytes.fromhex("56 53 8b f1 b8"))
            self.assertEqual(code[5:9], live.u32(updater))
            self.assertEqual(code[9:12], bytes.fromhex("ff d0 50"))
            self.assertEqual(code[-4:], bytes.fromhex("58 5b 5e c3"))
            self.assertLessEqual(len(code), 0x200)
            self.assertEqual(code.count(bytes.fromhex("39 70 6c")), len(nodes))
            self.assertEqual(code.count(bytes.fromhex("09 90 80 00 00 00")), len(nodes))
            self.assertIn(live.u32(0x50000), code)
            self.assertIn(live.u32(0x20000), code)

    def test_independent_scale_selector_preserves_other_flags(self):
        self.assertEqual(live.stretch_flags(0xFF150002), 0xFF120002)
        for flags in (0xFF150002, 0x00150000, 0x01A5FFFF):
            changed = live.stretch_flags(flags)
            self.assertEqual((changed >> 16) & 15, 2)
            self.assertEqual(changed & ~0xF0000, flags & ~0xF0000)

    def test_independent_scale_selector_rejects_other_modes(self):
        for mode in (0, 1, 2, 7, 8, 10, 15):
            with self.assertRaises(ValueError):
                live.stretch_flags(0xFF100002 | (mode << 16))

    def test_guard_failure_prevents_any_write(self):
        process = FakeProcess()
        with self.assertRaises(RuntimeError):
            live.transact(process, [(1, b"a", b"x")], guards=[(2, b"wrong")])
        self.assertEqual(process.calls, 0)

    def test_native_cache_invalidation_preserves_current_flags(self):
        process = FakeProcess()
        process.memory[0x154] = live.u32(0x81000B)
        live.transact(process, [(1, b"a", b"x")], dirty_nodes=[0x100])
        self.assertEqual(process.integer(0x154), 0x81000B)
        process.memory[0x154] = live.u32(0x40000B)
        live.transact(process, [(1, b"a", b"x")], restore=True, dirty_nodes=[0x100])
        self.assertEqual(process.integer(0x154), 0x41000B)

    def test_cache_write_failure_rolls_back_layout_and_flags(self):
        process = FakeProcess()
        process.memory[0x154] = live.u32(0x40000B)
        process.fail_once = True
        with self.assertRaises(RuntimeError):
            live.transact(process, [(1, b"a", b"x")], dirty_nodes=[0x100])
        self.assertEqual(process.memory[1], b"a")
        self.assertEqual(process.integer(0x154), 0x40000B)

    def test_hash_shape(self):
        self.assertEqual(len(live.ASI_HASH), 64)
        bytes.fromhex(live.ASI_HASH)

    def test_thunk_branches_and_register_balance(self):
        # These fixed offsets are independently decoded in the Capstone check.
        address, counter, core = 0x30000000, 0x30001000, 0x58AA1C40
        code = live.make_thunk(address, counter, core)
        self.assertEqual(code[:8], b"\x50\xa1" + live.u32(live.MODE_POINTER) + b"\x85\xc0")
        self.assertEqual(code[10:17], bytes.fromhex("83b8f008000001"))
        self.assertEqual(code[19:26], bytes.fromhex("83b8f408000001"))
        self.assertEqual(code[28:36], b"\x58\xf0\xff\x05" + live.u32(counter))
        self.assertEqual(code[36:39], bytes.fromhex("31d2e9"))
        for jump in (8, 17, 26):
            self.assertEqual(jump + 2 + code[jump + 1], 43)
        self.assertEqual(address + 43 + struct.unpack("<i", code[39:43])[0], core)
        self.assertEqual(code[43:45], b"\x58\xe9")
        self.assertEqual(address + 49 + struct.unpack("<i", code[45:49])[0], live.DRAW_ENTRY)

    def test_patch_scope(self):
        patches = live.patch_set(0x30000000)
        self.assertEqual(len(patches), 6)
        self.assertEqual([p[0] for p in patches[::2]], [0x8E4067, 0x8E99D1, 0x8E9EA3])
        self.assertTrue(all(a % 4 == 0 and len(b) == len(c) == 4 for a, b, c in patches[1::2]))
        self.assertTrue(all(b == b"\x84" and c == b"\x30" for _, b, c in patches[::2]))

    def test_success_and_restore(self):
        process = FakeProcess()
        patches = [(1, b"a", b"x"), (2, b"b", b"y")]
        live.transact(process, patches)
        self.assertEqual(process.memory, {1: b"x", 2: b"y"})
        live.transact(process, patches, restore=True)
        self.assertEqual(process.memory, {1: b"a", 2: b"b"})

    def test_mismatch_does_not_write(self):
        process = FakeProcess()
        with self.assertRaises(RuntimeError):
            live.transact(process, [(1, b"a", b"x"), (2, b"wrong", b"y")])
        self.assertEqual(process.calls, 0)

    def test_failure_restores_even_attempted_write(self):
        process = FakeProcess()
        process.fail_once = True
        with self.assertRaises(RuntimeError):
            live.transact(process, [(1, b"a", b"x"), (2, b"b", b"y")])
        self.assertEqual(process.memory, {1: b"a", 2: b"b"})


if __name__ == "__main__":
    unittest.main()
