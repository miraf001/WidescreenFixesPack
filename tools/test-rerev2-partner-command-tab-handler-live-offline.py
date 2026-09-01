"""Offline CPU tests for the local ChangeCharacter Tab result hook."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "out/toolchain/unicorn-2.1.3"))
from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32
from unicorn import x86_const as x


spec = importlib.util.spec_from_file_location(
    "live", Path(__file__).with_name("test-rerev2-partner-command-tab-handler-live.py")
)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


CODE, DATA, GET_KEY = 0x20000000, 0x20001000, 0x30000000
MODE, MANAGER, P1, P2 = 0x40000000, 0x41000000, 0x42000000, 0x42010000
STACK, ESP = 0x70000000, 0x70008000


def dword(value):
    return struct.pack("<I", value)


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for address, size in (
            (CODE, 0x2000), (GET_KEY, 0x1000), (MODE, 0x2000),
            (MANAGER, 0x1000), (P1, 0x20000), (STACK, 0x10000),
            (live.MODE_POINTER & ~0xFFF, 0x1000),
            (live.ACTOR_MANAGER & ~0xFFF, 0x1000),
            (live.CONTINUATION & ~0xFFF, 0x1000),
        ):
            self.uc.mem_map(address, size)
        self.uc.mem_write(CODE, live.make_thunk(CODE, DATA, GET_KEY))
        self.uc.mem_write(live.MODE_POINTER, dword(MODE))
        self.uc.mem_write(live.ACTOR_MANAGER, dword(MANAGER))
        self.uc.mem_write(MODE + 0x8F0, dword(1) + dword(1) + dword(0) + dword(1))
        self.uc.mem_write(MANAGER + 0x20, dword(P1) + dword(P2))
        self.uc.mem_write(GET_KEY, b"\xA1" + dword(DATA + 20) + bytes.fromhex("C2 04 00"))
        self.set_key(False)
        self.uc.hook_add(UC_HOOK_CODE, self.stop)

    def stop(self, uc, address, size, unused):
        if address == live.CONTINUATION:
            uc.emu_stop()

    def set_key(self, down):
        self.uc.mem_write(DATA + 20, dword(0x8000 if down else 0))

    def execute(self, native_al=0, actor=P1):
        original_eax = 0x12345600 | native_al
        registers = {
            x.UC_X86_REG_EAX: original_eax, x.UC_X86_REG_ECX: 0x22222222,
            x.UC_X86_REG_EDX: 0x33333333, x.UC_X86_REG_EBX: 0x44444444,
            x.UC_X86_REG_EBP: 0x55555555, x.UC_X86_REG_ESI: 0x66666666,
            x.UC_X86_REG_EDI: actor, x.UC_X86_REG_EFLAGS: 0x246,
        }
        xmm = tuple(int.from_bytes(bytes([i + 1]) * 16, "little") for i in range(8))
        for register, value in registers.items():
            self.uc.reg_write(register, value)
        for i, value in enumerate(xmm):
            self.uc.reg_write(getattr(x, f"UC_X86_REG_XMM{i}"), value)
        self.uc.reg_write(x.UC_X86_REG_ESP, ESP)
        self.uc.emu_start(CODE, live.CONTINUATION + 1)
        result = self.uc.reg_read(x.UC_X86_REG_EAX)
        self.assertEqual(result & 0xFFFFFF00, original_eax & 0xFFFFFF00)
        for register, value in registers.items():
            if register not in (x.UC_X86_REG_EAX, x.UC_X86_REG_EFLAGS):
                self.assertEqual(self.uc.reg_read(register), value)
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_EFLAGS), registers[x.UC_X86_REG_EFLAGS])
        for i, value in enumerate(xmm):
            self.assertEqual(self.uc.reg_read(getattr(x, f"UC_X86_REG_XMM{i}")), value)
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_ESP), ESP)
        return result & 0xFF

    def counters(self):
        return struct.unpack("<4I", self.uc.mem_read(DATA, 16))

    def test_mp_p1_returns_one_only_on_rising_tab_edge(self):
        self.set_key(True)
        self.assertEqual(self.execute(), 1)
        self.assertEqual(self.counters(), (1, 1, 1, 1))
        self.assertEqual(self.execute(native_al=1), 0)
        self.assertEqual(self.counters(), (1, 2, 2, 1))
        self.set_key(False)
        self.assertEqual(self.execute(native_al=1), 0)
        self.assertEqual(self.counters(), (0, 3, 3, 1))

    def test_sp_preserves_native_change_character_result(self):
        self.uc.mem_write(MODE + 0x8F0, dword(0))
        self.set_key(True)
        self.assertEqual(self.execute(native_al=0), 0)
        self.assertEqual(self.execute(native_al=1), 1)
        self.assertEqual(self.counters(), (0, 2, 0, 0))

    def test_non_primary_actor_preserves_native_result(self):
        self.set_key(True)
        self.assertEqual(self.execute(native_al=1, actor=P2), 1)
        self.assertEqual(self.counters(), (0, 1, 0, 0))


if __name__ == "__main__":
    unittest.main()
