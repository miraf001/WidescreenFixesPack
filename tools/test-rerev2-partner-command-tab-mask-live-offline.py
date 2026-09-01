"""Offline CPU verification for the MP-only Tab gameplay-mask thunk."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "out/toolchain/unicorn-2.1.3"))

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32
from unicorn import x86_const as x


spec = importlib.util.spec_from_file_location(
    "live", Path(__file__).with_name("test-rerev2-partner-command-tab-mask-live.py")
)
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


CODE = 0x20000000
DATA = CODE + 0x1000
GET_KEY = 0x30000000
MODE = 0x40000000
MANAGER = 0x41000000
P1 = 0x42000000
P2 = 0x42010000
STACK = 0x70000000
ESP = STACK + 0x8000


def dword(value: int) -> bytes:
    return struct.pack("<I", value)


class TabMaskThunkTests(unittest.TestCase):
    def setUp(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for address, size in (
            (CODE, 0x2000),
            (GET_KEY, 0x1000),
            (MODE, 0x2000),
            (MANAGER, 0x1000),
            (P1, 0x20000),
            (STACK, 0x10000),
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
        self.set_key(True)
        self.uc.hook_add(UC_HOOK_CODE, self.stop_at_continuation)

    def stop_at_continuation(self, uc, address, size, unused):
        if address == live.CONTINUATION:
            uc.emu_stop()

    def set_key(self, down: bool):
        # Keep the fake function's code stable so Unicorn's translation cache
        # cannot retain an earlier immediate between frames.
        self.uc.mem_write(GET_KEY, bytes.fromhex("A1") + dword(DATA + 20) + bytes.fromhex("C2 04 00"))
        self.uc.mem_write(DATA + 20, dword(0x8000 if down else 0))

    def run_frame(self, actor=P1, mask=0x00400000):
        registers = {
            x.UC_X86_REG_EAX: 0x11111111,
            x.UC_X86_REG_ECX: 0x22222222,
            x.UC_X86_REG_EDX: 0x33333333,
            x.UC_X86_REG_EBX: 0x44444444,
            x.UC_X86_REG_EBP: 0x55555555,
            x.UC_X86_REG_ESI: actor,
            x.UC_X86_REG_EDI: 0x66666666,
            x.UC_X86_REG_EFLAGS: 0x246,
        }
        xmm = tuple(int.from_bytes(bytes([index + 1]) * 16, "little") for index in range(8))
        for register, value in registers.items():
            self.uc.reg_write(register, value)
        for index, value in enumerate(xmm):
            self.uc.reg_write(getattr(x, f"UC_X86_REG_XMM{index}"), value)
        self.uc.reg_write(x.UC_X86_REG_ESP, ESP)
        self.uc.mem_write(ESP + 0x28, dword(mask))
        expected_xmm0 = int.from_bytes(bytes.fromhex("00 00 80 3F") + bytes(12), "little")
        self.uc.mem_write(ESP + 0x8C, bytes.fromhex("00 00 80 3F"))
        self.uc.emu_start(CODE, live.CONTINUATION + 1)
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_ESP), ESP)
        for register, value in registers.items():
            if register != x.UC_X86_REG_EFLAGS:
                self.assertEqual(self.uc.reg_read(register), value)
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_EFLAGS), registers[x.UC_X86_REG_EFLAGS])
        self.assertEqual(self.uc.reg_read(x.UC_X86_REG_XMM0), expected_xmm0)
        for index, value in enumerate(xmm[1:], 1):
            self.assertEqual(self.uc.reg_read(getattr(x, f"UC_X86_REG_XMM{index}")), value)
        return struct.unpack("<I", self.uc.mem_read(ESP + 0x28, 4))[0]

    def counters(self):
        return struct.unpack("<5I", self.uc.mem_read(DATA, 20))

    def test_rising_edge_pulses_once_and_release_rearms(self):
        self.assertEqual(self.run_frame(), 0x00401000)
        self.assertEqual(self.counters(), (1, 1, 1, 1, 1))
        self.assertEqual(self.run_frame(), 0x00400000)
        self.assertEqual(self.counters(), (1, 2, 2, 1, 1))
        self.set_key(False)
        self.assertEqual(self.run_frame(), 0x00400000)
        self.assertEqual(self.counters(), (0, 3, 3, 1, 1))
        self.set_key(True)
        self.assertEqual(self.run_frame(), 0x00401000)
        self.assertEqual(self.counters(), (1, 4, 4, 2, 2))

    def test_p2_does_not_modify_mask_or_clear_p1_edge_state(self):
        self.assertEqual(self.run_frame(), 0x00401000)
        self.assertEqual(self.run_frame(actor=P2), 0x00400000)
        self.assertEqual(self.counters(), (1, 2, 1, 1, 1))
        self.assertEqual(self.run_frame(), 0x00400000)
        self.assertEqual(self.counters(), (1, 3, 2, 1, 1))

    def test_single_player_does_not_query_or_inject_and_resets_edge(self):
        self.assertEqual(self.run_frame(), 0x00401000)
        self.uc.mem_write(MODE + 0x8F0, dword(0))
        self.assertEqual(self.run_frame(), 0x00400000)
        self.assertEqual(self.counters(), (0, 2, 1, 1, 1))
        self.uc.mem_write(MODE + 0x8F0, dword(1))
        self.assertEqual(self.run_frame(), 0x00401000)
        self.assertEqual(self.counters(), (1, 3, 2, 2, 2))


if __name__ == "__main__":
    unittest.main()
