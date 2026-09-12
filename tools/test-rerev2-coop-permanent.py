"""Test production C++-generated x86 offline; NEVER open the game process."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'out/toolchain/unicorn-2.1.3'))
sys.path.insert(0, str(ROOT / 'out/toolchain/capstone-5.0.9'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import x86_const as x
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(path))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

owner_tests = module('owner_tests', 'test-rerev2-input-owner-live-offline.py')
owner = owner_tests.live
inventory = module('inventory_live', 'test-rerev2-inventory-live.py')
command_far = module('command_far_live', 'test-rerev2-command-far-live.py')
parser = argparse.ArgumentParser()
parser.add_argument('--dump-exe', required=True)
args, extra = parser.parse_known_args()
output = subprocess.check_output([args.dump_exe], text=True)
BLOBS = {name: bytes.fromhex(data) for name, data in (line.split() for line in output.splitlines())}
A, COUNTER, C, N, TABLE, MODE, STACK, CONFIG = (0x2000000, 0x2002000, 0x4000000, 0x4001100, 0x4003000, 0x5000000, 0x6000000, 0x7000000)
GPRS = [getattr(x, 'UC_X86_REG_' + r) for r in ('EAX','EBX','ECX','EDX','ESI','EDI','EBP','ESP')]
XMMS = [getattr(x, 'UC_X86_REG_XMM' + str(i)) for i in range(8)]
CLASSES = ((0x139AE20, (0, 4)), (0x139B998, (3, 4)), (0x139BAF0, (0,)),
           (0x139B558, (2,)), (0x13A3868, (0,)))
CONFIRMED_INVENTORY_BLOB_SHA256 = '65664751cdb34abae26e9f9b2b9b7c0b9c6521fd11950b8e88b1bf22d8da31c0'
CONFIRMED_INVENTORY_EXPORTS = {
    '_InventoryDraw': 0,
    '_InventoryUpdate': 69,
    '_InventorySizeStandard': 90,
    '_InventorySizeAlternate': 117,
    '_CorrectInventoryRoot': 146,
    '_CorrectPreview': 536,
}

def machine():
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for addr, size in ((A, 0x3000), (C, 0x6000), (MODE, 4096), (STACK, 4096),
                       (CONFIG, 0x200000), (0x88D000, 0x3000),
                       (0x952000, 0x2000),
                       (0x1567000, 4096), (0x157A000, 4096), (0x701000, 4096),
                       (0xE63000, 4096), (0x988000, 4096)):
        uc.mem_map(addr, size)
    for i, reg in enumerate(GPRS + XMMS):
        uc.reg_write(reg, 0xABCDEF01 + i if i < 8 else 0x123456789ABCDEF123456789ABCDEF01 + i)
    uc.reg_write(x.UC_X86_REG_ESP, STACK + 0x800)
    uc.reg_write(x.UC_X86_REG_EFLAGS, 0x602)
    return uc

class Tests(unittest.TestCase):
    def test_short_cutscene_preserves_only_the_game_selected_mode_zero_camera(self):
        source = (ROOT / 'source/ResidentEvilRevelations2.FusionFix/dllmain.cpp').read_text(
            encoding='utf-8-sig')
        self.assertIn('constexpr uintptr_t NormalCameraVtable = 0x01264F30;', source)
        self.assertIn('GetScreen0PreservableCamera(graphics, originalMode)', source)
        self.assertIn('originalMode == 0 &&\n            cameraVtable == NormalCameraVtable', source)
        self.assertIn('(originalMode == 0 && preservedVtable == NormalCameraVtable)', source)

    def test_inventory_production_blobs_equal_confirmed_live_implementation(self):
        menu, config = 0x2100000, 0x2105000
        safe = BLOBS['inventorySafe']
        exports = CONFIRMED_INVENTORY_EXPORTS
        self.assertEqual(hashlib.sha256(safe).hexdigest(), CONFIRMED_INVENTORY_BLOB_SHA256)
        self.assertEqual(BLOBS['inventoryBound'], inventory.bind(safe, config))
        expected_config = inventory.centered_config_bytes(
            inventory.config_bytes(core=0x12345678))
        self.assertEqual(BLOBS['inventoryConfig'][:len(expected_config)], expected_config)
        self.assertEqual(BLOBS['inventoryConfig'][len(expected_config):], bytes(4096-len(expected_config)))
        self.assertEqual(BLOBS['inventoryDraw'], inventory.centered_draw_wrapper(
            menu+0x1000, menu+exports['_InventoryDraw'], config))
        self.assertEqual(BLOBS['inventoryStandard'], inventory.centered_preview_wrapper(
            menu+0x1800, menu+exports['_InventorySizeStandard'], config))
        self.assertEqual(BLOBS['inventoryAlternate'], inventory.centered_preview_wrapper(
            menu+0x2000, menu+exports['_InventorySizeAlternate'], config, True))
        self.assertEqual(BLOBS['shortcutUpdate'], inventory.centered_shortcut_update_wrapper(
            menu+0x2800, inventory.SHORTCUT_UPDATE_ENTRY, config, 0))

    def test_command_far_production_blob_equals_confirmed_live_implementation(self):
        self.assertEqual(BLOBS['commandFar'],
                         command_far.make_animation_clamp(0x2200000, 0x2201000))

    def test_tab_near_far_boundary_uses_the_confirmed_safe_margin(self):
        self.assertEqual([struct.unpack('<I', BLOBS[f'nearInside{i}'])[0] for i in range(5)],
                         [1, 0, 0, 0, 0])

    def test_all_29_input_blobs_equal_confirmed_live_instructions(self):
        for i, gate in enumerate(owner.GATES):
            self.assertEqual(BLOBS[f'input{i}'], owner.make_thunk(A, COUNTER, gate))

    def test_file_text_replay_is_exactly_scoped_and_uses_half_physical_width(self):
        self.assertEqual(
            [struct.unpack('<I', BLOBS[f'fileTextReplay{i}'])[0] for i in range(6)],
            [1, 0, 0, 0, 0, 0],
        )
        self.assertEqual(struct.unpack('<f', BLOBS['fileTextShift'])[0], 1957.5)
        self.assertEqual(struct.unpack('<f', BLOBS['fileTextRestore'])[0], 37.5)

    def test_production_input_blobs_execute_all_existing_cpu_cases(self):
        previous = owner.make_thunk
        try:
            owner.make_thunk = lambda address, counter, gate: BLOBS[f'input{owner.GATES.index(gate)}']
            # The existing harness uses these exact code/counter addresses.
            self.assertEqual((A, COUNTER), (owner_tests.THUNK, owner_tests.COUNTER))
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(owner_tests.Tests)
            # This one test separately relocates blobs to multiple addresses;
            # exact equality above already checks its builder counterpart.
            suite = unittest.TestSuite(t for t in suite if not t.id().endswith('test_complete_original_instructions_and_bounded_redirects'))
            result = unittest.TestResult()
            suite.run(result)
            self.assertEqual(result.errors + result.failures, [])
        finally:
            owner.make_thunk = previous

    def interaction_candidate(self, *, primary=0, secondary=1, actor_slot=0,
                              candidate_owner=1, split_mode=1, split_state=1,
                              missing_mode=False, missing_manager=False):
        uc = machine()
        actor = C + actor_slot * 0x1000
        candidate = N
        status = 10
        p = lambda address, value: uc.mem_write(address, struct.pack('<I', value))
        p(0x157AE00, 0 if missing_mode else MODE)
        p(0x1567EAC, 0 if missing_manager else TABLE)
        p(MODE + 0x8F0, split_mode)
        p(MODE + 0x8F4, split_state)
        p(MODE + 0x8F8, primary)
        p(MODE + 0x8FC, secondary)
        if primary < 8:
            p(TABLE + 0x20 + primary * 4, C + primary * 0x1000)
        p(candidate + 0x2AC, candidate_owner)
        p(candidate + 0x2D0, status)
        uc.reg_write(x.UC_X86_REG_EBX, actor)
        uc.reg_write(x.UC_X86_REG_ESI, candidate)
        uc.mem_write(A, BLOBS['interactionCandidate'])
        before = [uc.reg_read(reg) for reg in GPRS + XMMS]
        flags = uc.reg_read(x.UC_X86_REG_EFLAGS)
        reached = []
        exits = {0x70195B, 0x701972}
        def stop_at_exit(emulator, address, _size, _data):
            if address in exits:
                reached.append(address)
                emulator.emu_stop()
        uc.hook_add(UC_HOOK_CODE, stop_at_exit)
        uc.emu_start(A, 0xFFFFFFFF, count=200)
        should_skip = (not missing_mode and not missing_manager and
                       split_mode == split_state == 1 and primary < 8 and
                       actor_slot == primary and candidate_owner == secondary)
        self.assertEqual(reached, [0x701972 if should_skip else 0x70195B])
        after = [uc.reg_read(reg) for reg in GPRS + XMMS]
        self.assertEqual(after[0], status)  # replayed native MOV EAX,[ESI+0x2D0]
        self.assertEqual(after[1:], before[1:])
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EFLAGS), flags)

    def test_interaction_candidate_owner_filter_scope_and_preservation(self):
        self.interaction_candidate()
        self.interaction_candidate(candidate_owner=0)
        self.interaction_candidate(actor_slot=1)
        self.interaction_candidate(split_mode=0)
        self.interaction_candidate(split_state=0)
        self.interaction_candidate(missing_mode=True)
        self.interaction_candidate(missing_manager=True)
        self.interaction_candidate(primary=8)
        self.interaction_candidate(primary=1, secondary=0, actor_slot=1,
                                   candidate_owner=0)

    def interaction_candidate_alt(self, *, primary=0, secondary=1,
                                  actor_slot=0, candidate_owner=1,
                                  candidate_status=1, split_mode=1,
                                  split_state=1, missing_mode=False,
                                  missing_manager=False):
        uc = machine()
        actor = C + actor_slot * 0x1000
        candidate = N
        p = lambda address, value: uc.mem_write(address, struct.pack('<I', value))
        p(0x157AE00, 0 if missing_mode else MODE)
        p(0x1567EAC, 0 if missing_manager else TABLE)
        p(MODE + 0x8F0, split_mode)
        p(MODE + 0x8F4, split_state)
        p(MODE + 0x8F8, primary)
        p(MODE + 0x8FC, secondary)
        if primary < 8:
            p(TABLE + 0x20 + primary * 4, C + primary * 0x1000)
        p(candidate + 0x2AC, candidate_owner)
        p(candidate + 0x2D0, candidate_status)
        uc.reg_write(x.UC_X86_REG_EBX, actor)
        uc.reg_write(x.UC_X86_REG_EDI, candidate)
        uc.mem_write(A, BLOBS['interactionCandidateAlt'])
        before = [uc.reg_read(reg) for reg in GPRS + XMMS]
        reached = []
        exits = {0x70188D, 0x70189E}
        def stop_at_exit(emulator, address, _size, _data):
            if address in exits:
                reached.append(address)
                emulator.emu_stop()
        uc.hook_add(UC_HOOK_CODE, stop_at_exit)
        uc.emu_start(A, 0xFFFFFFFF, count=200)
        should_skip = (not missing_mode and not missing_manager and
                       split_mode == split_state == 1 and primary < 8 and
                       actor_slot == primary and candidate_owner == secondary)
        self.assertEqual(reached, [0x70189E if should_skip else 0x70188D])
        self.assertEqual([uc.reg_read(reg) for reg in GPRS + XMMS], before)
        self.assertEqual(bool(uc.reg_read(x.UC_X86_REG_EFLAGS) & 0x40),
                         candidate_status == 1)

    def test_alternate_fx_candidate_owner_filter_scope_and_preservation(self):
        self.interaction_candidate_alt()
        self.interaction_candidate_alt(candidate_owner=0)
        self.interaction_candidate_alt(actor_slot=1)
        self.interaction_candidate_alt(split_mode=0)
        self.interaction_candidate_alt(split_state=0)
        self.interaction_candidate_alt(missing_mode=True)
        self.interaction_candidate_alt(missing_manager=True)
        self.interaction_candidate_alt(primary=8)
        self.interaction_candidate_alt(primary=1, secondary=0, actor_slot=1,
                                       candidate_owner=0)
        self.interaction_candidate_alt(candidate_status=0)

    def prompt_input(self, gate_index, *, owner_slot=1, secondary=1,
                     vtable=None, input_mode=1, split_mode=1, split_state=1,
                     missing_mode=False):
        sites = (0x88DFBF, 0x88E0F9, 0x88F57E, 0x88FF01, 0x88FFAF)
        object_regs = (x.UC_X86_REG_ESI, x.UC_X86_REG_ECX,
                       x.UC_X86_REG_ESI, x.UC_X86_REG_ESI,
                       x.UC_X86_REG_ESI)
        accepted = ((0x13915B0,), (0x13915B0, 0x1391970),
                    (0x1391970,), (0x1391970,), (0x1391970,))
        uc = machine()
        p = lambda address, value: uc.mem_write(address, struct.pack('<I', value))
        p(0x157AE00, 0 if missing_mode else MODE)
        p(MODE + 0x8F0, split_mode)
        p(MODE + 0x8F4, split_state)
        p(MODE + 0x8FC, secondary)
        p(CONFIG + 0x15C4BC, input_mode)
        p(C, accepted[gate_index][0] if vtable is None else vtable)
        p(C + 0x2AC, owner_slot)
        uc.reg_write(x.UC_X86_REG_EAX, CONFIG)
        uc.reg_write(object_regs[gate_index], C)
        uc.mem_write(A, BLOBS[f'promptInput{gate_index}'])
        before = [uc.reg_read(reg) for reg in GPRS + XMMS]
        target = sites[gate_index] + 7
        uc.emu_start(A, target, count=200)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EIP), target)
        self.assertEqual([uc.reg_read(reg) for reg in GPRS + XMMS], before)
        p2 = (not missing_mode and split_mode == split_state == 1 and
              secondary < 8 and owner_slot == secondary and
              (accepted[gate_index][0] if vtable is None else vtable)
              in accepted[gate_index])
        self.assertEqual(bool(uc.reg_read(x.UC_X86_REG_EFLAGS) & 0x40),
                         input_mode == 1 and not p2)

    def test_action_prompt_owner_routes_only_p2_to_native_gamepad_glyphs(self):
        for gate_index in range(5):
            self.prompt_input(gate_index)
            self.prompt_input(gate_index, owner_slot=0)
            self.prompt_input(gate_index, input_mode=0)
            self.prompt_input(gate_index, split_mode=0)
            self.prompt_input(gate_index, split_state=0)
            self.prompt_input(gate_index, missing_mode=True)
            self.prompt_input(gate_index, vtable=0x13915B4)
            self.prompt_input(gate_index, secondary=0, owner_slot=0)

    def tutorial_prompt(self, site_index, *, owner_slot=1, secondary=1,
                        vtable=0x13BEDE0, input_mode=1, split_mode=1,
                        split_state=1, missing_mode=False,
                        missing_controller=False):
        sites = (0x9525F7, 0x95265B)
        uc = machine()
        p = lambda address, value: uc.mem_write(address, struct.pack('<I', value))
        p(0x157AE00, 0 if missing_mode else MODE)
        p(MODE + 0x8F0, split_mode)
        p(MODE + 0x8F4, split_state)
        p(MODE + 0x8FC, secondary)
        p(CONFIG + 0x15C4BC, input_mode)
        p(C, vtable)
        p(C + 0x2AC, owner_slot)
        esp = uc.reg_read(x.UC_X86_REG_ESP)
        p(esp + 0xFC, 0 if missing_controller else C)
        uc.reg_write(x.UC_X86_REG_EAX, CONFIG)
        uc.mem_write(A, BLOBS[f'tutorialPrompt{site_index}'])
        before = [uc.reg_read(reg) for reg in GPRS + XMMS]
        target = sites[site_index] + 7
        uc.emu_start(A, target, count=200)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EIP), target)
        self.assertEqual([uc.reg_read(reg) for reg in GPRS + XMMS], before)
        p2 = (not missing_mode and not missing_controller and
              split_mode == split_state == 1 and secondary < 8 and
              owner_slot == secondary and vtable == 0x13BEDE0)
        self.assertEqual(bool(uc.reg_read(x.UC_X86_REG_EFLAGS) & 0x40),
                         input_mode == 1 and not p2)

    def test_async_tutorial_parser_routes_only_exact_p2_controller(self):
        for site_index in range(2):
            self.tutorial_prompt(site_index)
            self.tutorial_prompt(site_index, owner_slot=0)
            self.tutorial_prompt(site_index, input_mode=0)
            self.tutorial_prompt(site_index, split_mode=0)
            self.tutorial_prompt(site_index, split_state=0)
            self.tutorial_prompt(site_index, missing_mode=True)
            self.tutorial_prompt(site_index, missing_controller=True)
            self.tutorial_prompt(site_index, vtable=0x13BEDE4)
            self.tutorial_prompt(site_index, secondary=0, owner_slot=0)

    def geometry(self, vt, index, width=960, height=1080, split=1, state=1,
                 selector=2, foreign=False, stale=False, missing_table=False, missing_mode=False,
                 relocated=False):
        uc = machine()
        node = N + (0x300 if relocated else 0)
        p = lambda addr, val: uc.mem_write(addr, struct.pack('<I', val))
        p(0x157AE00, 0 if missing_mode else MODE)
        p(MODE + 0x8F0, split); p(MODE + 0x8F4, state)
        p(C, vt); p(C + 0xF8, 0 if missing_table else TABLE)
        p(TABLE + index * 4, node + (0x100 if stale else 0))
        p(node + 0x6C, C + (4 if foreign else 0))
        uc.mem_write(C + 0x1C8 + selector * 8, struct.pack('<2f', width/1280, height/720))
        uc.reg_write(x.UC_X86_REG_EAX, C)
        uc.reg_write(x.UC_X86_REG_ECX, selector)
        uc.reg_write(x.UC_X86_REG_ESI, node)
        before = [uc.reg_read(r) for r in GPRS + XMMS]
        flags = uc.reg_read(x.UC_X86_REG_EFLAGS)
        uc.mem_write(A, BLOBS['geometry'])
        writes = []
        uc.hook_add(UC_HOOK_MEM_WRITE, lambda _u,_a,addr,size,_v,_d: writes.append((addr,size)))
        uc.emu_start(A, 0xE63093, count=200)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EIP), 0xE63093)
        self.assertEqual([uc.reg_read(r) for r in GPRS], before[:8])
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EFLAGS), flags)
        accepted = (split == state == 1 and selector == 2 and not any((foreign, stale, missing_table, missing_mode))
                    and any(vt == v and index in indices for v,indices in CLASSES))
        value = height/720 if accepted else width/1280
        self.assertEqual(uc.reg_read(x.UC_X86_REG_XMM1), struct.unpack('<I', struct.pack('<f',value))[0])
        for i in (0,2,3,4,5,6,7): self.assertEqual(uc.reg_read(XMMS[i]), before[8+i])
        for addr,size in writes:
            self.assertTrue(STACK <= addr < addr+size <= STACK+4096 or (addr,size)==(COUNTER,4))

    def test_geometry_all_selected_nodes_and_viewport_shapes(self):
        for vt,indices in CLASSES:
            for index in indices:
                for w,h in ((960,1080),(1920,1080),(2560,1440),(3440,1440),(3840,1080)):
                    with self.subTest(vt=hex(vt), index=index, width=w):
                        self.geometry(vt,index,w,h)
                        self.geometry(vt,index,w,h,relocated=True)

    def test_geometry_native_fallback_scope(self):
        for vt,indices in CLASSES:
            for kw in ({'split':0},{'state':0},{'selector':5},{'foreign':True},
                       {'stale':True},{'missing_table':True},{'missing_mode':True}):
                self.geometry(vt,indices[0],**kw)
            self.geometry(vt,10)
        self.geometry(0x139CCC8,0) # inventory excluded
        self.geometry(0x13A3B70,0) # scope excluded

    def test_capture_routes_without_altering_registers_or_flags(self):
        for captured in (0,1):
            for flags in (0x202,0x246,0x602,0xED7):
                uc = machine()
                uc.reg_write(x.UC_X86_REG_EFLAGS,flags)
                uc.mem_write(COUNTER,struct.pack('<I',captured))
                uc.mem_write(A,BLOBS['capture'])
                before=[uc.reg_read(r) for r in GPRS+XMMS]
                end=0x9886A7 if captured else 0x988622
                uc.emu_start(A,end,count=20)
                self.assertEqual(uc.reg_read(x.UC_X86_REG_EIP),end)
                self.assertEqual([uc.reg_read(r) for r in GPRS+XMMS],before)
                self.assertEqual(uc.reg_read(x.UC_X86_REG_EFLAGS),flags)

    def test_selectors_preserve_other_bits_and_restore_sp(self):
        for flags in (0xFF150002,0xFF120002,0xFF130002,0xFF100002):
            for coop in (False,True):
                expect = flags
                if ((flags>>16)&15) in (2,5): expect=(flags&~0xF0000)|(0x20000 if coop else 0x50000)
                self.assertEqual(BLOBS[f'flags{flags}{"mp" if coop else "sp"}'],struct.pack('<I',expect))

    def test_new_thunk_branches_land_on_whole_instructions(self):
        decoder=Cs(CS_ARCH_X86,CS_MODE_32); decoder.detail=True
        for name,exits in (('geometry',{0xE63093}),('capture',{0x988622,0x9886A7}),
                           ('interactionCandidate',{0x70195B,0x701972}),
                           ('interactionCandidateAlt',{0x70188D,0x70189E}),
                           *[(f'promptInput{i}', {site + 7}) for i,site in enumerate(
                               (0x88DFBF,0x88E0F9,0x88F57E,0x88FF01,0x88FFAF))],
                           *[(f'tutorialPrompt{i}', {site + 7}) for i,site in enumerate(
                               (0x9525F7,0x95265B))]):
            code=BLOBS[name]; instructions=list(decoder.disasm(code,A))
            self.assertEqual(sum(i.size for i in instructions),len(code))
            boundaries={i.address for i in instructions}
            for i in instructions:
                if i.mnemonic.startswith('j'): self.assertIn(i.operands[0].imm,boundaries|exits)

if __name__=='__main__': unittest.main(argv=[sys.argv[0]]+extra)
