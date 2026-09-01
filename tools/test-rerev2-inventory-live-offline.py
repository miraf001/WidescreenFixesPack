"""Offline x86 tests for the adaptive Campaign inventory hook."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'out/toolchain/unicorn-2.1.3'))
sys.path.insert(0,str(ROOT/'out/toolchain/capstone-5.0.9'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_MEM_WRITE
from unicorn import x86_const as x
from capstone import Cs,CS_ARCH_X86,CS_MODE_32

spec=importlib.util.spec_from_file_location('inventory',Path(__file__).with_name('test-rerev2-inventory-live.py'))
inventory=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventory)
h=inventory.hud

A,CONFIG,CORE,C,ITEM,TABLE,NODE,GFX,MODE,STACK,END=(
    0x02000000,0x02001000,0x03000000,0x04000000,0x04001000,
    0x04002000,0x04003000,0x04010000,0x05000000,0x06000000,0x07000000)
GPRS=[getattr(x,'UC_X86_REG_'+r) for r in ('EAX','EBX','ECX','EDX','ESI','EDI','EBP')]
XMMS=[getattr(x,'UC_X86_REG_XMM'+str(i)) for i in range(8)]

def u32(v):return struct.pack('<I',v&0xFFFFFFFF)
def f32(v):return struct.pack('<f',v)

def map_pages(uc,address,size,pages):
    for page in range(address&~4095,(address+size+4095)&~4095,4096):
        if page not in pages:uc.mem_map(page,4096);pages.add(page)

def machine(width=960,height=1080,view=0,split=1):
    uc=Uc(UC_ARCH_X86,UC_MODE_32);pages=set()
    for address,size in ((A,0x2000),(CORE,4096),(C,0x5000),(GFX,0x4000),(MODE,4096),
                         (STACK,4096),(END,4096),(h.MODE_POINTER,4),(0x15DE88C,4),
                         (inventory.UPDATE_ENTRY,64),(0x96C4D0,128),(h.DRAW_ENTRY,128)):
        map_pages(uc,address,size,pages)
    code,exports=inventory.load_object(ROOT/'out/tests/inventory/InventoryPreviewLive.obj')
    uc.mem_write(A,inventory.bind(code,CONFIG))
    uc.mem_write(CONFIG,inventory.config_bytes(core=CORE))
    uc.mem_write(h.MODE_POINTER,u32(MODE));uc.mem_write(MODE+0x8F0,u32(split)*2)
    uc.mem_write(0x15DE88C,u32(GFX))
    left=view*width
    uc.mem_write(GFX+0x48+view*0x190,struct.pack('<4i',left,0,left+width,height))
    uc.mem_write(GFX+0x1E0,struct.pack('<2i',width*2,height))
    uc.mem_write(C,u32(0x139CCC8));uc.mem_write(C+0x2AC,u32(view));uc.mem_write(C+0x2CC,u32(ITEM));uc.mem_write(C+0xF8,u32(TABLE))
    uc.mem_write(TABLE+192*4,u32(NODE));uc.mem_write(NODE,u32(0x141D330));uc.mem_write(NODE+0x6C,u32(C));uc.mem_write(NODE+0x54,u32(0xB))
    uc.mem_write(ITEM,u32(0x13BF4D0));uc.mem_write(ITEM+0x8C,u32(view));uc.mem_write(ITEM+0x90,b'\0')
    for i,reg in enumerate(GPRS+XMMS):uc.reg_write(reg,0x12345600+i)
    uc.reg_write(x.UC_X86_REG_ESP,STACK+0x800);uc.reg_write(x.UC_X86_REG_EFLAGS,0x602)
    return uc,exports

def run_entry(uc,address,ecx,stack_args=(),count=1000):
    esp=STACK+0x800
    uc.mem_write(esp,u32(END)+b''.join(u32(v) for v in stack_args))
    uc.reg_write(x.UC_X86_REG_ESP,esp);uc.reg_write(x.UC_X86_REG_ECX,ecx)
    uc.emu_start(address,END,count=count)

class Tests(unittest.TestCase):
    def test_policy_keeps_sp_scale_until_visible_bounds_need_shrink(self):
        self.assertAlmostEqual(inventory.adaptive_scale(960,1080),960/980)
        self.assertEqual(inventory.adaptive_scale(1920,1080),1.5)
        self.assertEqual(inventory.adaptive_scale(2560,1080),1.5)
        self.assertEqual(inventory.adaptive_scale(2560,1440),2.0)
        with self.assertRaises(ValueError):inventory.adaptive_scale(0,1080)

    def test_patch_scope_is_campaign_only(self):
        state={'allocation':A,'exports':inventory.load_object(ROOT/'out/tests/inventory/InventoryPreviewLive.obj')[1]}
        patches=inventory.patches(state)
        self.assertEqual([p[0] for p in patches[:4]],[0x8F7A54,0x8FA310,inventory.DRAW_SLOT,inventory.UPDATE_SLOT])
        self.assertEqual([p[0] for p in patches[4:]],list(inventory.LAYOUT_TESTS))
        self.assertTrue(all(p[1:]==(b'\x84\xc0',b'\x30\xc0') for p in patches[4:]))

    def test_blob_is_whole_instructions_with_internal_branch_targets(self):
        code,exports=inventory.load_object(ROOT/'out/tests/inventory/InventoryPreviewLive.obj')
        decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
        instructions=list(decoder.disasm(code,A))
        self.assertEqual(sum(i.size for i in instructions),len(code))
        boundaries={i.address for i in instructions}
        external={CORE,inventory.UPDATE_ENTRY,0x96C4D0,h.DRAW_ENTRY}
        for ins in instructions:
            if ins.mnemonic.startswith('j') or ins.mnemonic=='call':
                if ins.operands and ins.operands[0].type==2:
                    self.assertIn(ins.operands[0].imm,boundaries|external)
        self.assertEqual(set(exports),{'_InventoryDraw','_InventoryUpdate','_InventorySizeStandard','_InventorySizeAlternate','_CorrectInventoryRoot','_CorrectPreview'})

    def check_update(self,width,height,split=1,foreign=False):
        uc,exports=machine(width,height,split=split)
        uc.mem_write(inventory.UPDATE_ENTRY,b'\xB8'+u32(0x87654321)+b'\xC3')
        if foreign:uc.mem_write(NODE+0x6C,u32(C+4))
        preserved=[x.UC_X86_REG_EBX,x.UC_X86_REG_ESI,x.UC_X86_REG_EDI,x.UC_X86_REG_EBP]+XMMS
        before=[uc.reg_read(r) for r in preserved]
        writes=[];uc.hook_add(UC_HOOK_MEM_WRITE,lambda _u,_a,addr,size,_v,_d:writes.append((addr,size)))
        run_entry(uc,A+exports['_InventoryUpdate'],C)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EAX),0x87654321)
        self.assertEqual([uc.reg_read(r) for r in preserved],before)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_ESP),STACK+0x804)
        accepted=split==1 and not foreign
        desired=inventory.adaptive_scale(width,height);fit=min(width/1280,height/720);ratio=desired/fit
        values=struct.unpack('<4f',uc.mem_read(NODE+0xA0,8)+uc.mem_read(NODE+0xB0,8))
        expected=(78*ratio,138*ratio,ratio,ratio) if accepted else (0.,0.,0.,0.)
        for actual,want in zip(values,expected):self.assertAlmostEqual(actual,want,places=4)
        self.assertEqual(struct.unpack('<I',uc.mem_read(CONFIG+0x24,4))[0],1 if accepted else 0)
        if accepted:
            self.assertAlmostEqual(struct.unpack('<f',uc.mem_read(CONFIG+0x28,4))[0],desired,places=5)
            self.assertAlmostEqual(struct.unpack('<f',uc.mem_read(CONFIG+0x2C,4))[0],ratio,places=5)
            self.assertTrue(struct.unpack('<I',uc.mem_read(NODE+0x54,4))[0]&0x10000)
        allowed={(NODE+0xA0,4),(NODE+0xA4,4),(NODE+0xB0,4),(NODE+0xB4,4),(NODE+0x54,4),(CONFIG+0x24,4),(CONFIG+0x28,4),(CONFIG+0x2C,4)}
        for addr,size in writes:
            self.assertTrue(STACK<=addr<addr+size<=STACK+4096 or (addr,size) in allowed)

    def test_update_adapts_narrow_and_retains_sp_on_wide(self):
        for width,height in ((960,1080),(1920,1080),(2560,1080),(2560,1440)):
            with self.subTest(width=width,height=height):self.check_update(width,height)

    def test_update_sp_and_foreign_node_are_unchanged(self):
        self.check_update(960,1080,split=0)
        self.check_update(960,1080,foreign=True)

    def check_preview(self,width=960,height=1080,view=0,split=1,alternate=False,foreign=False):
        uc,exports=machine(width,height,view,split)
        left=view*width;fit=min(width/1280,height/720);hs=height/720
        old_x=int(720*(width*2)/height-800)
        canonical=(600.,126.,380.,213.)
        native=(left+int((canonical[0]+old_x)*fit),int(canonical[1]*fit),
                left+int((canonical[0]+old_x)*fit)+int(canonical[2]*hs),
                int(canonical[1]*fit)+int(canonical[3]*hs))
        stub=bytearray()
        for offset,value in zip((0xA4,0xA8,0xAC,0xB0),native):stub+=b'\xC7\x81'+u32(offset)+u32(value)
        stub+=b'\xB8'+u32(0x87654321)+b'\x83\xF8\x00\xC2\x04\x00'
        uc.mem_write(0x96C4D0,bytes(stub))
        if foreign:uc.mem_write(C+0x2CC,u32(ITEM+4))
        uc.reg_write(x.UC_X86_REG_EDI,C);uc.reg_write(x.UC_X86_REG_EBX,C)
        preserved=[x.UC_X86_REG_EBX,x.UC_X86_REG_ESI,x.UC_X86_REG_EDI,x.UC_X86_REG_EBP]+XMMS
        before=[uc.reg_read(r) for r in preserved]
        entry='_InventorySizeAlternate' if alternate else '_InventorySizeStandard'
        run_entry(uc,A+exports[entry],ITEM,(380,))
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EAX),0x87654321)
        self.assertEqual([uc.reg_read(r) for r in preserved],before)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_ESP),STACK+0x808)
        actual=struct.unpack('<4i',uc.mem_read(ITEM+0xA4,16))
        expected=inventory.preview_rectangle(native,(left,0,left+width,height),(width*2,height)) if split and not foreign else native
        self.assertEqual(actual,expected)
        self.assertEqual(struct.unpack('<I',uc.mem_read(CONFIG+0x18,4))[0],1 if split and not foreign else 0)

    def test_preview_all_items_standard_and_alternate_share_transform(self):
        for alternate in (False,True):
            for view in (0,1):
                with self.subTest(alternate=alternate,view=view):self.check_preview(view=view,alternate=alternate)

    def test_preview_sp_and_foreign_owner_are_unchanged(self):
        self.check_preview(split=0)
        self.check_preview(foreign=True)

    def test_draw_uses_core_only_in_mp_and_preserves_abi(self):
        for split in (0,1):
            uc,exports=machine(split=split)
            # MP wrapper must use the exact loaded ASI RESCALE sentinel.
            uc.mem_write(CORE,b'\x81\xFA\xDD\xDD\xDD\xDD\x75\x08\xB8'+u32(0x11112222)+b'\xC2\x04\x00')
            uc.mem_write(h.DRAW_ENTRY,b'\xB8'+u32(0x33334444)+b'\xC2\x04\x00')
            context=C+0x1000;render_context=C+0x1800;constants=C+0x3800
            uc.mem_write(context+4,u32(render_context));uc.mem_write(render_context+0x1818,u32(constants))
            uc.mem_write(constants,struct.pack('<4f',.0013020833721384406,-.0018518518190830946,-.625,2.))
            run_entry(uc,A+exports['_InventoryDraw'],C,(context,))
            self.assertEqual(uc.reg_read(x.UC_X86_REG_EAX),0x11112222 if split else 0x33334444)
            self.assertEqual(uc.reg_read(x.UC_X86_REG_ESP),STACK+0x808)
            self.assertEqual(struct.unpack('<I',uc.mem_read(CONFIG+0x20,4))[0],split)
            actual=struct.unpack('<4f',uc.mem_read(constants,16))
            expected=(.0020833334419876337,-.0018518518190830946,-1.,1.) if split else (.0013020833721384406,-.0018518518190830946,-.625,2.)
            for value,want in zip(actual,expected):self.assertAlmostEqual(value,want,places=6)
            if split:
                for value,want in zip(struct.unpack('<4f',uc.mem_read(CONFIG+0x40,16)),(.0013020833721384406,-.0018518518190830946,-.625,2.)):
                    self.assertAlmostEqual(value,want,places=6)
                for value,want in zip(struct.unpack('<4f',uc.mem_read(CONFIG+0x50,16)),(.0020833334419876337,-.0018518518190830946,-1.,1.)):
                    self.assertAlmostEqual(value,want,places=6)

if __name__=='__main__':unittest.main()
