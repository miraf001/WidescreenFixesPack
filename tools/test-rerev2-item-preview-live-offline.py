import importlib.util
from pathlib import Path
import unittest
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'out/toolchain/unicorn-2.1.3'))
sys.path.insert(0,str(ROOT/'out/toolchain/capstone-5.0.9'))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_WRITE
from unicorn import x86_const as x
from capstone import Cs,CS_ARCH_X86,CS_MODE_32

spec=importlib.util.spec_from_file_location('preview',Path(__file__).with_name('test-rerev2-item-preview-live.py'))
preview=importlib.util.module_from_spec(spec); spec.loader.exec_module(preview)

class Tests(unittest.TestCase):
    def test_captured_green_herb_fits_inside_left_player(self):
        rect=preview.aligned_rectangle((895,94,1589,484),(0,0,960,1080),(1920,1080))
        self.assertEqual(rect,(428,384,706,540))
        self.assertLess(rect[2],960)
        self.assertAlmostEqual((rect[2]-rect[0])/(rect[3]-rect[1]),694/390,delta=.005)

    def test_right_view_origin_not_scaled(self):
        left=preview.aligned_rectangle((895,94,1589,484),(0,0,960,1080),(1920,1080))
        right=preview.aligned_rectangle((1855,94,2549,484),(960,0,1920,1080),(1920,1080))
        self.assertEqual(right,(left[0]+960,left[1],left[2]+960,left[3]))

    def test_invalid_dimensions_refused(self):
        with self.assertRaises(ValueError):
            preview.aligned_rectangle((0,0,0,10),(0,0,960,1080),(1920,1080))

    def run_thunk(self,split=1,foreign=False,item_id=769,view=0,overlay=0,owner_changed=False):
        a,c,item,mode,stack,end=0x2000000,0x3000000,0x3001000,0x4000000,0x5000000,0x6000000
        uc=Uc(UC_ARCH_X86,UC_MODE_32)
        for addr,size in ((a,8192),(c,0x4000),(mode,4096),(stack,4096),(end,4096),(0x157A000,4096),(0x96C000,4096)):
            uc.mem_map(addr,size)
        regs=[getattr(x,'UC_X86_REG_'+r) for r in ('EBX','ESI','EDI','EBP')]+[getattr(x,'UC_X86_REG_XMM'+str(i)) for i in range(8)]
        for i,r in enumerate(regs): uc.reg_write(r,0xABCDEF00+i)
        p=lambda addr,v:uc.mem_write(addr,struct.pack('<I',v))
        selected=item+0x1000 if foreign else item
        for obj in (item,selected):
            p(obj,0x13BF4D0); p(obj+0x94,item_id); p(obj+0x8C,view); p(obj+0x90,overlay)
        p(c,0x139CCC8); p(c+0x2CC,item+(4 if owner_changed else 0))
        p(0x157AE00,mode); p(mode+0x8F0,split); p(mode+0x8F4,split)
        p(stack+0x800,end);p(stack+0x804,463)
        uc.reg_write(x.UC_X86_REG_ESP,stack+0x800);uc.reg_write(x.UC_X86_REG_ECX,selected)
        # Original thiscall ABI stub: verify the width argument forwarded;
        # populate its native rectangle and a known return EAX/flags.
        code=bytes.fromhex('8b442404')+bytes.fromhex('8981a4000000')
        for offset in (0xA8,0xAC,0xB0): code+=bytes.fromhex('c781')+struct.pack('<II',offset,777)
        code+=bytes.fromhex('b87856341283f800c20400')
        uc.mem_write(0x96C4D0,code)
        rect=(428,384,706,540)
        thunk=preview.make_size_thunk(a,a+4096,c,item,769,rect)
        uc.mem_write(a,thunk)
        before=[uc.reg_read(r) for r in regs]
        writes=[]
        uc.hook_add(UC_HOOK_MEM_WRITE,lambda _u,_a,addr,size,_v,_d:writes.append((addr,size)))
        uc.emu_start(a,end,count=150)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EIP),end)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_ESP),stack+0x808)
        self.assertEqual(uc.reg_read(x.UC_X86_REG_EAX),0x12345678)
        self.assertEqual([uc.reg_read(r) for r in regs],before)
        accepted=split==1 and not foreign and item_id==769 and view==overlay==0 and not owner_changed
        self.assertEqual(struct.unpack('<4i',uc.mem_read(selected+0xA4,16)),rect if accepted else (463,777,777,777))
        for addr,size in writes:
            self.assertTrue(stack<=addr<addr+size<=stack+4096 or selected+0xA4<=addr<addr+size<=selected+0xB4 or (addr,size)==(a+4096,4))

    def test_size_wrapper_argument_stack_and_preserved_registers(self): self.run_thunk()

    def test_size_wrapper_sp_other_item_other_owner_unmodified(self):
        for kw in ({'split':0},{'foreign':True},{'item_id':770},{'view':1},{'overlay':1},{'owner_changed':True}):
            with self.subTest(**kw): self.run_thunk(**kw)

    def test_size_wrapper_whole_instructions(self):
        address=0x2000000
        code=preview.make_size_thunk(address,address+4096,0x3000000,0x3001000,769,(428,384,706,540))
        decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
        instructions=list(decoder.disasm(code,address))
        self.assertEqual(sum(i.size for i in instructions),len(code))
        boundaries={i.address for i in instructions}
        for i in instructions:
            if i.mnemonic.startswith('j'):self.assertIn(i.operands[0].imm,boundaries)

if __name__=='__main__': unittest.main()
