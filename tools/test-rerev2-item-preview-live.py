"""Reversible Campaign inventory preview alignment experiment (MP only).

apply is a one-shot data write; apply-hook wraps just the Campaign size call
with a native, owner/item-guarded thunk. No camera/FOV/render-view changes or
per-frame external writes. Keep the same item selected for the visual test.
This first test matches the EXISTING legacy inventory panel, not its size.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location('hud', Path(__file__).with_name('test-rerev2-sp-hud-live.py'))
hud = importlib.util.module_from_spec(spec); spec.loader.exec_module(hud)
SIZE_CALL=0x8F7A54
SIZE_CALL_BYTES=bytes.fromhex('e8774a0700')

def make_size_thunk(address, counter, controller, item, item_id, rectangle):
    """Original thiscall size(width), then guarded rect; preserve its ABI/result."""
    code=bytearray.fromhex('56 8b f1 ff 74 24 08 b8')
    code+=hud.u32(0x96C4D0)
    code+=bytes.fromhex('ff d0 9c 60')
    fixups=[]
    def reject():
        code.extend(bytes.fromhex('0f85'))
        fixups.append(len(code)); code.extend(bytes(4))
    code+=bytes.fromhex('81fe')+hud.u32(item); reject()
    code+=bytes.fromhex('813e')+hud.u32(0x13BF4D0); reject()
    code+=bytes.fromhex('813d')+hud.u32(controller)+hud.u32(0x139CCC8); reject()
    code+=bytes.fromhex('813d')+hud.u32(controller+0x2CC)+hud.u32(item); reject()
    code+=bytes.fromhex('81be94000000')+hud.u32(item_id); reject()
    code+=bytes.fromhex('83be8c00000000'); reject()
    code+=bytes.fromhex('80be9000000000'); reject()
    code+=b'\xa1'+hud.u32(hud.MODE_POINTER)+bytes.fromhex('85c0')
    code+=bytes.fromhex('0f84'); fixups.append(len(code)); code+=bytes(4)
    for offset in (0x8F0,0x8F4):
        code+=bytes.fromhex('83b8')+hud.u32(offset)+b'\x01'; reject()
    for i,value in enumerate(rectangle):
        code+=bytes.fromhex('c786')+hud.u32(0xA4+i*4)+struct.pack('<i',value)
    code+=bytes.fromhex('f0ff05')+hud.u32(counter)
    done=len(code)
    code+=bytes.fromhex('619d5ec20400')
    for offset in fixups: struct.pack_into('<i',code,offset,done-offset-4)
    if len(code)>4096: raise RuntimeError('Preview thunk exceeds RX page')
    return bytes(code)

def size_redirect(address):
    return b'\xe8'+hud.u32((address-SIZE_CALL-5)&0xFFFFFFFF)

def aligned_rectangle(rect, viewport, screen, gui_scale=(0.8, 1.0), gui_offset=(0.0, 0.25)):
    left, top, right, bottom = viewport
    w, h = right-left, bottom-top
    rw, rh = rect[2]-rect[0], rect[3]-rect[1]
    if min(w,h,rw,rh,*screen,*gui_scale) <= 0:
        raise ValueError('All dimensions and scale factors must be positive')
    fit, size_scale = min(w/1280, h/720), h/720
    # Inverse of the old ASI MP position adjustment; native dimensions use the
    # HEIGHT scale while positions use FIT. Bring both onto the GUI's canvas.
    old_x_offset = int(720 * screen[0]/screen[1] - 800)
    x = left + (rect[0]-left-old_x_offset*fit)*gui_scale[0] + w*gui_offset[0]
    y = top + (rect[1]-top)*gui_scale[1] + h*gui_offset[1]
    box_w, box_h = rw*fit/size_scale*gui_scale[0], rh*fit/size_scale*gui_scale[1]
    # Fit undistorted inside the panel slot; do NOT copy the GUI's anisotropy
    # into the model/texture. Retain the item's native destination aspect.
    uniform = min(box_w/rw, box_h/rh)
    preview_w, preview_h = rw*uniform, rh*uniform
    x += (box_w-preview_w)/2; y += (box_h-preview_h)/2
    return tuple(round(v) for v in (x,y,x+preview_w,y+preview_h))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--controller',type=lambda s:int(s,0))
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--mode',choices=('plan','apply','apply-hook','inspect','restore'),default='plan')
    args=parser.parse_args()
    p=hud.Process(args.pid,args.mode in ('apply','apply-hook','restore'))
    try:
        identity=p.identity()
        asi=Path(identity['image']).parent/'scripts/ResidentEvilRevelations2.FusionFix.asi'
        if hashlib.sha256(asi.read_bytes()).hexdigest()!=hud.ASI_HASH: raise RuntimeError('Unverified ASI build')
        state=json.loads(args.state.read_text()) if args.state.exists() else None
        if state and (state['pid']!=args.pid or state['identity']!=identity): raise RuntimeError('Stale process state')
        if args.mode in ('plan','apply','apply-hook'):
            if state or not args.controller: raise RuntimeError('Supply fresh controller and new state path')
            controller=args.controller
            p.expect(controller,hud.u32(0x139CCC8))
            p.expect(0x139CD20,hud.u32(hud.DRAW_ENTRY))
            root=p.integer(controller+0xF4)
            p.expect(root+0x6C,hud.u32(controller))
            item=p.integer(controller+0x2CC)
            p.expect(item,hud.u32(0x13BF4D0))
            if p.read(item+0x90,1)!=b'\0': raise RuntimeError('Overlay preview not supported')
            view=p.integer(item+0x8C)
            if view not in (0,1): raise RuntimeError('Not a player view')
            gfx=p.integer(0x15DE88C)
            viewport=struct.unpack('<4i',p.read(gfx+0x48+0x190*view,16))
            screen=struct.unpack('<2i',p.read(gfx+0x1E0,8))
            mode=p.integer(hud.MODE_POINTER)
            p.expect(mode+0x8F0,hud.u32(1)*2)
            before=struct.unpack('<4i',p.read(item+0xA4,16))
            after=aligned_rectangle(before,viewport,screen)
            # Diagnostic assumption: the confirmed legacy GUI tuning (0/1).
            # This is a captured-state experiment, not a general INI reader.
            if screen!=(1920,1080) or viewport[2]-viewport[0]!=960 or viewport[3]-viewport[1]!=1080:
                raise RuntimeError('First visual experiment is restricted to the captured 1920x1080 layout')
            if view != 0 or p.integer(item+0x94) != 769 or before != (895,94,1589,484):
                raise RuntimeError('First experiment requires the unchanged captured P1 Green Herb reference')
            state={'pid':args.pid,'identity':identity,'status':'planned','controller':controller,
                   'root':root,'item':item,'itemId':p.integer(item+0x94),'view':view,
                   'viewport':viewport,'screen':screen,'before':before,'after':after,
                   'policy':'fit native preview aspect within existing legacy GUI slot',
                   'guards':[(controller,hud.u32(0x139CCC8).hex()),
                             (controller+0x2CC,hud.u32(item).hex()),
                             (root+0x6C,hud.u32(controller).hex()),
                             (item,hud.u32(0x13BF4D0).hex()),
                             (item+0x94,p.read(item+0x94,4).hex()),
                             (item+0x8C,hud.u32(view).hex()),
                             (item+0x90,'00'),
                             (gfx+0x48+0x190*view,p.read(gfx+0x48+0x190*view,16).hex()),
                             (mode+0x8F0,(hud.u32(1)*2).hex())]}
            if args.mode in ('apply','apply-hook'):
                patches=[(item+0xA4,struct.pack('<4i',*before),struct.pack('<4i',*after))]
                if args.mode=='apply-hook':
                    p.expect(SIZE_CALL,SIZE_CALL_BYTES)
                    allocation=p.k.VirtualAllocEx(p.handle,None,8192,0x3000,0x04)
                    p.check(allocation)
                    if allocation+8192>0x100000000: raise RuntimeError('Allocation outside x86')
                    code=make_size_thunk(allocation,allocation+4096,controller,item,state['itemId'],after)
                    p.write(allocation,code); p.expect(allocation,code)
                    p.protect(allocation,4096,0x20)
                    p.check(p.k.FlushInstructionCache(p.handle,allocation,len(code)))
                    state['allocation']=allocation
                    patches=[(SIZE_CALL,SIZE_CALL_BYTES,size_redirect(allocation))]
                state['status']='prepared'
                args.state.parent.mkdir(parents=True,exist_ok=True)
                with args.state.open('x',encoding='utf-8') as f: json.dump(state,f,indent=2)
                hud.transact(p,patches,
                             guards=[(a,bytes.fromhex(b)) for a,b in state['guards']])
                state['status']='applied'
                args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        elif args.mode=='restore':
            if not state or state['status'] not in ('applied','prepared'): raise RuntimeError('No active experiment')
            if 'allocation' in state:
                # Remove code even after GUI recreation; native size recalculates
                # its own rectangle. Never dereference obsolete heap pointers.
                hud.transact(p,[(SIZE_CALL,size_redirect(state['allocation']),SIZE_CALL_BYTES)])
            else:
                hud.transact(p,[(state['item']+0xA4,struct.pack('<4i',*state['after']),struct.pack('<4i',*state['before']))],
                             guards=[(a,bytes.fromhex(b)) for a,b in state['guards']])
            state['status']='restored'; args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        if not state: raise RuntimeError('No saved state')
        p.expect(state['item'],hud.u32(0x13BF4D0))
        state['currentRectangle']=struct.unpack('<4i',p.read(state['item']+0xA4,16))
        state['currentItemId']=p.integer(state['item']+0x94)
        state['appliedNativeRectangle']=struct.unpack('<4i',p.read(state['item']+0x70,16))
        if 'allocation' in state:
            p.expect(state['allocation'],make_size_thunk(state['allocation'],state['allocation']+4096,
                     state['controller'],state['item'],state['itemId'],state['after']))
            state['correctionCalls']=p.integer(state['allocation']+4096)
        elif state['status']=='applied' and tuple(state['currentRectangle'])!=tuple(state['after']):
            state['status']='native-recomputed'
            args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        print(json.dumps(state,indent=2))
    finally: p.close()

if __name__=='__main__': main()
