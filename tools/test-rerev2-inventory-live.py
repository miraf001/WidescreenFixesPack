"""Adaptive SP-layout Campaign inventory test; no item-ID/heap whitelist.

Replaces both Campaign preview-size calls, the Campaign update/draw slots, and
only its eight local layout predicates. Panel and preview use one canonical
1280x720 transform: SP height scale is the maximum, reduced uniformly only when
the verified visible content bounds do not fit the player viewport. No
changes to other HUD classes, native input, camera, item selection, or save data.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hud',Path(__file__).with_name('test-rerev2-sp-hud-live.py'))
hud=importlib.util.module_from_spec(spec);spec.loader.exec_module(hud)
DRAW_SLOT=0x139CD20
UPDATE_SLOT=0x139CCEC
UPDATE_ENTRY=0x8F8970
CALLS=((0x8F7A54,'_InventorySizeStandard'),(0x8FA310,'_InventorySizeAlternate'))
LAYOUT_TESTS=(0x8F79E1,0x8F7A01,0x8F7A33,0x8FA217,0x8FA25E,0x8FA28F,0x8FA2BD,0x8FA2EF)
SHORTCUT_VTABLE=0x139AFB0
SHORTCUT_UPDATE_SLOT=SHORTCUT_VTABLE+0x24
SHORTCUT_UPDATE_ENTRY=0x8E53F0
SHORTCUT_NODE_COUNT=21
SHORTCUT_INACTIVE_MATRIX_INDICES=(16,20)
GFX_POINTER=0x15DE88C
SHORTCUT_CANONICAL_Y=215.0
MARKER=struct.pack('<I',0xBADF00D)
CONFIRMED_TEMPLATE_HASH='9e2a6ff1553af2c3b2f18ab6b25c0d2dc26553964d10fe0115207d7b4ef626a7'
ASI_PROFILES={
    hud.ASI_HASH:{'rescaleRva':hud.RESCALE_RVA,'coreRva':hud.CORE_RVA,
                  'positionRva':0x1A30,
                  'coreProlog':bytes.fromhex('5589e553575681ecec0100008b4508')},
    '8e527e0b43f6c7358082ad14c07db5bd79b336bf7a0ddd657ab121254e9fd592':{
        'rescaleRva':0x2D60,'coreRva':0x25C0,'positionRva':0x2440,
        'coreProlog':bytes.fromhex('5553575683ec648b7c24788b5f048b35d8df5d01f30f7e8b')},
}

def load_object(path):
    data=path.read_bytes()
    machine,count,_,symbols,nsyms,optional,_=struct.unpack_from('<HHIIIHH',data)
    if machine!=0x14C or optional:raise RuntimeError('Expected x86 COFF object')
    sections=[struct.unpack_from('<8sIIIIIIHHI',data,20+40*i) for i in range(count)]
    matches=[(i+1,s) for i,s in enumerate(sections) if s[0].startswith(b'.text') and s[3]]
    if len(matches)!=1:raise RuntimeError('Expected one code section')
    section_number,section=matches[0]
    if section[7]:raise RuntimeError('Code is not relocation-free')
    code=data[section[4]:section[4]+section[3]]
    strings=data[symbols+nsyms*18:]
    exports={};i=0
    while i<nsyms:
        raw,value,sec,_,_,aux=struct.unpack_from('<8sIhHBB',data,symbols+i*18)
        name=(strings[struct.unpack_from('<I',raw,4)[0]:].split(b'\0')[0] if raw[:4]==bytes(4) else raw.rstrip(b'\0')).decode('ascii')
        if sec==section_number and name.startswith('_'):exports[name]=value
        i+=1+aux
    for _,name in CALLS:
        if name not in exports:raise RuntimeError('Missing preview entry')
    for name in ('_InventoryDraw','_InventoryUpdate'):
        if name not in exports:raise RuntimeError(f'Missing {name} entry')
    if len(code)>=4096 or code.count(MARKER)!=5:raise RuntimeError('Unexpected code/config marker layout')
    return code,exports

def load_template(path,content_right,content_bottom):
    template=json.loads(path.read_text(encoding='utf-8'))
    if template.get('objectHash')!=CONFIRMED_TEMPLATE_HASH:
        raise RuntimeError('Template is not the confirmed safe -01 inventory blob')
    expected=[0.,0.,float(content_right),float(content_bottom)]
    if [float(v) for v in template.get('contentBounds',())]!=expected:
        raise RuntimeError('Template content bounds differ from this test')
    code=bytes.fromhex(template['unboundCode'])
    exports={name:int(value) for name,value in template['exports'].items()}
    for _,name in CALLS:
        if name not in exports:raise RuntimeError('Missing preview template entry')
    for name in ('_InventoryDraw','_InventoryUpdate'):
        if name not in exports:raise RuntimeError(f'Missing {name} template entry')
    if len(code)>=4096 or code.count(MARKER)!=4:
        raise RuntimeError('Unexpected template code/config marker layout')
    return code,exports,template['objectHash']

def bind(code,config):return code.replace(MARKER,hud.u32(config))
def call_bytes(site,target):return b'\xe8'+hud.u32((target-site-5)&0xFFFFFFFF)

def jump_bytes(site,target):return b'\xe9'+hud.u32((target-site-5)&0xFFFFFFFF)

class CodeBuilder:
    def __init__(self,address):
        self.address=address;self.code=bytearray();self.labels={};self.fixups=[]
    def emit(self,value):
        self.code += bytes.fromhex(value) if isinstance(value,str) else value
    def absolute(self,value):self.code += hud.u32(value)
    def call(self,target):self.code += call_bytes(self.address+len(self.code),target)
    def jump(self,opcode,label):
        self.emit(opcode);self.fixups.append((len(self.code),label));self.code += bytes(4)
    def mark(self,label):self.labels[label]=len(self.code)
    def finish(self):
        for offset,label in self.fixups:
            if label not in self.labels:raise RuntimeError(f'Missing code label {label}')
            struct.pack_into('<i',self.code,offset,self.labels[label]-offset-4)
        return bytes(self.code)

def guarded_inventory_dispatch(address,safe_target,native_target):
    # ECX is the Campaign controller for both vtable slots. Quick Menu keeps
    # currentItem=0; standard inventory supplies a real item ID. Tail-dispatch
    # so each original/safe callee retains its exact calling convention.
    code=bytearray()
    branches=[]
    code += bytes.fromhex('81 39 c8 cc 39 01')       # Campaign vtable
    branches.append(len(code)+1);code += b'\x75\x00' # JNE native
    code += bytes.fromhex('8b 81 cc 02 00 00')       # controller->uItemDraw
    code += bytes.fromhex('85 c0')
    branches.append(len(code)+1);code += b'\x74\x00' # JE native
    code += bytes.fromhex('81 38 d0 f4 3b 01')       # uItemDraw vtable
    branches.append(len(code)+1);code += b'\x75\x00' # JNE native
    code += bytes.fromhex('83 b8 94 00 00 00 00')    # currentItem
    branches.append(len(code)+1);code += b'\x74\x00' # JE native/Quick Menu
    code += jump_bytes(address+len(code),safe_target)
    native_offset=len(code)
    code += jump_bytes(address+len(code),native_target)
    for displacement in branches:
        delta=native_offset-(displacement+1)
        if not -128<=delta<=127:raise RuntimeError('Guard branch exceeds rel8')
        code[displacement]=delta&0xFF
    return bytes(code)

def centered_draw_wrapper(address,safe_target,config_address):
    """Call the confirmed transform, then center it using the live viewport."""
    b=CodeBuilder(address)
    b.emit('ff 74 24 04');b.call(safe_target)
    b.emit('9c 60 83 ec 20 0f 11 04 24 0f 11 4c 24 10')
    b.emit('a1');b.absolute(hud.MODE_POINTER);b.emit('85 c0');b.jump('0f 84','done')
    b.emit('83 b8 f0 08 00 00 01');b.jump('0f 85','done')
    b.emit('83 b8 f4 08 00 00 01');b.jump('0f 85','done')
    # Original draw argument is 0x48 bytes above the saved-XMM stack frame.
    b.emit('8b 44 24 48 85 c0');b.jump('0f 84','done')
    b.emit('8b 40 04 85 c0');b.jump('0f 84','done')
    b.emit('8b b8 18 18 00 00 85 ff');b.jump('0f 84','done')
    b.emit('a1');b.absolute(GFX_POINTER);b.emit('85 c0');b.jump('0f 84','done')
    # Campaign player 1 uses viewport zero. Read its real rectangle every draw.
    b.emit('8b 50 50 2b 50 48 8b 48 54 2b 48 4c')
    b.emit('85 d2');b.jump('0f 8e','done');b.emit('85 c9');b.jump('0f 8e','done')
    # desired=min(H/720,W/contentRight,H/contentBottom)
    b.emit('f3 0f 2a c1 f3 0f 5e 05');b.absolute(config_address+0x04)
    b.emit('f3 0f 2a ca f3 0f 5e 0d');b.absolute(config_address+0x08)
    b.emit('f3 0f 5d c1 f3 0f 2a c9 f3 0f 5e 0d');b.absolute(config_address+0x0C)
    b.emit('f3 0f 5d c1')
    # NDC delta = contentBottom*desired/H - 1, i.e. a centered pixel offset.
    b.emit('f3 0f 59 05');b.absolute(config_address+0x0C)
    b.emit('f3 0f 2a c9 f3 0f 5e c1 f3 0f 5c 05');b.absolute(config_address+0x60)
    b.emit('f3 0f 58 47 0c f3 0f 11 47 0c f0 ff 05');b.absolute(config_address+0x68)
    b.mark('done')
    b.emit('0f 10 04 24 0f 10 4c 24 10 83 c4 20 61 9d c2 04 00')
    return b.finish()

def centered_preview_wrapper(address,safe_target,config_address,owner_from_ebx=False):
    """Apply the same live pixel translation to the corrected preview rect."""
    b=CodeBuilder(address)
    # Keep the original item-draw ECX and Campaign-owner EDI across the call.
    b.emit('51');b.emit('53' if owner_from_ebx else '57');b.emit('ff 74 24 0c');b.call(safe_target)
    b.emit('9c 60 83 ec 20 0f 11 04 24 0f 11 4c 24 10')
    b.emit('8b 7c 24 44 8b 74 24 48')
    b.emit('81 3f c8 cc 39 01');b.jump('0f 85','done')
    b.emit('39 b7 cc 02 00 00');b.jump('0f 85','done')
    b.emit('81 3e d0 f4 3b 01');b.jump('0f 85','done')
    b.emit('80 be 90 00 00 00 00');b.jump('0f 85','done')
    b.emit('8b 8e 8c 00 00 00 83 f9 01');b.jump('0f 87','done')
    b.emit('a1');b.absolute(hud.MODE_POINTER);b.emit('85 c0');b.jump('0f 84','done')
    b.emit('83 b8 f0 08 00 00 01');b.jump('0f 85','done')
    b.emit('83 b8 f4 08 00 00 01');b.jump('0f 85','done')
    b.emit('a1');b.absolute(GFX_POINTER);b.emit('85 c0');b.jump('0f 84','done')
    b.emit('69 c9 90 01 00 00 8d 7c 08 48')
    b.emit('8b 47 08 2b 07 8b 57 0c 2b 57 04')
    b.emit('85 c0');b.jump('0f 8e','done');b.emit('85 d2');b.jump('0f 8e','done')
    # Recompute desired from this preview's own viewport.
    b.emit('f3 0f 2a c2 f3 0f 5e 05');b.absolute(config_address+0x04)
    b.emit('f3 0f 2a c8 f3 0f 5e 0d');b.absolute(config_address+0x08)
    b.emit('f3 0f 5d c1 f3 0f 2a ca f3 0f 5e 0d');b.absolute(config_address+0x0C)
    b.emit('f3 0f 5d c1 f3 0f 59 05');b.absolute(config_address+0x0C)
    b.emit('f3 0f 2a ca f3 0f 5c c8 f3 0f 59 0d');b.absolute(config_address+0x64)
    b.emit('f3 0f 2c d1 01 96 a8 00 00 00 01 96 b0 00 00 00')
    b.emit('f0 ff 05');b.absolute(config_address+0x6C)
    b.mark('done')
    b.emit('0f 10 04 24 0f 10 4c 24 10 83 c4 20 61 9d 83 c4 08 c2 04 00')
    return b.finish()

def centered_shortcut_update_wrapper(address,native_target,config_address,controller,
                                     include_campaign_center=False):
    """Make the shortcut root follow the exact Campaign scale and centering."""
    b=CodeBuilder(address)
    b.emit('56 53 57 55 8b f1 b8');b.absolute(native_target);b.emit('ff d0 50 9c 60')
    b.emit('83 ec 40 0f 11 04 24 0f 11 4c 24 10 0f 11 54 24 20 0f 11 5c 24 30')
    b.emit('81 3e b0 af 39 01');b.jump('0f 85','done')
    b.emit('a1');b.absolute(hud.MODE_POINTER);b.emit('85 c0');b.jump('0f 84','done')
    b.emit('83 b8 f0 08 00 00 01');b.jump('0f 85','done')
    b.emit('83 b8 f4 08 00 00 01');b.jump('0f 85','done')
    b.emit('8b 86 ac 02 00 00 83 f8 01');b.jump('0f 87','done')
    b.emit('8b 2d');b.absolute(GFX_POINTER);b.emit('85 ed');b.jump('0f 84','done')
    b.emit('69 c0 90 01 00 00 8d 6c 05 48')
    b.emit('8b 55 08 2b 55 00 8b 4d 0c 2b 4d 04')
    b.emit('85 d2');b.jump('0f 8e','done');b.emit('85 c9');b.jump('0f 8e','done')
    b.emit('8b ae f8 00 00 00 85 ed');b.jump('0f 84','done')
    b.emit('8b 6d 00 85 ed');b.jump('0f 84','done')
    b.emit('81 7d 00 30 d3 41 01');b.jump('0f 85','done')
    b.emit('39 75 6c');b.jump('0f 85','done')
    # Only the active Quick Menu instance has this verified canonical root.
    # Other class instances use 1244-based inactive/menu-specific positions.
    b.emit('81 bd a0 00 00 00 00 00 aa 43');b.jump('0f 85','done')
    b.emit('81 bd a4 00 00 00 00 00 8c 43');b.jump('0f 85','done')
    b.emit('81 bd b0 00 00 00 00 00 80 3f');b.jump('0f 85','done')
    b.emit('81 bd b4 00 00 00 00 00 80 3f');b.jump('0f 85','done')
    # desired in xmm0.
    b.emit('f3 0f 2a c1 f3 0f 5e 05');b.absolute(config_address+0x04)
    b.emit('f3 0f 2a da f3 0f 5e 1d');b.absolute(config_address+0x08)
    b.emit('f3 0f 5d c3 f3 0f 2a d9 f3 0f 5e 1d');b.absolute(config_address+0x0C)
    b.emit('f3 0f 5d c3')
    # FIT=min(W/1280,H/720) in xmm1; ratio=desired/FIT in xmm2.
    b.emit('f3 0f 2a ca f3 0f 5e 0d');b.absolute(config_address+0x00)
    b.emit('f3 0f 2a d9 f3 0f 5e 1d');b.absolute(config_address+0x04)
    b.emit('f3 0f 5d cb 0f 28 d0 f3 0f 5e d1')
    # local X=340*ratio, scale=ratio.
    b.emit('f3 0f 10 1d');b.absolute(config_address+0x74)
    b.emit('f3 0f 59 da f3 0f 11 9d a0 00 00 00')
    b.emit('f3 0f 11 95 b0 00 00 00 f3 0f 11 95 b4 00 00 00')
    # Shortcut is a separate controller. Its canonical Y follows the adaptive
    # scale, but the Campaign draw-matrix centering term must not be applied a
    # second time here; doing so places the hotkey block over the description.
    b.emit('f3 0f 10 1d');b.absolute(config_address+0x78)
    if include_campaign_center:
        b.emit('f3 0f 59 d8')
        b.emit('0f 28 d0 f3 0f 59 15');b.absolute(config_address+0x0C)
        b.emit('f3 0f 2a c1 f3 0f 5c c2 f3 0f 59 05');b.absolute(config_address+0x64)
        b.emit('f3 0f 58 d8 f3 0f 5e d9')
    else:
        b.emit('f3 0f 59 da')
    b.emit('f3 0f 11 9d a4 00 00 00')
    # The shortcut controller caches final matrices separately from the root
    # locals. Shift every active owned node by targetRootY-currentRootY. The
    # root reaches an absolute target, so this never accumulates across frames.
    b.emit('f3 0f 10 1d');b.absolute(config_address+0x78)
    b.emit('f3 0f 59 d8 f3 0f 5c 5d 44')
    b.emit('8b be f8 00 00 00 85 ff');b.jump('0f 84','matrix_done')
    b.emit('b9');b.absolute(SHORTCUT_NODE_COUNT)
    b.mark('matrix_loop')
    b.emit('8b 07 83 c7 04 85 c0');b.jump('0f 84','matrix_next')
    b.emit('39 70 6c');b.jump('0f 85','matrix_next')
    b.emit('8b 50 40 0b 50 44');b.jump('0f 84','matrix_next')
    b.emit('83 78 24 00');b.jump('0f 84','matrix_next')
    b.emit('f3 0f 10 50 44 f3 0f 58 d3 f3 0f 11 50 44')
    b.mark('matrix_next')
    b.emit('49');b.jump('0f 85','matrix_loop')
    b.mark('matrix_done')
    b.emit('81 4d 54 00 00 01 00 f0 ff 05');b.absolute(config_address+0x70)
    b.mark('done')
    b.emit('0f 10 04 24 0f 10 4c 24 10 0f 10 54 24 20 0f 10 5c 24 30')
    b.emit('83 c4 40 61 9d 58 5d 5f 5b 5e c3')
    return b.finish()
def adaptive_scale(width,height,content_right=980.,content_bottom=650.):
    if min(width,height,content_right,content_bottom)<=0:raise ValueError('Dimensions must be positive')
    return min(height/720.,width/content_right,height/content_bottom)

def shortcut_local_transform(width,height,canonical_y=SHORTCUT_CANONICAL_Y,
                             content_right=980.,content_bottom=650.):
    desired=adaptive_scale(width,height,content_right,content_bottom)
    fit=min(width/1280.,height/720.)
    if fit<=0:raise ValueError('Viewport FIT scale must be positive')
    ratio=desired/fit
    return 340.*ratio,canonical_y*ratio,ratio,ratio

def preview_rectangle(rect,viewport,screen,content_right=980.,content_bottom=650.):
    left,top,right,bottom=viewport; width,height=right-left,bottom-top
    if min(width,height,*screen)<=0:raise ValueError('Dimensions must be positive')
    fit=min(width/1280.,height/720.); desired=adaptive_scale(width,height,content_right,content_bottom)
    old_x=int(720*screen[0]/screen[1]-800)
    x=(rect[0]-left)/fit-old_x; y=(rect[1]-top)/fit
    native_height_scale=height/720.
    w=(rect[2]-rect[0])/native_height_scale; h=(rect[3]-rect[1])/native_height_scale
    return tuple(int(v) for v in (left+x*desired,top+y*desired,left+(x+w)*desired,top+(y+h)*desired))

def config_bytes(content_right=980.,content_bottom=650.,core=0):
    return struct.pack('<6f4I14f',1280.,720.,content_right,content_bottom,78.,138.,0,core,0,0,
                       0.,0.,800.,1.6,-.375,-1.,*([0.]*8))

def centered_config_bytes(base,shortcut_y=SHORTCUT_CANONICAL_Y):
    if len(base)>0x60:raise RuntimeError('Safe config overlaps centering extension')
    if not 0.<shortcut_y<650.:raise ValueError('Shortcut canonical Y must stay inside content bounds')
    # +60 one, +64 half, +68/+6C/+70 counters, +74/+78 shortcut SP root.
    return base+bytes(0x60-len(base))+struct.pack('<2f3I2f',1.,.5,0,0,0,340.,shortcut_y)

def shortcut_root(process,controller,require_native=False):
    process.expect(controller,hud.u32(SHORTCUT_VTABLE))
    player=process.integer(controller+0x2AC)
    if player>1:raise RuntimeError('Shortcut player index is outside the verified split-screen pair')
    table=process.integer(controller+0xF8)
    if not table:raise RuntimeError('Shortcut has no node table')
    node=process.integer(table)
    if not node:raise RuntimeError('Shortcut has no root node')
    process.expect(node,hud.u32(0x141D330));process.expect(node+0x6C,hud.u32(controller))
    if require_native:
        process.expect(node+0xA0,struct.pack('<2f',340.,280.))
        process.expect(node+0xB0,struct.pack('<2f',1.,1.))
        selector=(process.integer(node+0x80)>>16)&15
        if selector!=5:raise RuntimeError('Shortcut root is not on verified native FIT selector 5')
    return {'controller':controller,'player':player,'table':table,'node':node,
            'local':process.read(node+0xA0,8).hex(),'scale':process.read(node+0xB0,8).hex()}

def patches(state):
    draw_target=state['allocation']+state['exports']['_InventoryDraw']
    update_target=state['allocation']+state['exports']['_InventoryUpdate']
    if state.get('quickMenuGuard'):
        draw_target=state['allocation']+state['guardOffsets']['draw']
        update_target=state['allocation']+state['guardOffsets']['update']
    size_targets={name:state['allocation']+state['exports'][name] for _,name in CALLS}
    if state.get('centerContent'):
        draw_target=state['allocation']+state['centerOffsets']['draw']
        size_targets['_InventorySizeStandard']=state['allocation']+state['centerOffsets']['previewStandard']
        size_targets['_InventorySizeAlternate']=state['allocation']+state['centerOffsets']['previewAlternate']
    out=[(site,call_bytes(site,0x96C4D0),call_bytes(site,size_targets[name])) for site,name in CALLS]
    out += [(DRAW_SLOT,hud.u32(hud.DRAW_ENTRY),hud.u32(draw_target)),
            (UPDATE_SLOT,hud.u32(UPDATE_ENTRY),hud.u32(update_target))]
    out += [(site,b'\x84\xc0',b'\x30\xc0') for site in LAYOUT_TESTS]
    if state.get('shortcutController'):
        out.append((SHORTCUT_UPDATE_SLOT,hud.u32(SHORTCUT_UPDATE_ENTRY),
                    hud.u32(state['allocation']+state['centerOffsets']['shortcut'])))
    return out

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--object',type=Path,default=ROOT/'out/tests/inventory/InventoryPreviewLive.obj')
    parser.add_argument('--template-state',type=Path,
                        help='Reuse the exact confirmed safe -01 unbound code blob')
    parser.add_argument('--guard-quick-menu',action='store_true',
                        help='Keep currentItem=0 Quick Menu on native update/draw slots')
    parser.add_argument('--center-content',action='store_true',
                        help='Center the complete scaled screen from the live viewport dimensions')
    parser.add_argument('--shortcut-controller',type=lambda value:int(value,0),
                        help='Exact active uGUIEquipShortcut controller to follow the Campaign transform')
    parser.add_argument('--shortcut-y',type=float,
                        help='Canonical adaptive shortcut Y; used for a new apply or in-place retune')
    parser.add_argument('--mode',choices=('plan','apply','reapply','inspect','retune-shortcut','restore'),default='inspect')
    parser.add_argument('--content-right',type=float,default=980.,help='Rightmost visible SP content edge in 1280x720 coordinates')
    parser.add_argument('--content-bottom',type=float,default=650.,help='Bottom visible SP content edge in 1280x720 coordinates')
    args=parser.parse_args()
    p=hud.Process(args.pid,args.mode in ('apply','reapply','retune-shortcut','restore'))
    try:
        identity=p.identity()
        state=json.loads(args.state.read_text()) if args.state.exists() else None
        if state and (state['pid']!=args.pid or state['identity']!=identity):raise RuntimeError('Stale process state')
        asi=Path(identity['image']).parent/'scripts/ResidentEvilRevelations2.FusionFix.asi'
        asi_hash=hashlib.sha256(asi.read_bytes()).hexdigest()
        profile=ASI_PROFILES.get(asi_hash)
        if not profile:raise RuntimeError('Unverified ASI')
        if args.mode in ('apply','plan'):
            if state:raise RuntimeError('Use a fresh state path')
            if args.template_state:
                code,exports,object_hash=load_template(
                    args.template_state,args.content_right,args.content_bottom)
            else:
                code,exports=load_object(args.object)
                object_hash=hashlib.sha256(args.object.read_bytes()).hexdigest()
            for site,_ in CALLS:p.expect(site,call_bytes(site,0x96C4D0))
            p.expect(DRAW_SLOT,hud.u32(hud.DRAW_ENTRY))
            p.expect(UPDATE_SLOT,hud.u32(UPDATE_ENTRY))
            for site in LAYOUT_TESTS:p.expect(site,b'\x84\xc0')
            # Confirm the original size ABI and all three still-ASI position calls.
            p.expect(0x96C4D0,bytes.fromhex('8b54240469d2d0020000'))
            jump=p.read(hud.DRAW_ENTRY,5)
            if jump[0]!=0xE9:raise RuntimeError('Missing renderer redirect')
            base=hud.DRAW_ENTRY+5+struct.unpack('<i',jump[1:])[0]-profile['rescaleRva']
            p.expect(base,b'MZ')
            for pos in (0x8F7A29,0x8FA254,0x8FA2E5):
                p.expect(pos,call_bytes(pos,base+profile['positionRva']))
            core=base+profile['coreRva']
            p.expect(core,profile['coreProlog'])
            state={'pid':args.pid,'identity':identity,'status':'planned',
                   'asiHash':asi_hash,'core':core,'exports':exports,'objectHash':object_hash,
                   'contentBounds':[0.,0.,args.content_right,args.content_bottom],
                   'policy':'SP height scale maximum; uniform shrink only when canonical visible bounds exceed viewport',
                   'unboundCode':code.hex(),'config':config_bytes(args.content_right,args.content_bottom,core).hex()}
            if args.guard_quick_menu:
                state.update(quickMenuGuard=True,guardOffsets={'draw':0x800,'update':0x880})
            if args.center_content:
                if args.guard_quick_menu:raise RuntimeError('Centering and Quick Menu guard are mutually exclusive')
                if not args.shortcut_controller:
                    raise RuntimeError('Centered Campaign test requires its active shortcut controller')
                p.expect(SHORTCUT_UPDATE_SLOT,hud.u32(SHORTCUT_UPDATE_ENTRY))
                shortcut=shortcut_root(p,args.shortcut_controller,require_native=True)
                state.update(centerContent=True,
                             centerOffsets={'draw':0x600,'previewStandard':0x800,
                                            'previewAlternate':0xA00,'shortcut':0xC00},
                             centerTranslation='dynamic from each live viewport rectangle',
                             shortcutVerticalPolicy='canonical Y under adaptive scale; no Campaign draw centering term',
                             shortcutCanonicalY=(args.shortcut_y if args.shortcut_y is not None else SHORTCUT_CANONICAL_Y),
                             shortcutDynamicControllers=True,
                             shortcutController=args.shortcut_controller,
                             shortcutBefore=shortcut)
                state['config']=centered_config_bytes(
                    bytes.fromhex(state['config']),state['shortcutCanonicalY']).hex()
            if args.mode=='apply':
                allocation=p.k.VirtualAllocEx(p.handle,None,8192,0x3000,0x04);p.check(allocation)
                if allocation+8192>0x100000000:raise RuntimeError('Allocation outside x86')
                state.update(allocation=allocation,status='prepared')
                p.write(allocation,bind(code,allocation+4096))
                if state.get('quickMenuGuard'):
                    draw_guard=guarded_inventory_dispatch(
                        allocation+state['guardOffsets']['draw'],
                        allocation+exports['_InventoryDraw'],hud.DRAW_ENTRY)
                    update_guard=guarded_inventory_dispatch(
                        allocation+state['guardOffsets']['update'],
                        allocation+exports['_InventoryUpdate'],UPDATE_ENTRY)
                    p.write(allocation+state['guardOffsets']['draw'],draw_guard)
                    p.write(allocation+state['guardOffsets']['update'],update_guard)
                    state['guardCode']={'draw':draw_guard.hex(),'update':update_guard.hex()}
                if state.get('centerContent'):
                    config_address=allocation+4096
                    centered={
                        'draw':centered_draw_wrapper(
                            allocation+state['centerOffsets']['draw'],
                            allocation+exports['_InventoryDraw'],config_address),
                        'previewStandard':centered_preview_wrapper(
                            allocation+state['centerOffsets']['previewStandard'],
                            allocation+exports['_InventorySizeStandard'],config_address),
                        'previewAlternate':centered_preview_wrapper(
                            allocation+state['centerOffsets']['previewAlternate'],
                            allocation+exports['_InventorySizeAlternate'],config_address,
                            owner_from_ebx=True),
                        'shortcut':centered_shortcut_update_wrapper(
                            allocation+state['centerOffsets']['shortcut'],
                            SHORTCUT_UPDATE_ENTRY,config_address,state['shortcutController']),
                    }
                    limits={'draw':state['centerOffsets']['previewStandard'],
                            'previewStandard':state['centerOffsets']['previewAlternate'],
                            'previewAlternate':state['centerOffsets']['shortcut'],
                            'shortcut':0x1000}
                    for name,value in centered.items():
                        if state['centerOffsets'][name]+len(value)>limits[name]:
                            raise RuntimeError(f'{name} wrapper exceeds reserved slot')
                        p.write(allocation+state['centerOffsets'][name],value)
                    state['centerCode']={name:value.hex() for name,value in centered.items()}
                p.write(allocation+4096,bytes.fromhex(state['config']))
                p.protect(allocation,4096,0x20)
                p.check(p.k.FlushInstructionCache(p.handle,allocation,4096))
                args.state.parent.mkdir(parents=True,exist_ok=True)
                with args.state.open('x',encoding='utf-8') as f:json.dump(state,f,indent=2)
                hud.transact(p,patches(state))
                state['status']='applied';args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        elif args.mode=='reapply':
            if not state or state['status']!='restored':raise RuntimeError('No restored test to reapply')
            p.expect(state['allocation'],bind(bytes.fromhex(state['unboundCode']),state['allocation']+4096))
            saved_config=bytes.fromhex(state['config']);config_address=state['allocation']+4096
            # Runtime counters and last computed scales are intentionally mutable.
            p.expect(config_address,saved_config[:0x18])
            p.expect(config_address+0x1C,saved_config[0x1C:0x20])
            p.expect(config_address+0x30,saved_config[0x30:0x34])
            hud.transact(p,patches(state))
            state['status']='applied';args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        elif args.mode=='retune-shortcut':
            if not state or state['status']!='applied' or not state.get('centerContent'):
                raise RuntimeError('No active centered shortcut test to retune')
            address=state['allocation']+state['centerOffsets']['shortcut']
            old=bytes.fromhex(state['centerCode']['shortcut'])
            p.expect(address,old)
            replacement=centered_shortcut_update_wrapper(
                address,SHORTCUT_UPDATE_ENTRY,state['allocation']+4096,
                state['shortcutController'],include_campaign_center=False)
            slot_size=0x1000-state['centerOffsets']['shortcut']
            if len(replacement)>slot_size:raise RuntimeError('Retuned shortcut exceeds active code slot')
            if len(replacement)>len(old):
                p.expect(address+len(old),bytes(len(replacement)-len(old)))
            else:
                replacement += b'\xCC'*(len(old)-len(replacement))
            with p.suspended():
                protection=p.protect(address,len(replacement),0x40)
                try:
                    p.write(address,replacement);p.expect(address,replacement)
                    p.check(p.k.FlushInstructionCache(p.handle,address,len(replacement)))
                finally:p.protect(address,len(replacement),protection)
            state['centerCode']['shortcut']=replacement.hex()
            state['shortcutVerticalPolicy']='canonical Y under adaptive scale; no Campaign draw centering term'
            state['shortcutDynamicControllers']=True
            if args.shortcut_y is not None:
                if not 0.<args.shortcut_y<state['contentBounds'][3]:
                    raise ValueError('Shortcut canonical Y must stay inside content bounds')
                config=bytearray.fromhex(state['config'])
                struct.pack_into('<f',config,0x78,args.shortcut_y)
                try:current=shortcut_root(p,state['shortcutController'])
                except (OSError,RuntimeError):current=None
                if current:
                    gfx=p.integer(GFX_POINTER);player=current['player']
                    viewport=struct.unpack('<4i',p.read(gfx+0x48+player*0x190,16))
                    width,height=viewport[2]-viewport[0],viewport[3]-viewport[1]
                    local=shortcut_local_transform(
                        width,height,args.shortcut_y,state['contentBounds'][2],state['contentBounds'][3])
                with p.suspended():
                    p.write(state['allocation']+4096+0x78,struct.pack('<f',args.shortcut_y))
                    cleanup=[]
                    if current:
                        p.write(current['node']+0xA0,struct.pack('<2f',*local[:2]))
                        p.write(current['node']+0xB0,struct.pack('<2f',*local[2:]))
                        flags=p.integer(current['node']+0x54)&~0x10000
                        p.write(current['node']+0x54,hud.u32(flags))
                        for index in SHORTCUT_INACTIVE_MATRIX_INDICES:
                            node=p.integer(current['table']+index*4)
                            if not node or p.integer(node+0x6C)!=state['shortcutController']:continue
                            mx,my=struct.unpack('<2f',p.read(node+0x40,8))
                            if mx==0. and my<0.:
                                p.write(node+0x44,struct.pack('<f',0.));cleanup.append(index)
                        # E170F8 observes this cached edge and performs the native
                        # full-subtree matrix refresh on the next GUI update.
                        p.write(state['shortcutController']+0x170,hud.u32(0xFFFFFFFF))
                state['config']=config.hex();state['shortcutCanonicalY']=args.shortcut_y
                if cleanup:state['shortcutInactiveMatrixCleanup']=cleanup
                if not current:state['shortcutControllerRecreated']=True
            state['shortcutRetunedInPlace']=True
            args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        elif args.mode=='restore':
            if not state or state['status'] not in ('applied','prepared'):raise RuntimeError('No active test')
            p.expect(state['allocation'],bind(bytes.fromhex(state['unboundCode']),state['allocation']+4096))
            hud.transact(p,patches(state),restore=True)
            if state.get('shortcutController'):
                try:current=shortcut_root(p,state['shortcutController'])
                except (OSError,RuntimeError):current=None
                before=state['shortcutBefore']
                if current and current['node']==before['node']:
                    with p.suspended():
                        p.write(current['node']+0xA0,bytes.fromhex(before['local']))
                        p.write(current['node']+0xB0,bytes.fromhex(before['scale']))
                        dirty=p.integer(current['node']+0x54)|0x10000
                        p.write(current['node']+0x54,hud.u32(dirty))
            state['status']='restored';args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        if not state:raise RuntimeError('No saved state')
        result={k:v for k,v in state.items() if k not in ('unboundCode','config')}
        if 'allocation' in state:
            p.expect(state['allocation'],bind(bytes.fromhex(state['unboundCode']),state['allocation']+4096))
            for name,value in state.get('guardCode',{}).items():
                p.expect(state['allocation']+state['guardOffsets'][name],bytes.fromhex(value))
            for name,value in state.get('centerCode',{}).items():
                p.expect(state['allocation']+state['centerOffsets'][name],bytes.fromhex(value))
            for address,original,patched in patches(state):p.expect(address,patched if state['status']=='applied' else original)
            result['previewCorrections']=p.integer(state['allocation']+4096+0x18)
            result['panelDraws']=p.integer(state['allocation']+4096+0x20)
            result['panelUpdates']=p.integer(state['allocation']+4096+0x24)
            result['lastDesiredScale']=struct.unpack('<f',p.read(state['allocation']+4096+0x28,4))[0]
            result['lastRootRatio']=struct.unpack('<f',p.read(state['allocation']+4096+0x2C,4))[0]
            if state.get('centerContent'):
                result['centeredDraws']=p.integer(state['allocation']+4096+0x68)
                result['centeredPreviews']=p.integer(state['allocation']+4096+0x6C)
                result['shortcutUpdates']=p.integer(state['allocation']+4096+0x70)
                try:result['shortcutRoot']=shortcut_root(p,state['shortcutController'])
                except (OSError,RuntimeError):result['shortcutRoot']='reference controller was recreated; dynamic class/layout guard remains active'
            if len(bytes.fromhex(state['config']))>=0x60:
                result['drawCompensation']=struct.unpack('<3f',p.read(state['allocation']+4096+0x34,12))
                result['drawConstantsBefore']=struct.unpack('<4f',p.read(state['allocation']+4096+0x40,16))
                result['drawConstantsAfter']=struct.unpack('<4f',p.read(state['allocation']+4096+0x50,16))
        print(json.dumps(result,indent=2))
    finally:p.close()

if __name__=='__main__':main()
