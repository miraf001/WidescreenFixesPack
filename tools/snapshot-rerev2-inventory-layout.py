"""Read-only snapshot of a verified RE:Rev2 GUI controller node table."""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import struct

spec=importlib.util.spec_from_file_location('hud',Path(__file__).with_name('test-rerev2-sp-hud-live.py'))
hud=importlib.util.module_from_spec(spec);spec.loader.exec_module(hud)

def clean(value):
    return round(value,6) if math.isfinite(value) and abs(value)<1_000_000 else None

def pair(process,address):return [clean(v) for v in struct.unpack('<2f',process.read(address,8))]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--controller',type=lambda value:int(value,0),required=True)
    parser.add_argument('--vtable',type=lambda value:int(value,0),default=0x139CCC8,
                        help='Expected controller vtable (defaults to Campaign inventory)')
    parser.add_argument('--node-count',type=int,default=256,
                        help='Maximum number of table slots to inspect')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    process=hud.Process(args.pid,False)
    try:
        controller=args.controller
        process.expect(controller,hud.u32(args.vtable))
        root=process.integer(controller+0xF4);table=process.integer(controller+0xF8)
        process.expect(root+0x6C,hud.u32(controller))
        nodes=[]
        for index in range(args.node_count):
            address=process.integer(table+index*4)
            if not address:continue
            try:
                data=process.read(address,0xBC)
            except OSError:
                continue
            u32=lambda offset:struct.unpack_from('<I',data,offset)[0]
            # Small HUD tables are not 256 slots long. Past their real end the
            # adjacent object data can resemble pointers; only accept nodes
            # whose verified owner backlink names this controller.
            if u32(0x6C) != controller:
                continue
            nodes.append({'index':index,'address':f'0x{address:08X}','vtable':f'0x{u32(0):08X}',
                          'owner':f'0x{u32(0x6C):08X}','parent':f'0x{u32(0x5C):08X}',
                          'firstChild':f'0x{u32(0x60):08X}','nextSibling':f'0x{u32(0x64):08X}',
                          'flags':f'0x{u32(0x54):08X}','layoutFlags':f'0x{u32(0x80):08X}',
                          'localPosition':pair(process,address+0xA0),'localScale':pair(process,address+0xB0),
                          'matrixPosition':pair(process,address+0x40),
                          'matrixScale':[clean(struct.unpack('<f',process.read(address+offset,4))[0]) for offset in (0x10,0x24)]})
        report={'pid':args.pid,'identity':process.identity(),'controller':f'0x{controller:08X}',
                'vtable':f'0x{args.vtable:08X}',
                'player':process.integer(controller+0x2AC),'root':f'0x{root:08X}',
                'table':f'0x{table:08X}','nodes':nodes}
        item=process.integer(controller+0x2CC) if args.vtable == 0x139CCC8 else 0
        if item:
            report['item']=f'0x{item:08X}'
        if item and process.integer(item)==0x13BF4D0:
            report['itemState']={'state':process.integer(item+0x80),'requestedView':process.integer(item+0x84),
                                 'activeView':process.integer(item+0x88),'drawView':process.integer(item+0x8C),
                                 'overlay':process.read(item+0x90,1)[0],'currentItem':process.integer(item+0x94),
                                 'requestedItem':process.integer(item+0x9C),
                                 'rectangle':list(struct.unpack('<4i',process.read(item+0xA4,16)))}
        args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
        print(json.dumps({'output':str(args.output),'nodes':len(nodes),'itemState':report.get('itemState')},indent=2))
    finally:process.close()

if __name__=='__main__':main()
