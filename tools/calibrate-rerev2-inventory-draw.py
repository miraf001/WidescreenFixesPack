"""Calibrate Campaign RESCALE shader output against the accepted mode-0 draw."""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import struct
import time

spec=importlib.util.spec_from_file_location('inventory',Path(__file__).with_name('test-rerev2-inventory-live.py'))
inventory=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventory)
h=inventory.hud

MODE0=struct.pack('<I',0)
RESCALE=struct.pack('<I',0xDDDDDDDD)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid',type=int,required=True)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--settle-ms',type=int,default=250)
    args=parser.parse_args()
    if not 100<=args.settle_ms<=1000:raise ValueError('settle-ms must be 100..1000')
    state=json.loads(args.state.read_text())
    if state.get('status')!='applied':raise RuntimeError('Inventory test is not active')
    code=bytes.fromhex(state['unboundCode']);pattern=b'\xBA'+RESCALE
    if code.count(pattern)!=1:raise RuntimeError('Expected one RESCALE immediate')
    immediate=state['allocation']+code.index(pattern)+1
    config=state['allocation']+4096
    process=h.Process(args.pid,True)
    try:
        if process.identity()!=state['identity']:raise RuntimeError('Stale process state')
        process.expect(immediate,RESCALE)
        previous=process.read(config+0x34,12)

        def switch(old_mode,new_mode,old_comp,new_comp):
            h.transact(process,[(immediate,old_mode,new_mode),(config+0x34,old_comp,new_comp)])

        neutral=struct.pack('<3f',1.,0.,0.)
        switch(RESCALE,MODE0,previous,neutral)
        time.sleep(args.settle_ms/1000)
        baseline=struct.unpack('<4f',process.read(config+0x40,16))
        switch(MODE0,RESCALE,neutral,neutral)
        time.sleep(args.settle_ms/1000)
        rescale=struct.unpack('<4f',process.read(config+0x40,16))
        if not all(math.isfinite(value) for value in baseline+rescale) or abs(rescale[0])<1e-12:
            switch(RESCALE,RESCALE,neutral,previous)
            raise RuntimeError('Invalid captured shader constants')
        if abs(baseline[1]-rescale[1])>1e-6:
            switch(RESCALE,RESCALE,neutral,previous)
            raise RuntimeError(f'RESCALE also changes unsupported constants: {baseline} vs {rescale}')
        compensation=(baseline[0]/rescale[0],baseline[2]-rescale[2],baseline[3]-rescale[3])
        encoded=struct.pack('<3f',*compensation)
        switch(RESCALE,RESCALE,neutral,encoded)
        time.sleep(args.settle_ms/1000)
        after=struct.unpack('<4f',process.read(config+0x50,16))
        state['calibration']={'baselineMode0':baseline,'rescaleUncompensated':rescale,
                              'compensation':compensation,'rescaleCompensated':after}
        args.state.write_text(json.dumps(state,indent=2),encoding='utf-8')
        print(json.dumps(state['calibration'],indent=2))
    finally:process.close()

if __name__=='__main__':main()
