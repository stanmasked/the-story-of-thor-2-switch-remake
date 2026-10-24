#!/usr/bin/env python3
"""Layer an opt-in, side-effect-free SH2 high-WRAM byte witness over Stage109.

Public Mednafen source only. No addresses, game dumps, BIOS, or raw traces embedded.
The emitted per-step memory observations are PRIVATE runtime output.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import re

SIGNATURE = '/* STAGE111_PRIVATE_RAM_WITNESS_V1 */'
ANCHOR_PRE = 'if(stage109_observer.enabled) stage109_observer.Record(CPU[0],"pre");'
ANCHOR_POST = 'if(stage109_observer.enabled) stage109_observer.Record(CPU[0],"post");'
STAGE109_SIGNATURE = '/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */'

WITNESS = r'''
/* STAGE111_PRIVATE_RAM_WITNESS_V1 */
// An explicitly enabled runtime-only observation of SH2 R3 and the physically
// backed high-work-RAM byte at R3. No MMIO, bus read or cache side effects.
// PC values are a pipeline context, not an assertion of executed opcode.
struct Stage111Witness
{
 bool configured = false;
 bool enabled = false;
 bool recording = false;
 uint32 trigger = 0;
 unsigned long count = 0;
 unsigned long max_count = 64;
 std::FILE* output = nullptr;

 void Configure()
 {
  if(configured) return;
  configured = true;
  const char* yes = std::getenv("STAGE111_RAM_WITNESS_ENABLE");
  const char* pc = std::getenv("STAGE111_RAM_WITNESS_PC");
  const char* dest = std::getenv("STAGE111_RAM_WITNESS_OUT");
  const char* cap = std::getenv("STAGE111_RAM_WITNESS_MAX_STEPS");
  if(!yes || std::strcmp(yes,"1") || !pc || !dest || !*dest) return;
  if(std::strlen(pc) != 8) return;
  for(unsigned i=0;i<8;i++)
   if(!((pc[i]>='0'&&pc[i]<='9') || (pc[i]>='a'&&pc[i]<='f') || (pc[i]>='A'&&pc[i]<='F'))) return;
  char* end = nullptr;
  unsigned long num = std::strtoul(pc,&end,16);
  if(!end || *end || num>0xFFFFFFFFUL) return;
  trigger=(uint32)num;
  if(cap && *cap)
  {
   unsigned long v=std::strtoul(cap,&end,10);
   if(!end || *end || v<4 || v>4096) return;
   max_count=v;
  }
  output=std::fopen(dest,"wb");
  enabled=(output != nullptr);
  if(enabled)
  {
   std::fprintf(output,"stage111_sh2_highram_witness_v1\n");
   std::fflush(output);
  }
 }

 void Record(SH7095& cpu, const char* phase)
 {
  if(!enabled) return;
  const uint32 id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
  const uint32 fi=cpu.GetRegister(SH7095::GSREG_PC_IF,nullptr,0);
  const uint32 rpc=cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0);
  if(!recording)
  {
   if(std::strcmp(phase,"pre")) return;
   if(id!=trigger && fi!=trigger && rpc!=trigger) return;
   recording=true;
  }
  const uint32 address=cpu.GetRegister(SH7095::GSREG_R3,nullptr,0);
  const bool valid=address>=0x06000000U && address<0x08000000U;
  // Mirrors high RAM at 1-MiB intervals. Reads directly from the same
  // public emulation backing storage, not through a bus/MMIO callback.
  const unsigned value=valid ? ne16_rbo_be<uint8>(WorkRAMH,address & 0xFFFFFU) : 0;
  std::fprintf(output,"%lu,%s,%08x,%08x,%08x,%08x,%02x,%u\n",
   count,phase,id,fi,rpc,address,value,valid ? 1 : 0);
  if(!std::strcmp(phase,"post"))
  {
   std::fflush(output);
   ++count;
   if(count>=max_count)
   {
    std::fclose(output);
    output=nullptr;
    enabled=false;
   }
  }
 }
};
static Stage111Witness stage111_witness;
'''


def patch(text: str) -> str:
    if SIGNATURE in text:
        raise ValueError('already_patched_stage111')
    if text.count(STAGE109_SIGNATURE) != 1:
        raise ValueError('stage109_observer_required')
    if text.count(ANCHOR_PRE) != 1 or text.count(ANCHOR_POST) != 1:
        raise ValueError('stage109_record_anchors_mismatch')
    mem = re.search(r'^static uint16 WorkRAMH\[1024 \* 1024 / sizeof\(uint16\)\];[^\n]*',text,re.M)
    if mem is None:
        raise ValueError('unsupported_high_ram_backing')
    text=text[:mem.end()]+'\n'+WITNESS+text[mem.end():]
    # Place memory readings on both sides of the very same CPU[0].Step call.
    text=text.replace(ANCHOR_PRE,ANCHOR_PRE+'\n    stage111_witness.Configure();\n    if(stage111_witness.enabled) stage111_witness.Record(CPU[0],"pre");',1)
    text=text.replace(ANCHOR_POST,ANCHOR_POST+'\n    if(stage111_witness.enabled) stage111_witness.Record(CPU[0],"post");',1)
    return text


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path)
    a=p.parse_args()
    if not a.source.is_file() or a.source.is_symlink():
        raise SystemExit('invalid_public_source_file')
    try:
        result=patch(a.source.read_text(encoding='utf-8'))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    a.source.write_text(result,encoding='utf-8')
    print('stage111_public_memory_witness_source_patched')

if __name__=='__main__':main()