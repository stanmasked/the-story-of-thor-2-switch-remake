#!/usr/bin/env python3
"""Patch *public* Mednafen 1.29.0 ss.cpp with an opt-in SH-2 step recorder.

Source and patched binary contain NO private game addresses/ISO/BIOS/trace.
Only local user environment can turn the observer on and supply a trigger PC.
"""
from __future__ import annotations
import argparse
import re
from pathlib import Path

ANCHOR = 'CPU[0].Step<0, EmulateICache, DebugMode>();'
SIGNATURE = '/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */'

GLOBAL_HEADERS = "#include <cstdio>\n#include <cstdlib>\n#include <cstdint>\n#include <cstring>\n"

IMPL = r'''
/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */
// Default-disabled public source instrumentation. Only an explicitly configured
// private execution writes any raw register data, and never to stdout.
struct Stage109Observer
{
 bool configured = false;
 bool enabled = false;
 bool tracing = false;
 unsigned long limit = 256;
 unsigned long step = 0;
 uint32 trigger = 0;
 std::FILE* out = nullptr;

 void Configure()
 {
  if(configured) return;
  configured = true;
  const char* yes = std::getenv("STAGE109_SH2_OBSERVER_ENABLE");
  const char* pc = std::getenv("STAGE109_SH2_OBSERVER_PC");
  const char* dst = std::getenv("STAGE109_SH2_OBSERVER_OUT");
  const char* max = std::getenv("STAGE109_SH2_OBSERVER_MAX_STEPS");
  const char* immediate = std::getenv("STAGE109_SH2_OBSERVER_START_IMMEDIATELY");
  if(!yes || std::strcmp(yes, "1") || !pc || !dst || !*dst) return;
  // Eight hex digits are required: no hardcoded private instruction address.
  if(std::strlen(pc) != 8) return;
  for(unsigned i=0; i<8; i++)
   if(!((pc[i]>='0'&&pc[i]<='9')||(pc[i]>='a'&&pc[i]<='f')||(pc[i]>='A'&&pc[i]<='F'))) return;
  char* end = nullptr;
  const unsigned long trigger_num = std::strtoul(pc, &end, 16);
  if(!end || *end || trigger_num > 0xFFFFFFFFUL) return;
  trigger = (uint32)trigger_num;
  if(max && *max)
  {
   const unsigned long m=std::strtoul(max,&end,10);
   if(end && !*end && m>=4 && m<=4096) limit=m;
  }
  out = std::fopen(dst,"wb");
  enabled = (out != nullptr);
  // For a private smoke test, start at first executed Master SH-2 step.
  // Still requires explicit enable=1, valid private PC and writable output.
  if(enabled && immediate && !std::strcmp(immediate,"1")) tracing=true;
  if(enabled)
  {
   std::fprintf(out,"stage109_sh2_steps_v1\n");
   std::fflush(out);
  }
 }

 void Record(SH7095& cpu, const char* phase)
 {
  // The debug PC_ID, PC_IF and internal RPC are recorded together because
  // pipelined instruction fetch makes any single PC field ambiguous.
  const uint32 id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
  const uint32 fi=cpu.GetRegister(SH7095::GSREG_PC_IF,nullptr,0);
  const uint32 rpc=cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0);
  if(!tracing)
  {
   // Trigger only at a pre-step boundary: a post-only start is unpaired.
   if(std::strcmp(phase,"pre")) return;
   if(id!=trigger && fi!=trigger && rpc!=trigger) return;
   tracing=true;
  }
  std::fprintf(out,"%lu,%s,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
   step,phase,id,fi,rpc,
   cpu.GetRegister(SH7095::GSREG_R13,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_PR,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_R2,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_R3,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_R4,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_R5,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_R6,nullptr,0));
  if(!std::strcmp(phase,"post"))
  {
   ++step;
   if(step>=limit)
   {
    std::fflush(out);
    std::fclose(out);
    out=nullptr;
    enabled=false;
   }
  }
 }
};

static Stage109Observer stage109_observer;
'''


def patch(text: str) -> str:
    if SIGNATURE in text:
        raise ValueError('already_patched')
    if text.count(ANCHOR) != 1:
        raise ValueError('unsupported_source_version: cpu_step_anchor')
    cpu = re.search(r'^SH7095 CPU\[2\].*;', text, re.M)
    if cpu is None:
        raise ValueError('unsupported_source_version: cpu_global')
    # Make code available after SH7095 and the global CPU declaration.
    pos = cpu.end()
    text = text[:pos] + '\n' + IMPL + text[pos:]
    replacement = '''stage109_observer.Configure();
    if(stage109_observer.enabled) stage109_observer.Record(CPU[0],"pre");
    ''' + ANCHOR + '''
    if(stage109_observer.enabled) stage109_observer.Record(CPU[0],"post");'''
    core = '#include <mednafen/mednafen.h>\n'
    if text.count(core) != 1:
        raise ValueError('unsupported_source_version: mednafen_core_include')
    # Mednafen types.h requires mednafen.h to have initialized core typedefs.
    # Standard C++ includes must also remain OUTSIDE MDFN_IEN_SS namespace.
    text = text.replace(core, core + GLOBAL_HEADERS, 1)
    return text.replace(ANCHOR, replacement, 1)


def main() -> None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path, help='public mednafen-1.29.0 src/ss/ss.cpp')
    args=ap.parse_args()
    src=args.source
    if src.is_symlink() or not src.is_file():
        raise SystemExit('unsupported_source_file')
    original=src.read_text(encoding='utf-8')
    try:
        result=patch(original)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    src.write_text(result, encoding='utf-8')
    print('stage109_public_emulator_source_patched')

if __name__=='__main__':
    main()