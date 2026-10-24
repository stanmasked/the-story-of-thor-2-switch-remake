#!/usr/bin/env python3
"""Layer an opt-in bounded SH2 liveness event monitor over Stage109+Stage111.

Public source only; no game addresses, ROM or BIOS. Raw event output is private.
A potential RPC==PR event is only a pipeline marker, not proof of RTS.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import re

SIGNATURE='/* STAGE112_PUBLIC_SH2_LIVENESS_MONITOR_V1 */'
PRE='if(stage111_witness.enabled) stage111_witness.Record(CPU[0],"pre");'
POST='if(stage111_witness.enabled) stage111_witness.Record(CPU[0],"post");'
MEM_ANCHOR=r'^static uint16 WorkRAMH\[1024 \* 1024 / sizeof\(uint16\)\];[^\n]*'

IMPL=r'''
/* STAGE112_PUBLIC_SH2_LIVENESS_MONITOR_V1 */
// Default-disabled, bounded private SH2 event recorder. No MMIO access.
// Current RPC, PC_ID and PC_IF are pipeline context, not an exact opcode PC.
struct Stage112Monitor
{
 bool configured = false;
 bool enabled = false;
 bool active = false;
 bool saw_rpc_equal_pr = false;
 uint32 trigger = 0;
 uint32 target = 0;
 uint32 last_r13 = 0;
 uint32 last_pr = 0;
 unsigned last_byte = 0;
 unsigned long steps = 0;
 unsigned long events = 0;
 unsigned long max_steps = 200000;
 unsigned long max_events = 1024;
 unsigned long every = 8192;
 std::FILE* log = nullptr;

 static bool ParseHex8(const char* str, uint32& value)
 {
  if(!str || std::strlen(str)!=8) return false;
  for(unsigned k=0;k<8;k++)
   if(!((str[k]>='0'&&str[k]<='9')||(str[k]>='a'&&str[k]<='f')||(str[k]>='A'&&str[k]<='F'))) return false;
  char* end=nullptr;
  unsigned long parsed=std::strtoul(str,&end,16);
  if(!end || *end || parsed>0xFFFFFFFFUL) return false;
  value=(uint32)parsed;
  return true;
 }

 static bool ParseUnsigned(const char* src, unsigned long low, unsigned long high, unsigned long& dst)
 {
  if(!src || !*src) return true;
  for(const char* p=src;*p;p++) if(*p<'0'||*p>'9') return false;
  char* end=nullptr;
  unsigned long n=std::strtoul(src,&end,10);
  if(!end || *end || n<low || n>high) return false;
  dst=n;
  return true;
 }

 void Configure()
 {
  if(configured) return;
  configured=true;
  const char* yes=std::getenv("STAGE112_SH2_EVENTS_ENABLE");
  const char* pc=std::getenv("STAGE112_SH2_EVENTS_PC");
  const char* ptr=std::getenv("STAGE112_SH2_EVENTS_RAM_POINTER");
  const char* out=std::getenv("STAGE112_SH2_EVENTS_OUT");
  if(!yes || std::strcmp(yes,"1") || !out || !*out || !ParseHex8(pc,trigger) || !ParseHex8(ptr,target)) return;
  if(target<0x06000000U || target>=0x08000000U) return;
  if(!ParseUnsigned(std::getenv("STAGE112_SH2_EVENTS_MAX_STEPS"),1024,2000000,max_steps)) return;
  if(!ParseUnsigned(std::getenv("STAGE112_SH2_EVENTS_MAX_EVENTS"),16,4096,max_events)) return;
  if(!ParseUnsigned(std::getenv("STAGE112_SH2_EVENTS_SAMPLE_EVERY"),128,1048576,every)) return;
  log=std::fopen(out,"wb");
  enabled=(log != nullptr);
  if(enabled){std::fprintf(log,"stage112_sh2_events_v1\n");std::fflush(log);}
 }

 unsigned ByteAtTarget() const {return ne16_rbo_be<uint8>(WorkRAMH,target & 0xFFFFFU);}

 void Event(const char* name, uint32 rpc, uint32 pr, uint32 r13, unsigned byte)
 {
  if(!log || events>=max_events) return;
  std::fprintf(log,"%lu,%s,%08x,%08x,%08x,%02x\n",steps,name,rpc,pr,r13,byte);
  events++;
  std::fflush(log);
 }

 void Record(SH7095& cpu, const bool before)
 {
  if(!enabled) return;
  const uint32 rpc=cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0);
  if(!active)
  {
   if(!before) return;
   const uint32 id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
   const uint32 fi=cpu.GetRegister(SH7095::GSREG_PC_IF,nullptr,0);
   if(rpc!=trigger && id!=trigger && fi!=trigger) return;
   active=true;
   last_r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
   last_pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
   last_byte=ByteAtTarget();
   Event("start",rpc,last_pr,last_r13,last_byte);
   return;
  }
  if(before) return;
  steps++;
  const uint32 pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
  const uint32 r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
  const unsigned byte=ByteAtTarget();
  if(r13!=last_r13) Event("r13_change",rpc,pr,r13,byte);
  if(pr!=last_pr) Event("pr_change",rpc,pr,r13,byte);
  if(byte!=last_byte) Event("byte_change",rpc,pr,r13,byte);
  if(!saw_rpc_equal_pr && pr && pr==rpc)
  {
   saw_rpc_equal_pr=true;
   Event("rpc_equals_pr_candidate",rpc,pr,r13,byte);
  }
  if(steps%every==0) Event("sample",rpc,pr,r13,byte);
  last_pr=pr;last_r13=r13;last_byte=byte;
  if(steps>=max_steps)
  {
   Event("step_limit",rpc,pr,r13,byte);
   std::fclose(log);log=nullptr;enabled=false;
  }
 }
};
static Stage112Monitor stage112_monitor;
'''

def patch(source:str)->str:
    if SIGNATURE in source:raise ValueError('already_patched_stage112')
    if source.count('/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */') != 1:raise ValueError('stage109_missing')
    if source.count('/* STAGE111_PRIVATE_RAM_WITNESS_V1 */') != 1:raise ValueError('stage111_missing')
    if source.count(PRE)!=1 or source.count(POST)!=1:raise ValueError('step_anchors_missing')
    anchor=re.search(MEM_ANCHOR,source,re.M)
    if anchor is None:raise ValueError('ram_layout_mismatch')
    source=source[:anchor.end()]+'\n'+IMPL+source[anchor.end():]
    source=source.replace(PRE,PRE+'\n    stage112_monitor.Configure();\n    if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],true);',1)
    source=source.replace(POST,POST+'\n    if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],false);',1)
    return source

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('file',type=Path)
    p=a.parse_args().file
    if p.is_symlink() or not p.is_file():raise SystemExit('invalid_source_file')
    try:out=patch(p.read_text(encoding='utf-8'))
    except ValueError as e:raise SystemExit(str(e)) from None
    p.write_text(out,encoding='utf-8')
    print('stage112_public_event_monitor_source_patched')

if __name__=='__main__':main()