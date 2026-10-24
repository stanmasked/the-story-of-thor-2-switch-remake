#!/usr/bin/env python3
"""Add a default-disabled SH-2 dispatch-selected opcode recorder to public Mednafen.

The *lower 16 bits of Pipe_ID* are the opcode selected by SH7095::Step.
The higher bits describe the interpreter's dispatch state and are retained
in private output to distinguish normal instructions from pseudo-operations.
No original game code, BIOS, or game-specific addresses are embedded.
"""
from __future__ import annotations
import argparse
import re
from pathlib import Path

SIG = '/* STAGE113_SH2_DISPATCH_OPCODE_V1 */'
PRE='if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],true);'
POST='if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],false);'
RAM_ANCHOR = r'^static uint16 WorkRAMH\[1024 \* 1024 / sizeof\(uint16\)\];[^\n]*'
CODE = r'''
/* STAGE113_SH2_DISPATCH_OPCODE_V1 */
// This reads the SH-2 interpreter's *selected* Pipe_ID word before Step().
// The top bits include pseudo-op state; even an RTS-looking low word alone
// must never be taken as proof of executed RTS or completed return.
struct Stage113OpcodeWitness
{
 bool configured=false, enabled=false, active=false;
 uint32 trigger=0;
 uint32 last_pr=0, last_r13=0, pending_pid=0;
 unsigned pending_kind=0; // 0 none, 1 warmup, 2 BSR, 3 JSR, 4 RTS, 5 user-specified
 unsigned long steps=0, event_count=0, max_steps=2000000, max_events=16384, sample_every=8192;
 uint32 requested_opcode=0;
 bool has_requested_opcode=false;
 std::FILE* out=nullptr;

 static bool Hex(const char* s, unsigned n, uint32& value)
 {
  if(!s || std::strlen(s)!=n) return false;
  for(unsigned k=0;k<n;k++)
   if(!((s[k]>='0'&&s[k]<='9')||(s[k]>='a'&&s[k]<='f')||(s[k]>='A'&&s[k]<='F'))) return false;
  char* end=nullptr;
  const unsigned long num=std::strtoul(s,&end,16);
  if(!end || *end || num>0xffffffffUL) return false;
  value=(uint32)num;
  return true;
 }
 static bool Unsigned(const char* s, unsigned long lo, unsigned long hi, unsigned long& to)
 {
  if(!s || !*s) return true;
  for(const char* x=s;*x;x++) if(*x<'0'||*x>'9') return false;
  char* end=nullptr;
  unsigned long v=std::strtoul(s,&end,10);
  if(!end||*end||v<lo||v>hi) return false;
  to=v;return true;
 }
 void Configure()
 {
  if(configured) return;
  configured=true;
  const char* yes=std::getenv("STAGE113_OPCODE_WITNESS_ENABLE");
  const char* dst=std::getenv("STAGE113_OPCODE_WITNESS_OUT");
  const char* pc=std::getenv("STAGE113_OPCODE_WITNESS_PC");
  if(!yes||std::strcmp(yes,"1")||!dst||!*dst||!Hex(pc,8,trigger)) return;
  const char* op=std::getenv("STAGE113_OPCODE_WITNESS_TARGET_OPCODE");
  if(op&&*op)
  {
   if(!Hex(op,4,requested_opcode)) return;
   has_requested_opcode=true;
  }
  if(!Unsigned(std::getenv("STAGE113_OPCODE_WITNESS_MAX_STEPS"),1024,2000000,max_steps)) return;
  if(!Unsigned(std::getenv("STAGE113_OPCODE_WITNESS_MAX_EVENTS"),128,16384,max_events)) return;
  if(!Unsigned(std::getenv("STAGE113_OPCODE_WITNESS_SAMPLE_EVERY"),128,1048576,sample_every)) return;
  out=std::fopen(dst,"wb");enabled=(out!=nullptr);
  if(enabled){std::fprintf(out,"stage113_dispatch_selected_opcode_v1\n");std::fflush(out);}
 }
 void Log(const char* phase,const char* kind,SH7095& cpu,const uint32 pid)
 {
  if(!out||event_count>=max_events) return;
  std::fprintf(out,"%lu,%s,%s,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
   steps,phase,kind,pid,
   cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_PC_IF,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_PR,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_R13,nullptr,0),
   cpu.GetRegister(SH7095::GSREG_R3,nullptr,0));
  ++event_count;
  std::fflush(out);
 }
 void Before(SH7095& cpu)
 {
  if(!enabled) return;
  const uint32 pc_id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
  const uint32 pc_if=cpu.GetRegister(SH7095::GSREG_PC_IF,nullptr,0);
  const uint32 rpc=cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0);
  if(!active)
  {
   if(pc_id!=trigger && pc_if!=trigger && rpc!=trigger) return;
   active=true;
   last_pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
   last_r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
   Log("pre","start",cpu,cpu.GetRegister(SH7095::GSREG_PID,nullptr,0));
  }
  const uint32 pid=cpu.GetRegister(SH7095::GSREG_PID,nullptr,0);
  const uint32 op=pid&0xffffU;
  // Generic SH-2 opcode families, not any original-game literals.
  pending_kind=0;
  if(steps<8) pending_kind=1;
  if((op&0xf000U)==0xb000U) pending_kind=2; // BSR d12
  if((op&0xf0ffU)==0x400bU) pending_kind=3; // JSR @Rn
  if(op==0x000bU) pending_kind=4; // RTS
  if(has_requested_opcode && op==requested_opcode) pending_kind=5;
  pending_pid=pid;
  if(pending_kind) Log("pre","selected",cpu,pid);
 }
 void After(SH7095& cpu)
 {
  if(!enabled || !active) return;
  if(pending_kind) Log("post","selected",cpu,pending_pid);
  const uint32 pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
  const uint32 r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
  if(pr!=last_pr) Log("post","pr_change",cpu,pending_pid);
  if(r13!=last_r13) Log("post","r13_change",cpu,pending_pid);
  last_pr=pr;last_r13=r13;
  ++steps;
  if(steps%sample_every==0) Log("post","sample",cpu,pending_pid);
  if(steps>=max_steps || event_count+2>=max_events)
  {
   Log("post", steps>=max_steps ? "step_limit" : "event_cap",cpu,pending_pid);
   std::fclose(out);out=nullptr;enabled=false;
  }
 }
};
static Stage113OpcodeWitness stage113_opcode;
'''


def patch(text:str)->str:
    if SIG in text:raise ValueError('already_patched_stage113')
    for sig in ['/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */', '/* STAGE111_PRIVATE_RAM_WITNESS_V1 */','/* STAGE112_PUBLIC_SH2_LIVENESS_MONITOR_V1 */']:
        if text.count(sig)!=1:raise ValueError('requires_previous_observer')
    if text.count(PRE)!=1 or text.count(POST)!=1:raise ValueError('bad_step_anchor')
    anchor=re.search(RAM_ANCHOR,text,re.M)
    if anchor is None:raise ValueError('bad_ram_backing')
    text=text[:anchor.end()]+'\n'+CODE+text[anchor.end():]
    text=text.replace(PRE,PRE+'\n    stage113_opcode.Configure();\n    if(stage113_opcode.enabled) stage113_opcode.Before(CPU[0]);',1)
    text=text.replace(POST,POST+'\n    if(stage113_opcode.enabled) stage113_opcode.After(CPU[0]);',1)
    return text

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('source',type=Path)
    p=a.parse_args().source
    if p.is_symlink() or not p.is_file():raise SystemExit('invalid_source_file')
    try:out=patch(p.read_text(encoding='utf-8'))
    except ValueError as exc:raise SystemExit(str(exc)) from None
    p.write_text(out,encoding='utf-8');print('stage113_public_selected_opcode_patch_applied')
if __name__=='__main__':main()