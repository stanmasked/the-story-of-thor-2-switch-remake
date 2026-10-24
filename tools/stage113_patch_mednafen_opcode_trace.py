#!/usr/bin/env python3
"""Add a default-disabled private SH-2 opcode-dispatch trace to public Mednafen."""
from __future__ import annotations
import argparse
from pathlib import Path

SIGNATURE = "/* STAGE113_SH2_EXECUTED_OPCODE_TRACE_V1 */"
STEP = "INLINE void SH7095::Step(void)"
INSTR = "const uint32 instr = (uint16)Pipe_ID;"
NYB2 = "const unsigned instr_nyb2 = (instr >> 8) & 0xF;"
PC_ADVANCE = " PC += 2;"
STATE = "\n\nvoid SH7095::StateAction"

IMPL = r"""
/* STAGE113_SH2_EXECUTED_OPCODE_TRACE_V1 */
// Opt-in private dispatch witness. A row is emitted only after the instruction
// handler returns through the normal end of Step; missing post rows fail the gate.
struct Stage113OpcodeTrace
{
 bool configured = false;
 bool enabled = false;
 uint32 trigger = 0;
 unsigned long max_steps = 8192;
 unsigned long next_step[2] = {0, 0};
 bool active[2] = {false, false};
 std::FILE* out = nullptr;

 static bool ParseHex8(const char* src, uint32& dst)
 {
  if(!src || std::strlen(src) != 8) return false;
  for(unsigned i=0;i<8;i++)
   if(!((src[i]>='0'&&src[i]<='9')||(src[i]>='a'&&src[i]<='f')||(src[i]>='A'&&src[i]<='F'))) return false;
  char* end=nullptr;
  unsigned long v=std::strtoul(src,&end,16);
  if(!end || *end || v>0xFFFFFFFFUL) return false;
  dst=(uint32)v;
  return true;
 }

 static bool ParseLimit(const char* src, unsigned long& dst)
 {
  if(!src || !*src) return true;
  for(const char* p=src;*p;p++) if(*p<'0'||*p>'9') return false;
  char* end=nullptr;
  unsigned long v=std::strtoul(src,&end,10);
  if(!end || *end || v<16 || v>8192) return false;
  dst=v;
  return true;
 }

 void Configure()
 {
  if(configured) return;
  configured=true;
  const char* yes=std::getenv("STAGE113_OPCODE_TRACE_ENABLE");
  const char* pc=std::getenv("STAGE113_OPCODE_TRACE_PC");
  const char* dst=std::getenv("STAGE113_OPCODE_TRACE_OUT");
  if(!yes || std::strcmp(yes,"1") || !dst || !*dst || !ParseHex8(pc,trigger) ||
     !ParseLimit(std::getenv("STAGE113_OPCODE_TRACE_MAX_STEPS"),max_steps)) return;
  out=std::fopen(dst,"wb");
  enabled=(out!=nullptr);
  if(enabled){std::fprintf(out,"stage113_sh2_opcode_trace_v1\n");std::fflush(out);}
 }

 bool Write(unsigned cpu, unsigned long step, const char* phase, uint32 pipe,
            uint32 opcode, uint32 dispatch, uint32 pc, uint32 pc_id,
            uint32 pc_if, uint32 rpc, uint32 r13, uint32 pr)
 {
  if(!enabled || !out) return false;
  if(std::fprintf(out,"%u,%lu,%s,%08x,%04x,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
       cpu,step,phase,pipe,opcode,dispatch,pc,pc_id,pc_if,rpc,r13,pr)<0)
  {
   enabled=false;
   std::fclose(out);out=nullptr;
   return false;
  }
  std::fflush(out);
  return true;
 }

 long Begin(unsigned cpu, uint32 pc, uint32 pc_id, uint32 pc_if,
            uint32 rpc, uint32 pipe, uint32 opcode, uint32 r13, uint32 pr)
 {
  if(!enabled || cpu>=2) return -1;
  if(!active[cpu])
  {
   if(pc_id!=trigger && pc_if!=trigger && rpc!=trigger) return -1;
   active[cpu]=true;
  }
  if(next_step[cpu]>=max_steps) return -1;
  const unsigned long step=next_step[cpu]++;
  if(!Write(cpu,step,"pre",pipe,opcode,pipe>>24,pc,pc_id,pc_if,rpc,r13,pr)) return -1;
  return (long)step;
 }

 void Complete(unsigned cpu, long step, uint32 pipe, uint32 opcode,
               uint32 pc, uint32 pc_id, uint32 pc_if, uint32 rpc,
               uint32 r13, uint32 pr)
 {
  if(step<0 || !enabled) return;
  Write(cpu,(unsigned long)step,"post",pipe,opcode,pipe>>24,pc,pc_id,pc_if,rpc,r13,pr);
 }
};
static Stage113OpcodeTrace stage113_opcode_trace;
"""

def patch(source: str) -> str:
    if SIGNATURE in source:
        raise ValueError("already_patched_stage113")
    if source.count(STEP) != 1:
        raise ValueError("unsupported_sh2_step_anchor")
    marker=source.index(STEP)
    start=source.rfind("template<unsigned which, bool EmulateICache, int DebugMode>",0,marker)
    if start < 0:
        raise ValueError("unsupported_step_template")
    end=source.find(STATE,marker)
    if end < 0:
        raise ValueError("unsupported_step_end")
    body=source[start:end]
    if body.count(INSTR)!=1 or body.count(NYB2)!=1 or body.count(PC_ADVANCE)!=1:
        raise ValueError("unsupported_step_body")
    hook = NYB2 + r"""
 const uint32 stage113_pipe_before = Pipe_ID;
 const uint32 stage113_pc_before = PC;
 const uint32 stage113_pc_id_before = GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
 const uint32 stage113_pc_if_before = GetRegister(SH7095::GSREG_PC_IF,nullptr,0);
 const uint32 stage113_rpc_before = GetRegister(SH7095::GSREG_RPC,nullptr,0);
 const uint32 stage113_r13_before = GetRegister(SH7095::GSREG_R13,nullptr,0);
 const uint32 stage113_pr_before = GetRegister(SH7095::GSREG_PR,nullptr,0);
 stage113_opcode_trace.Configure();
 const long stage113_trace_step = stage113_opcode_trace.Begin(which,stage113_pc_before,
  stage113_pc_id_before,stage113_pc_if_before,stage113_rpc_before,stage113_pipe_before,
  instr,stage113_r13_before,stage113_pr_before);
"""
    body=body.replace(NYB2,hook,1)
    complete = PC_ADVANCE + r"""
 if(stage113_trace_step>=0)
  stage113_opcode_trace.Complete(which,stage113_trace_step,stage113_pipe_before,instr,
   PC,GetRegister(SH7095::GSREG_PC_ID,nullptr,0),GetRegister(SH7095::GSREG_PC_IF,nullptr,0),
   GetRegister(SH7095::GSREG_RPC,nullptr,0),GetRegister(SH7095::GSREG_R13,nullptr,0),
   GetRegister(SH7095::GSREG_PR,nullptr,0));
"""
    body=body.replace(PC_ADVANCE,complete,1)
    return source[:start]+IMPL+"\n"+body+source[end:]

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source",type=Path)
    args=ap.parse_args()
    if args.source.is_symlink() or not args.source.is_file():
        raise SystemExit("invalid_public_source_file")
    try:
        result=patch(args.source.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    args.source.write_text(result,encoding="utf-8")
    print("stage113_public_opcode_trace_source_patched")

if __name__=="__main__": main()
