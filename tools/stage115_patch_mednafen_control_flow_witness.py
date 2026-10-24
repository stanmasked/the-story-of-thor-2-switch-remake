#!/usr/bin/env python3
"""Add a default-disabled, bounded SH-2 BSR/JSR/RTS + R13 event observer to public Mednafen source.

The patcher embeds no game, BIOS, ROM addresses, private trace values or assets.
Runtime trigger and output path are supplied only by the private runner through
environment variables. The observer only reads CPU/pipeline registers.
"""
from __future__ import annotations
import argparse
import re
from pathlib import Path

SIGNATURE = "STAGE115_SH2_CONTROL_FLOW_WITNESS_V1"
OBJECT = "static Stage114ReturnWindow stage114_return_window;"
PRE = "if(stage114_return_window.enabled) stage114_return_window.Before(CPU[0]);"
POST = "if(stage114_return_window.enabled) stage114_return_window.After(CPU[0]);"
RUNLOOP = re.compile(
    r"(?P<indent>[ \t]*)stage112_monitor\.Configure\(\);[ \t]*\n"
    r"[ \t]*stage113_opcode\.Configure\(\);[ \t]*\n"
    r"[ \t]*stage114_return_window\.Configure\(\);[ \t]*\n"
    r"[ \t]*if\(stage114_return_window\.force_debug_mode\)[ \t]*\n"
    r"[ \t]*end_ts = NeedEmuICache \? RunLoop_Debug<true>\(espec\) : RunLoop_Debug<false>\(espec\);[ \t]*\n"
    r"[ \t]*else[ \t]*\n"
    r"[ \t]*end_ts = rltab\[NeedEmuICache\]\[DBG_NeedCPUHooks\(\)\]\(espec\);"
)

CODE = r"""
// STAGE115_SH2_CONTROL_FLOW_WITNESS_V1: default-disabled, bounded, read-only observer.
struct Stage115Record
{
 long relative_step=0;
 unsigned long global_step=0;
 uint32 pc=0, pc_id=0, pc_if=0, pipe_id=0, pipe_if=0, pr=0, r13=0, r15=0;
};
struct Stage115ControlFlowWitness
{
 bool configured=false, enabled=false, force_debug_mode=false;
 bool active=false, finished=false, pending_valid=false;
 bool target_bsr_seen=false, target_rts_seen=false;
 bool pending_target_bsr=false, pending_target_rts=false;
 uint32 trigger=0, expected_return=0;
 unsigned long max_steps=350000, max_rows=16384, global_step=0, completed=0, rows=0;
 unsigned long follow_remaining=0, target_return_remaining=0;
 const char* pending_control="none";
 Stage115Record pending{};
 std::FILE* out=nullptr;
 static const unsigned long hard_max_rows=16384;

 static bool NormalBSR(uint32 pid)
 {
  return (((pid >> 24) & 0xffU) == 0x6aU) && (((pid & 0xffffU) & 0xf000U) == 0xb000U);
 }
 static bool NormalJSR(uint32 pid)
 {
  return (((pid >> 24) & 0xffU) == 0x6dU) && (((pid & 0xffffU) & 0xf0ffU) == 0x400bU);
 }
 static bool NormalRTS(uint32 pid)
 {
  return (((pid >> 24) & 0xffU) == 0x6eU) && ((pid & 0xffffU) == 0x000bU);
 }
 void Configure()
 {
  if(configured) return;
  configured=true;
  const char* yes=std::getenv("STAGE115_CONTROL_FLOW_ENABLE");
  const char* dest=std::getenv("STAGE115_CONTROL_FLOW_OUT");
  const char* trig=std::getenv("STAGE115_CONTROL_FLOW_PC");
  const char* steps=std::getenv("STAGE115_CONTROL_FLOW_MAX_STEPS");
  const char* row_cap=std::getenv("STAGE115_CONTROL_FLOW_MAX_ROWS");
  if(!yes || std::strcmp(yes,"1") || !dest || !*dest || !trig ||
     !stage114_return_window.enabled || !stage113_opcode.enabled) return;
  char* end=nullptr;
  unsigned long parsed_trigger=std::strtoul(trig,&end,16);
  if(!end || *end) return;
  trigger=(uint32)parsed_trigger;
  if(steps && *steps)
  {
   end=nullptr;
   unsigned long parsed_steps=std::strtoul(steps,&end,10);
   if(!end || *end) return;
   max_steps=parsed_steps;
  }
  if(row_cap && *row_cap)
  {
   end=nullptr;
   unsigned long parsed_rows=std::strtoul(row_cap,&end,10);
   if(!end || *end) return;
   max_rows=parsed_rows;
  }
  if(trigger==0 || (trigger & 1U) || max_steps<1024 || max_steps>2000000 ||
     max_rows<128 || max_rows>hard_max_rows ||
     stage114_return_window.trigger!=trigger || stage113_opcode.trigger!=trigger) return;
  out=std::fopen(dest,"wb");
  if(!out) return;
  enabled=true;
  force_debug_mode=true;
  std::fprintf(out,"stage115_sh2_control_flow_v1\n");
  std::fprintf(out,"kind,relative_step,global_step,pre_rpc,pre_pc_id,pre_pc_if,pre_pipe_id,pre_pipe_if,pre_pr,pre_r13,pre_r15,post_rpc,post_pc_id,post_pc_if,post_pipe_id,post_pipe_if,post_pr,post_r13,post_r15,control_kind,r13_changed,target_bsr,target_rts_candidate\n");
  std::fflush(out);
 }
 Stage115Record Capture(SH7095& cpu) const
 {
  Stage115Record r;
  r.global_step=global_step;
  r.pc=cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0);
  r.pc_id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
  r.pc_if=cpu.GetRegister(SH7095::GSREG_PC_IF,nullptr,0);
  r.pipe_id=cpu.GetRegister(SH7095::GSREG_PID,nullptr,0);
  r.pipe_if=cpu.GetRegister(SH7095::GSREG_PIF,nullptr,0);
  r.pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
  r.r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
  r.r15=cpu.GetRegister(SH7095::GSREG_R15,nullptr,0);
  return r;
 }
 void WritePair(const Stage115Record& pre, const Stage115Record& post,
                const char* control, const bool r13_changed,
                const bool bsr, const bool rts)
 {
  if(!out || rows>=max_rows) return;
  std::fprintf(out,"step,%ld,%lu,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%s,%u,%u,%u\n",
   pre.relative_step,pre.global_step,pre.pc,pre.pc_id,pre.pc_if,pre.pipe_id,pre.pipe_if,
   pre.pr,pre.r13,pre.r15,post.pc,post.pc_id,post.pc_if,post.pipe_id,post.pipe_if,
   post.pr,post.r13,post.r15,control,r13_changed ? 1U : 0U,
   bsr ? 1U : 0U,rts ? 1U : 0U);
  rows++;
  std::fflush(out);
 }
 void Finish(const char* marker)
 {
  if(out)
  {
   std::fprintf(out,"%s,%lu,%lu",marker,completed,global_step);
   for(unsigned i=0;i<20;i++) std::fputc(',',out);
   std::fputc('\n',out);
   std::fflush(out);
   std::fclose(out);
   out=nullptr;
  }
  enabled=false;
  finished=true;
 }
 void Before(SH7095& cpu)
 {
  if(!enabled || finished) return;
  global_step++;
  Stage115Record r=Capture(cpu);
  r.global_step=global_step;
  if(!active)
  {
   if(r.pc!=trigger) return;
   active=true;
   r.relative_step=1;
   pending=r;
   pending_valid=true;
   pending_control="none";
   pending_target_bsr=false;
   pending_target_rts=false;
   return;
  }
  if(completed>=max_steps) { Finish("step_limit"); return; }
  r.relative_step=(long)(completed+1);
  pending=r;
  pending_valid=true;
  pending_control="none";
  pending_target_bsr=false;
  pending_target_rts=false;
  if(NormalBSR(r.pipe_id)) pending_control="bsr";
  else if(NormalJSR(r.pipe_id)) pending_control="jsr";
  else if(NormalRTS(r.pipe_id)) pending_control="rts";
  pending_target_bsr=(!target_bsr_seen && r.pc==trigger+4U && NormalBSR(r.pipe_id));
  pending_target_rts=(target_bsr_seen && !target_rts_seen &&
                      NormalRTS(r.pipe_id) && r.pr==expected_return);
 }
 void After(SH7095& cpu)
 {
  if(!enabled || !active || !pending_valid || finished) return;
  Stage115Record post=Capture(cpu);
  post.global_step=pending.global_step;
  post.relative_step=pending.relative_step;
  completed=(unsigned long)pending.relative_step;
  const bool r13_changed=(pending.r13!=post.r13);
  const bool log_this=(completed<=32 || std::strcmp(pending_control,"none") ||
                       r13_changed || follow_remaining>0 ||
                       pending_target_bsr || pending_target_rts);
  if(log_this) WritePair(pending,post,pending_control,r13_changed,
                         pending_target_bsr,pending_target_rts);
  if(pending_target_bsr && !target_bsr_seen)
  {
   target_bsr_seen=true;
   expected_return=post.pr;
  }
  if(pending_target_rts && !target_rts_seen)
  {
   target_rts_seen=true;
   target_return_remaining=2;
  }
  if(std::strcmp(pending_control,"none")) follow_remaining=2;
  else if(follow_remaining>0) follow_remaining--;
  pending_valid=false;
  if(target_rts_seen && target_return_remaining>0 && !pending_target_rts)
  {
   target_return_remaining--;
   if(target_return_remaining==0) { Finish("complete"); return; }
  }
  if(rows>=max_rows) { Finish("event_cap"); return; }
  if(completed>=max_steps) { Finish("step_limit"); return; }
 }
};
static Stage115ControlFlowWitness stage115_control_flow;
"""

def patch(source: str) -> str:
    if SIGNATURE in source:
        raise ValueError("already_patched_stage115")
    if source.count(OBJECT) != 1:
        raise ValueError("stage114_object_anchor_mismatch")
    if source.count(PRE) != 1 or source.count(POST) != 1:
        raise ValueError("stage114_step_hook_anchor_mismatch")
    matches=list(RUNLOOP.finditer(source))
    if len(matches)!=1:
        raise ValueError("runloop_selection_anchor_mismatch")
    source=source.replace(OBJECT,OBJECT+"\n"+CODE,1)
    source=source.replace(PRE,PRE+"\n    if(stage115_control_flow.enabled) stage115_control_flow.Before(CPU[0]);",1)
    source=source.replace(POST,POST+"\n    if(stage115_control_flow.enabled) stage115_control_flow.After(CPU[0]);",1)
    m=RUNLOOP.search(source)
    if not m:
        raise ValueError("runloop_selection_anchor_mismatch_after_hooks")
    i=m.group("indent")
    replacement=(
      i+"stage112_monitor.Configure();\n"
      +i+"stage113_opcode.Configure();\n"
      +i+"stage114_return_window.Configure();\n"
      +i+"stage115_control_flow.Configure();\n"
      +i+"if(stage114_return_window.force_debug_mode || stage115_control_flow.force_debug_mode)\n"
      +i+"  end_ts = NeedEmuICache ? RunLoop_Debug<true>(espec) : RunLoop_Debug<false>(espec);\n"
      +i+"else\n"
      +i+"  end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);"
    )
    source=source[:m.start()]+replacement+source[m.end():]
    return source

def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source",type=Path)
    p=ap.parse_args().source
    if p.is_symlink() or not p.is_file():
        raise SystemExit("invalid_source_file")
    try: result=patch(p.read_text(encoding="utf-8"))
    except ValueError as exc: raise SystemExit(str(exc)) from None
    p.write_text(result,encoding="utf-8")
    print("stage115_public_control_flow_patch_applied")
    return 0
if __name__=="__main__": raise SystemExit(main())
