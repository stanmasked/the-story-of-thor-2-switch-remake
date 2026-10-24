#!/usr/bin/env python3
"""Add a default-disabled bounded SH-2 return-site window to public Mednafen.

The observer uses the public interpreter's selected Pipe_ID and debug pipeline
fields only when explicitly enabled. It contains no game-specific addresses,
ROM, BIOS, or private traces. All raw runtime output is private.
"""
from __future__ import annotations
import argparse
from pathlib import Path

SIGNATURE = "/* STAGE114_SH2_RETURN_SITE_WINDOW_V1 */"
OBJECT = "static Stage113OpcodeWitness stage113_opcode;"
INSERT_AFTER = "static Stage112Monitor stage112_monitor;"
PRE = "if(stage113_opcode.enabled) stage113_opcode.Before(CPU[0]);"
POST = "if(stage113_opcode.enabled) stage113_opcode.After(CPU[0]);"
RUNLOOP = "end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);"

CODE = r'''
/* STAGE114_SH2_RETURN_SITE_WINDOW_V1 */
// Capture a bounded instruction window around a private BSR, its MOV.B delay
// slot, a matching normal RTS, the RTS delay slot, and the return-site opcode.
// PC_ID/PC_IF are meaningful because this opt-in mode selects RunLoop_Debug.
struct Stage114Record
{
 unsigned long global_step = 0;
 long relative_step = 0;
 uint32 pc = 0, pc_id = 0, pc_if = 0, pipe_id = 0, pipe_if = 0;
 uint32 r3 = 0, r13 = 0, r15 = 0, pr = 0, sr = 0;
 unsigned byte = 0;
};
struct Stage114ReturnWindow
{
 bool configured=false, enabled=false, force_debug_mode=false;
 bool triggered=false, pending_valid=false, target_bsr_seen=false;
 bool target_rts_seen=false, finished=false;
 bool pending_target_bsr=false, pending_target_rts=false;
 uint32 trigger=0, target=0, expected_return=0;
 unsigned long max_steps=350000, global_step=0, completed=0, rows=0;
 unsigned long target_bsr_step=0, target_rts_step=0, follow_remaining=0;
 Stage114Record pending{};
 std::FILE* out=nullptr;
 static const unsigned long max_rows=512;

 static bool NormalBSR(uint32 pid)
 {
  return (((pid >> 24) & 0xffU) == 0x6aU) && (((pid & 0xffffU) & 0xf000U) == 0xb000U);
 }
 static bool NormalRTS(uint32 pid)
 {
  return (((pid >> 24) & 0xffU) == 0x6eU) && ((pid & 0xffffU) == 0x000bU);
 }
 void Configure()
 {
  if(configured) return;
  configured=true;
  const char* yes=std::getenv("STAGE114_RETURN_WINDOW_ENABLE");
  const char* dest=std::getenv("STAGE114_RETURN_WINDOW_OUT");
  const char* trig=std::getenv("STAGE114_RETURN_WINDOW_PC");
  const char* ram=std::getenv("STAGE114_RETURN_WINDOW_RAM_POINTER");
  const char* steps=std::getenv("STAGE114_RETURN_WINDOW_MAX_STEPS");
  if(!yes || std::strcmp(yes,"1") || !dest || !*dest ||
     !trig || !ram || !stage113_opcode.enabled) return;
  char* end=nullptr;
  unsigned long parsed_trigger=std::strtoul(trig,&end,16);
  if(!end || *end) return;
  end=nullptr;
  unsigned long parsed_target=std::strtoul(ram,&end,16);
  if(!end || *end) return;
  trigger=(uint32)parsed_trigger;
  target=(uint32)parsed_target;
  if(steps && *steps)
  {
   end=nullptr;
   unsigned long parsed_steps=std::strtoul(steps,&end,10);
   if(!end || *end) return;
   max_steps=parsed_steps;
  }
  if(trigger==0 || target<0x06000000U || target>=0x08000000U ||
     max_steps<1024 || max_steps>2000000 ||
     stage113_opcode.trigger!=trigger) return;
  out=std::fopen(dest,"wb");
  if(!out) return;
  enabled=true;
  force_debug_mode=true;
  std::fprintf(out,"stage114_return_window_v1\n");
  std::fprintf(out,"kind,relative_step,global_step,pre_pc,pre_pc_id,pre_pc_if,pre_pipe_id,pre_pipe_if,pre_r3,pre_r13,pre_r15,pre_pr,pre_sr,pre_byte,post_pc,post_pc_id,post_pc_if,post_pipe_id,post_pipe_if,post_r3,post_r13,post_r15,post_pr,post_sr,post_byte,byte_changed,target_bsr,target_rts_candidate\n");
  std::fflush(out);
 }
 Stage114Record Capture(SH7095& cpu) const
 {
  Stage114Record r;
  r.global_step=global_step;
  r.pc=cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0);
  r.pc_id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
  r.pc_if=cpu.GetRegister(SH7095::GSREG_PC_IF,nullptr,0);
  r.pipe_id=cpu.GetRegister(SH7095::GSREG_PID,nullptr,0);
  r.pipe_if=cpu.GetRegister(SH7095::GSREG_PIF,nullptr,0);
  r.r3=cpu.GetRegister(SH7095::GSREG_R3,nullptr,0);
  r.r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
  r.r15=cpu.GetRegister(SH7095::GSREG_R15,nullptr,0);
  r.pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
  r.sr=cpu.GetRegister(SH7095::GSREG_SR,nullptr,0);
  r.byte=ne16_rbo_be<uint8>(WorkRAMH,target & 0xfffffU);
  return r;
 }
 void WritePair(const Stage114Record& pre, const Stage114Record& post,
                const bool byte_changed, const bool bsr, const bool rts)
 {
  if(!out || rows>=max_rows) return;
  std::fprintf(out,"step,%ld,%lu,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%02x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%02x,%u,%u,%u\n",
   pre.relative_step,pre.global_step,pre.pc,pre.pc_id,pre.pc_if,pre.pipe_id,pre.pipe_if,
   pre.r3,pre.r13,pre.r15,pre.pr,pre.sr,pre.byte,
   post.pc,post.pc_id,post.pc_if,post.pipe_id,post.pipe_if,
   post.r3,post.r13,post.r15,post.pr,post.sr,post.byte,
   byte_changed ? 1U : 0U,bsr ? 1U : 0U,rts ? 1U : 0U);
  rows++;
  std::fflush(out);
 }
 void Finish(const char* marker)
 {
  if(out)
  {
   std::fprintf(out,"%s,%lu,%lu",marker,completed,global_step);
   // The remaining 25 columns are empty except for the three trailing flags.
   for(unsigned i=0;i<25;i++) std::fputc(',',out);
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
  Stage114Record r=Capture(cpu);
  r.global_step=global_step;
  if(!triggered)
  {
   // RPC is the fetch/pipeline PC. Start there; the target BSR enters Pipe_ID
   // two instruction steps later. The private runner supplies the BSR address.
   if(r.pc!=trigger) return;
   triggered=true;
   r.relative_step=1;
   pending=r;
   pending_valid=true;
   pending_target_bsr=false;
   pending_target_rts=false;
   return;
  }
  r.relative_step=(long)(completed+1);
  pending=r;
  pending_valid=true;
  pending_target_bsr=(!target_bsr_seen && r.pc==trigger+4U && NormalBSR(r.pipe_id));
  pending_target_rts=(target_bsr_seen && !target_rts_seen &&
                      NormalRTS(r.pipe_id) && r.pr==expected_return);
 }
 void After(SH7095& cpu)
 {
  if(!enabled || !triggered || !pending_valid || finished) return;
  Stage114Record post=Capture(cpu);
  post.global_step=pending.global_step;
  post.relative_step=pending.relative_step;
  completed=(unsigned long)pending.relative_step;
  const bool byte_changed=(pending.byte!=post.byte);
  const bool log_this=(completed<=32 || byte_changed ||
                       pending_target_bsr || pending_target_rts ||
                       pending.r13!=post.r13 || follow_remaining>0);
  if(log_this) WritePair(pending,post,byte_changed,pending_target_bsr,pending_target_rts);
  if(pending_target_bsr && !target_bsr_seen)
  {
   target_bsr_seen=true;
   target_bsr_step=completed;
   expected_return=post.pr;
  }
  if(pending_target_rts && !target_rts_seen)
  {
   target_rts_seen=true;
   target_rts_step=completed;
   follow_remaining=4;
  }
  else if(follow_remaining>0)
   follow_remaining--;
  pending_valid=false;
  if(rows>=max_rows) { Finish("event_cap"); return; }
  if(target_rts_seen && follow_remaining==0) { Finish("complete"); return; }
  if(completed>=max_steps) { Finish("step_limit"); return; }
 }
};
static Stage114ReturnWindow stage114_return_window;
'''

def patch(text: str) -> str:
    if SIGNATURE in text:
        raise ValueError("already_patched_stage114")
    if text.count(OBJECT) != 1:
        raise ValueError("stage113_object_anchor_mismatch")
    if text.count(INSERT_AFTER) != 1:
        raise ValueError("stage112_object_anchor_mismatch")
    if text.count(PRE) != 1 or text.count(POST) != 1:
        raise ValueError("stage113_step_hook_anchor_mismatch")
    if text.count(RUNLOOP) != 1:
        raise ValueError("runloop_selection_anchor_mismatch")
    text=text.replace(INSERT_AFTER,INSERT_AFTER+"\n"+CODE,1)
    text=text.replace(PRE,PRE+"\n    if(stage114_return_window.enabled) stage114_return_window.Before(CPU[0]);",1)
    text=text.replace(POST,POST+"\n    if(stage114_return_window.enabled) stage114_return_window.After(CPU[0]);",1)
    replacement=(
      "stage112_monitor.Configure();\n"
      " stage113_opcode.Configure();\n"
      " stage114_return_window.Configure();\n"
      " if(stage114_return_window.force_debug_mode)\n"
      "  end_ts = NeedEmuICache ? RunLoop_Debug<true>(espec) : RunLoop_Debug<false>(espec);\n"
      " else\n"
      "  end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);"
    )
    text=text.replace(RUNLOOP,replacement,1)
    return text

def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source",type=Path)
    p=ap.parse_args().source
    if p.is_symlink() or not p.is_file():
        raise SystemExit("invalid_source_file")
    try: result=patch(p.read_text(encoding="utf-8"))
    except ValueError as exc: raise SystemExit(str(exc)) from None
    p.write_text(result,encoding="utf-8")
    print("stage114_public_return_window_patch_applied")
    return 0
if __name__=="__main__": raise SystemExit(main())
