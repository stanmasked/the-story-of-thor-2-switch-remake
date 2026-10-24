#!/usr/bin/env python3
"""Add a default-disabled private SH-2 code-window provenance observer.

This source-only patch reads a bounded 48-byte window from physical WorkRAMH
around each selected BSR/JSR/RTS PC_ID in Stage115's observed call window.
It never reads MMIO and contains no game-specific addresses or assets. Raw
windows are private evidence; public summaries must omit bytes and addresses.
"""
from __future__ import annotations
import argparse
from pathlib import Path

SIGNATURE = "STAGE116_SH2_CODE_WINDOW_PROVENANCE_V1"
OBJECT = "static Stage115ControlFlowWitness stage115_control_flow;"
PRE = "if(stage115_control_flow.enabled) stage115_control_flow.Before(CPU[0]);"
POST = "if(stage115_control_flow.enabled) stage115_control_flow.After(CPU[0]);"
CONFIG = "stage115_control_flow.Configure();"

CODE = r'''
// STAGE116_SH2_CODE_WINDOW_PROVENANCE_V1: opt-in private code-source evidence.
struct Stage116CodeWindowWitness
{
 bool configured=false, enabled=false, finished=false, pending_valid=false;
 unsigned long max_rows=4096, rows=0;
 struct Record
 {
  unsigned long relative_step=0, global_step=0;
  uint32 rpc=0, pc_id=0, pipe_id=0, pr=0, r13=0;
  uint32 post_pc_id=0, post_pipe_id=0, post_pr=0, post_r13=0;
  uint32 window_base=0;
  bool window_valid=false, selected_word_matches=false;
  char control[4]{};
  char window_hex[97]{};
 } pending;
 std::FILE* out=nullptr;
 static const unsigned long hard_max_rows=4096;

 static uint8 ByteAt(uint32 address)
 {
  return ne16_rbo_be<uint8>(WorkRAMH,address & 0xFFFFFU);
 }
 static bool NormalWindowAddress(uint32 pc_id)
 {
  return pc_id>=0x06000000U && pc_id<=0x060FFFFEU && !(pc_id&1U);
 }
 void Configure()
 {
  if(configured) return;
  configured=true;
  const char* yes=std::getenv("STAGE116_CODE_WINDOW_ENABLE");
  const char* dest=std::getenv("STAGE116_CODE_WINDOW_OUT");
  const char* cap=std::getenv("STAGE116_CODE_WINDOW_MAX_ROWS");
  if(!yes || std::strcmp(yes,"1") || !dest || !*dest || !stage115_control_flow.enabled) return;
  if(cap && *cap)
  {
   for(const char* p=cap;*p;p++) if(*p<'0'||*p>'9') return;
   char* end=nullptr; unsigned long n=std::strtoul(cap,&end,10);
   if(!end || *end || n<32 || n>hard_max_rows) return;
   max_rows=n;
  }
  out=std::fopen(dest,"wb");
  enabled=(out!=nullptr);
  if(enabled)
  {
   std::fprintf(out,"stage116_sh2_code_window_v1\n");
   std::fprintf(out,"kind,relative_step,global_step,control_kind,pre_rpc,pre_pc_id,pre_pipe_id,pre_pr,pre_r13,post_pc_id,post_pipe_id,post_pr,post_r13,window_base,window_valid,selected_word_matches,window_hex\n");
   std::fflush(out);
  }
 }
 void Before(SH7095& cpu)
 {
  if(!enabled || finished || !stage115_control_flow.active || !stage115_control_flow.pending_valid) return;
  const char* kind=stage115_control_flow.pending_control;
  if(!kind || !std::strcmp(kind,"none")) return;
  if(pending_valid) { Finish("incomplete"); return; }
  Record r;
  r.relative_step=(unsigned long)stage115_control_flow.pending.relative_step;
  r.global_step=stage115_control_flow.pending.global_step;
  r.rpc=cpu.GetRegister(SH7095::GSREG_RPC,nullptr,0);
  r.pc_id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
  r.pipe_id=cpu.GetRegister(SH7095::GSREG_PID,nullptr,0);
  r.pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
  r.r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
  std::strncpy(r.control,kind,sizeof(r.control)-1);
  if(NormalWindowAddress(r.pc_id))
  {
   uint32 base=(r.pc_id>=0x06000010U)?((r.pc_id-16U)&~0x0FU):0x06000000U;
   if(base>=0x06000000U && base+48U<=0x06100000U && r.pc_id>=base && r.pc_id+2U<=base+48U)
   {
    r.window_base=base;
    r.window_valid=true;
    for(unsigned i=0;i<48;i++) std::snprintf(r.window_hex+i*2,3,"%02x",ByteAt(base+i));
    const uint16 word=(uint16)(((uint16)ByteAt(r.pc_id)<<8)|(uint16)ByteAt(r.pc_id+1U));
    r.selected_word_matches=(word==(uint16)(r.pipe_id&0xFFFFU));
   }
  }
  pending=r;
  pending_valid=true;
 }
 void Finish(const char* marker)
 {
  if(out)
  {
   std::fprintf(out,"%s,%lu,%lu",marker,stage115_control_flow.completed,stage115_control_flow.global_step);
   for(unsigned i=0;i<14;i++) std::fputc(',',out);
   std::fputc('\n',out); std::fflush(out); std::fclose(out); out=nullptr;
  }
  enabled=false; finished=true; pending_valid=false;
 }
 void After(SH7095& cpu)
 {
  if(!enabled || finished || !pending_valid) return;
  pending.post_pc_id=cpu.GetRegister(SH7095::GSREG_PC_ID,nullptr,0);
  pending.post_pipe_id=cpu.GetRegister(SH7095::GSREG_PID,nullptr,0);
  pending.post_pr=cpu.GetRegister(SH7095::GSREG_PR,nullptr,0);
  pending.post_r13=cpu.GetRegister(SH7095::GSREG_R13,nullptr,0);
  if(rows>=max_rows) { Finish("event_cap"); return; }
  std::fprintf(out,"step,%lu,%lu,%s,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%u,%u,%s\n",
   pending.relative_step,pending.global_step,pending.control,pending.rpc,pending.pc_id,pending.pipe_id,
   pending.pr,pending.r13,pending.post_pc_id,pending.post_pipe_id,pending.post_pr,pending.post_r13,
   pending.window_base,pending.window_valid?1U:0U,pending.selected_word_matches?1U:0U,
   pending.window_valid?pending.window_hex:"");
  rows++; std::fflush(out); pending_valid=false;
  if(stage115_control_flow.finished)
  {
   if(stage115_control_flow.target_rts_seen && stage115_control_flow.target_return_remaining==0)
    Finish("complete");
   else Finish("incomplete");
  }
 }
};
static Stage116CodeWindowWitness stage116_code_window;
'''

def patch(source: str) -> str:
    if SIGNATURE in source:
        raise ValueError("already_patched_stage116")
    if source.count(OBJECT) != 1:
        raise ValueError("stage115_object_anchor_mismatch")
    if source.count(PRE) != 1 or source.count(POST) != 1:
        raise ValueError("stage115_hook_anchor_mismatch")
    if source.count(CONFIG) != 1:
        raise ValueError("stage115_config_anchor_mismatch")
    source = source.replace(OBJECT, OBJECT + "\n" + CODE, 1)
    source = source.replace(CONFIG, CONFIG + "\n    stage116_code_window.Configure();", 1)
    source = source.replace(PRE, PRE + "\n    if(stage116_code_window.enabled) stage116_code_window.Before(CPU[0]);", 1)
    source = source.replace(POST, POST + "\n    if(stage116_code_window.enabled) stage116_code_window.After(CPU[0]);", 1)
    # Stage115 is already responsible for selecting the debug runloop.
    return source

def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument("source",type=Path)
    p=ap.parse_args().source
    if p.is_symlink() or not p.is_file(): raise SystemExit("invalid_source_file")
    try: out=patch(p.read_text(encoding="utf-8"))
    except ValueError as exc: raise SystemExit(str(exc)) from None
    p.write_text(out,encoding="utf-8")
    print("stage116_public_code_window_patch_applied")
    return 0
if __name__ == "__main__": raise SystemExit(main())
