#!/usr/bin/env python3
"""Add a default-disabled SH-2 opcode/return-window recorder to public Mednafen.

This patch contains no game-specific addresses, ROM, BIOS, or private traces.
Raw opcode/register/memory evidence is emitted only by an explicitly enabled
private runtime and must stay in owner-only storage. RPC==PR remains a candidate.
"""
from __future__ import annotations
import argparse
from pathlib import Path

SIGNATURE = "/* STAGE113_PUBLIC_SH2_OPCODE_WINDOW_V1 */"
STAGE112_OBJECT = "static Stage112Monitor stage112_monitor;"
PRE = "if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],true);"
POST = "if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],false);"
RUNLOOP = "end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);"

IMPL = r'''/* STAGE113_PUBLIC_SH2_OPCODE_WINDOW_V1 */
// Runtime-only instruction witness. DebugMode is forced only when explicitly
// enabled so PC_ID/PC_IF are populated; ordinary execution remains unchanged.
// The raw output is private. This records pipeline state, not a hardware trace.
struct Stage113OpcodeRecord
{
 unsigned long global_step = 0;
 long relative_step = -1;
 uint32 pc = 0, pc_id = 0, pc_if = 0, pipe_id = 0, pipe_if = 0;
 uint32 r3 = 0, r13 = 0, r15 = 0, pr = 0, sr = 0;
 unsigned byte = 0;
};
struct Stage113OpcodeWindow
{
 bool configured = false, enabled = false, force_debug_mode = false;
 bool triggered = false, pending_valid = false, byte_seen = false, candidate_seen = false;
 bool finished = false;
 uint32 trigger = 0, target = 0;
 unsigned long max_steps = 2000000, global_step = 0, completed = 0;
 unsigned long log_until = 0, rows = 0, last_logged_step = 0;
 unsigned ring_next = 0, ring_count = 0;
 Stage113OpcodeRecord ring[96]{};
 Stage113OpcodeRecord pending{};
 std::FILE* log = nullptr;

 void Configure()
 {
  if(configured) return;
  configured = true;
  const char* yes = std::getenv("STAGE113_OPCODE_WITNESS_ENABLE");
  const char* out = std::getenv("STAGE113_OPCODE_WITNESS_OUT");
  if(!yes || std::strcmp(yes,"1") || !out || !*out || !stage112_monitor.enabled) return;
  trigger = stage112_monitor.trigger;
  target = stage112_monitor.target;
  max_steps = stage112_monitor.max_steps;
  if(target < 0x06000000U || target >= 0x08000000U || max_steps < 1024 || max_steps > 2000000) return;
  log = std::fopen(out,"wb");
  if(!log) return;
  enabled = true;
  force_debug_mode = true;
  std::fprintf(log,"stage113_opcode_witness_v1\n");
  std::fprintf(log,"kind,relative_step,global_step,pre_pc,pre_pc_id,pre_pc_if,pre_pipe_id,pre_pipe_if,pre_r3,pre_r13,pre_r15,pre_pr,pre_sr,pre_byte,post_pc,post_pc_id,post_pc_if,post_pipe_id,post_pipe_if,post_r3,post_r13,post_r15,post_pr,post_sr,post_byte,byte_changed,rpc_equals_pr_candidate\n");
  std::fflush(log);
 }

 Stage113OpcodeRecord Capture(SH7095& cpu) const
 {
  Stage113OpcodeRecord r;
  r.global_step = global_step;
  r.pc = cpu.PC;
  r.pc_id = cpu.PC_ID;
  r.pc_if = cpu.PC_IF;
  r.pipe_id = cpu.Pipe_ID;
  r.pipe_if = cpu.Pipe_IF;
  r.r3 = cpu.R[3];
  r.r13 = cpu.R[13];
  r.r15 = cpu.R[15];
  r.pr = cpu.PR;
  r.sr = cpu.SR;
  r.byte = stage112_monitor.ByteAtTarget();
  return r;
 }

 void PushRing(const Stage113OpcodeRecord& r)
 {
  ring[ring_next] = r;
  ring_next = (ring_next + 1) % 96;
  if(ring_count < 96) ring_count++;
 }

 const Stage113OpcodeRecord& RingAt(const unsigned i) const
 {
  return ring[(ring_next + 96 - ring_count + i) % 96];
 }

 void WriteContext(Stage113OpcodeRecord r, const long override_step = 0, const bool override = false)
 {
  if(!log || rows >= 1024) return;
  if(override) r.relative_step = override_step;
  std::fprintf(log,"context,%ld,%lu,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%02x,,,,,,,,,,,,0,0\n",
   r.relative_step,r.global_step,r.pc,r.pc_id,r.pc_if,r.pipe_id,r.pipe_if,r.r3,r.r13,r.r15,r.pr,r.sr,r.byte);
  rows++;
  if(r.relative_step > last_logged_step) last_logged_step = (unsigned long)r.relative_step;
 }

 void WritePair(const unsigned long step, const Stage113OpcodeRecord& pre, const Stage113OpcodeRecord& post,
                const bool byte_changed, const bool candidate)
 {
  if(!log || rows >= 1024 || step <= last_logged_step) return;
  std::fprintf(log,"step,%lu,%lu,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%02x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%02x,%u,%u\n",
   step,pre.global_step,pre.pc,pre.pc_id,pre.pc_if,pre.pipe_id,pre.pipe_if,pre.r3,pre.r13,pre.r15,pre.pr,pre.sr,pre.byte,
   post.pc,post.pc_id,post.pc_if,post.pipe_id,post.pipe_if,post.r3,post.r13,post.r15,post.pr,post.sr,post.byte,
   byte_changed ? 1U : 0U,candidate ? 1U : 0U);
  rows++;
  last_logged_step = step;
  std::fflush(log);
 }

 void DumpPreTriggerRing()
 {
  for(unsigned i=0;i<ring_count;i++)
   WriteContext(RingAt(i),(long)i-(long)ring_count,true);
 }

 void DumpRecentRing()
 {
  for(unsigned i=0;i<ring_count;i++)
  {
   const Stage113OpcodeRecord& r = RingAt(i);
   if(r.relative_step > (long)last_logged_step && r.relative_step < (long)pending.relative_step)
    WriteContext(r);
  }
 }

 void Finish()
 {
  if(log) { std::fflush(log); std::fclose(log); log = nullptr; }
  enabled = false;
  finished = true;
 }

 void Before(SH7095& cpu)
 {
  if(!enabled || finished) return;
  global_step++;
  pending = Capture(cpu);
  pending.global_step = global_step;
  if(!triggered)
  {
   // DebugMode is explicitly enabled for this run, so PC_ID is the decoded
   // instruction address associated with Pipe_ID; do not trigger on RPC alone.
   if(pending.pc_id != trigger) { PushRing(pending); return; }
   triggered = true;
   completed = 0;
   pending.relative_step = 1;
   DumpPreTriggerRing();
   log_until = 256;
   pending_valid = true;
   return;
  }
  pending.relative_step = (long)(completed + 1);
  pending_valid = true;
 }

 void After(SH7095& cpu)
 {
  if(!enabled || !triggered || !pending_valid || finished) return;
  Stage113OpcodeRecord post = Capture(cpu);
  post.global_step = pending.global_step;
  post.relative_step = pending.relative_step;
  completed = (unsigned long)pending.relative_step;
  const bool byte_changed = pending.byte != post.byte;
  const bool byte_event = byte_changed && !byte_seen;
  const bool rpc_pr_equal = post.pc != 0 && post.pr != 0 && post.pc == post.pr;
  const bool candidate = rpc_pr_equal && !candidate_seen;
  if((byte_event || candidate) && completed > log_until)
  {
   DumpRecentRing();
   if(completed + 64 > log_until) log_until = completed + 64;
  }
  if(completed <= log_until || byte_event || candidate)
   WritePair(completed,pending,post,byte_event,candidate);
  PushRing(pending);
  pending_valid = false;
  if(byte_event) byte_seen = true;
  if(candidate) candidate_seen = true;
  if(completed >= max_steps || (candidate_seen && completed >= log_until)) Finish();
 }
};
static Stage113OpcodeWindow stage113_opcode_window;
'''

def patch(source: str) -> str:
    if SIGNATURE in source:
        raise ValueError("already_patched_stage113")
    if source.count(STAGE112_OBJECT) != 1:
        raise ValueError("stage112_object_anchor_mismatch")
    if source.count(PRE) != 1 or source.count(POST) != 1:
        raise ValueError("stage112_step_hook_anchor_mismatch")
    if source.count(RUNLOOP) != 1:
        raise ValueError("runloop_selection_anchor_mismatch")
    source = source.replace(STAGE112_OBJECT, STAGE112_OBJECT + "\n" + IMPL, 1)
    source = source.replace(PRE, PRE + "\n    if(stage113_opcode_window.enabled) stage113_opcode_window.Before(CPU[0]);", 1)
    source = source.replace(POST, POST + "\n    if(stage113_opcode_window.enabled) stage113_opcode_window.After(CPU[0]);", 1)
    replacement = (
        "stage112_monitor.Configure();\n"
        " stage113_opcode_window.Configure();\n"
        " if(stage113_opcode_window.force_debug_mode)\n"
        "  end_ts = NeedEmuICache ? RunLoop_Debug<true>(espec) : RunLoop_Debug<false>(espec);\n"
        " else\n"
        "  end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);"
    )
    source = source.replace(RUNLOOP, replacement, 1)
    return source


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file", type=Path)
    p = ap.parse_args().file
    if p.is_symlink() or not p.is_file():
        raise SystemExit("invalid_source_file")
    try:
        patched = patch(p.read_text(encoding="utf-8"))
    except ValueError as e:
        raise SystemExit(str(e)) from None
    p.write_text(patched, encoding="utf-8")
    print("stage113_public_opcode_witness_patched")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())