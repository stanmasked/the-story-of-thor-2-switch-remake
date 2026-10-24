#!/usr/bin/env python3
"""Fail-closed validator for private Stage115 SH-2 control-flow traces.

Only safe counters and booleans are emitted. Raw PCs, opcodes, registers, RAM,
source bytes and filenames are never included in stdout or the aggregate JSON.
"""
from __future__ import annotations
import argparse, csv, json
from collections import Counter
from pathlib import Path

MAGIC = ["stage115_sh2_control_flow_v1"]
HEADER = ["kind","relative_step","global_step","pre_rpc","pre_pc_id","pre_pc_if","pre_pipe_id","pre_pipe_if","pre_pr","pre_r13","pre_r15","post_rpc","post_pc_id","post_pc_if","post_pipe_id","post_pipe_if","post_pr","post_r13","post_r15","control_kind","r13_changed","target_bsr","target_rts_candidate"]
HEX_FIELDS = HEADER[3:19]
class AuditError(ValueError): pass

def hx(s):
    if len(s)!=8 or any(c not in "0123456789abcdefABCDEF" for c in s):
        raise AuditError("invalid_hex_field")
    return int(s,16)

def is_bsr(pid):
    return ((pid>>24)&0xff)==0x6a and ((pid&0xffff)&0xf000)==0xb000
def is_jsr(pid):
    return ((pid>>24)&0xff)==0x6d and ((pid&0xffff)&0xf0ff)==0x400b
def is_rts(pid):
    return ((pid>>24)&0xff)==0x6e and (pid&0xffff)==0x000b

def audit(path: Path):
    try:
        with path.open(encoding="ascii",newline="") as f:
            rd=csv.reader(f)
            if next(rd,None)!=MAGIC: raise AuditError("bad_magic")
            if next(rd,None)!=HEADER: raise AuditError("bad_header")
            rows=[]; terminal=None; last_step=0; last_global=0
            for raw in rd:
                if terminal is not None: raise AuditError("row_after_terminal")
                if len(raw)!=len(HEADER): raise AuditError("wrong_column_count")
                d=dict(zip(HEADER,raw))
                if d["kind"] in ("complete","step_limit","event_cap"):
                    terminal=d["kind"]
                    if not d["relative_step"].isdecimal() or not d["global_step"].isdecimal(): raise AuditError("bad_terminal_step")
                    terminal_step=int(d["relative_step"]); terminal_global=int(d["global_step"])
                    if terminal_step<last_step or terminal_global<last_global: raise AuditError("terminal_before_last_step")
                    if terminal_step>2000000 or terminal_global>10000000000: raise AuditError("terminal_step_limit_exceeded")
                    if any(d[k] for k in HEADER[3:]): raise AuditError("terminal_payload")
                    continue
                if d["kind"]!="step": raise AuditError("bad_row_kind")
                if not d["relative_step"].isdecimal() or not d["global_step"].isdecimal(): raise AuditError("bad_step")
                step=int(d["relative_step"]); glob=int(d["global_step"])
                if step<=last_step or glob<=last_global: raise AuditError("nonmonotonic_steps")
                if step>2000000 or glob>10000000000: raise AuditError("step_limit_exceeded")
                last_step,last_global=step,glob
                for k in HEX_FIELDS: hx(d[k])
                if d["control_kind"] not in ("none","bsr","jsr","rts"): raise AuditError("bad_control_kind")
                for k in ("r13_changed","target_bsr","target_rts_candidate"):
                    if d[k] not in ("0","1"): raise AuditError("bad_flag")
                pre_r13=hx(d["pre_r13"]); post_r13=hx(d["post_r13"])
                if (pre_r13!=post_r13)!=(d["r13_changed"]=="1"): raise AuditError("r13_flag_mismatch")
                pre_pid=hx(d["pre_pipe_id"]); post_pid=hx(d["post_pipe_id"])
                ctl=d["control_kind"]
                if ctl=="bsr" and not is_bsr(pre_pid): raise AuditError("bsr_selector_mismatch")
                if ctl=="jsr" and not is_jsr(pre_pid): raise AuditError("jsr_selector_mismatch")
                if ctl=="rts" and not is_rts(pre_pid): raise AuditError("rts_selector_mismatch")
                if d["target_bsr"]=="1" and ctl!="bsr": raise AuditError("target_bsr_flag_mismatch")
                if d["target_rts_candidate"]=="1" and ctl!="rts": raise AuditError("target_rts_flag_mismatch")
                rows.append(d)
    except (OSError,UnicodeError,csv.Error) as e:
        raise AuditError("unreadable_trace") from None
    if terminal!="complete": raise AuditError("capture_incomplete")
    if not rows or len(rows)>16384: raise AuditError("row_limit")
    by_step={int(x["relative_step"]):x for x in rows}
    controls=[x for x in rows if x["control_kind"]!="none"]
    counts=Counter(x["control_kind"] for x in controls)
    pipeline_windows=0
    for c in controls:
        s=int(c["relative_step"])
        delay=by_step.get(s+1); nxt=by_step.get(s+2)
        if delay is None or nxt is None: raise AuditError("missing_control_window")
        if delay["control_kind"]!="none": raise AuditError("control_in_delay_slot")
        if hx(c["post_pipe_id"])!=hx(delay["pre_pipe_id"]): raise AuditError("delay_slot_pipeline_mismatch")
        if ((hx(delay["pre_pipe_id"])>>24)&0x80)==0: raise AuditError("delay_slot_not_marked")
        if ((hx(delay["post_pipe_id"])>>24)&0x80)!=0: raise AuditError("delay_slot_post_marker")
        if hx(nxt["pre_pipe_id"])!=hx(delay["post_pipe_id"]): raise AuditError("post_delay_pipeline_mismatch")
        if ((hx(nxt["pre_pipe_id"])>>24)&0x80)!=0: raise AuditError("post_delay_still_marked")
        target=hx(c["post_pc_if"])
        if hx(nxt["pre_pc_id"])!=target: raise AuditError("control_target_pc_mismatch")
        if hx(nxt["pre_pc_if"])!=((target+2)&0xffffffff): raise AuditError("control_target_pcif_mismatch")
        if c["control_kind"] in ("bsr","jsr") and hx(c["post_pr"])!=hx(c["pre_rpc"]):
            raise AuditError("call_return_token_mismatch")
        if c["control_kind"]=="rts" and hx(c["pre_pr"])!=target:
            raise AuditError("rts_return_target_mismatch")
        pipeline_windows+=1
    bsr_flags=[x for x in rows if x["target_bsr"]=="1"]
    rts_flags=[x for x in rows if x["target_rts_candidate"]=="1"]
    if len(bsr_flags)!=1 or len(rts_flags)!=1: raise AuditError("target_call_pair_missing")
    target_bsr=bsr_flags[0]; target_rts=rts_flags[0]
    if int(target_rts["relative_step"])<=int(target_bsr["relative_step"]): raise AuditError("target_return_order")
    expected_return=hx(target_bsr["post_pr"])
    if hx(target_rts["pre_pr"])!=expected_return or hx(target_rts["post_pc_if"])!=expected_return:
        raise AuditError("target_return_token_mismatch")

    # Reconstruct a delayed call stack. The call/RTS delay slot is attributed to
    # the current caller/callee; push/pop occurs after that delay-slot step.
    stack=[]; frames=[]; pending=None; mismatches=0; delay_conflicts=0
    current_r13=hx(rows[0]["pre_r13"])
    target_frame=None; target_returned=False
    r13_changes=0; r13_changes_in_target_window=0
    returned_match=0; returned_mismatch=0; max_depth=0
    for row in rows:
        s=int(row["relative_step"])
        if pending is not None and s!=pending["step"]+1:
            raise AuditError("missing_delay_step")
        if row["r13_changed"]=="1":
            r13_changes+=1
            if int(target_bsr["relative_step"])<=s<=int(target_rts["relative_step"]):
                r13_changes_in_target_window+=1
            if stack: stack[-1]["r13_change_count"]+=1
        current_r13=hx(row["post_r13"])
        if pending is not None:
            if row["control_kind"]!="none": delay_conflicts+=1; raise AuditError("control_in_delay_slot")
            if pending["kind"]=="call":
                fr={"id":len(frames)+1,"type":pending["type"],"step":pending["step"],
                    "return_token":pending["return_token"],"target":pending["target"],
                    "entry_r13":current_r13,"return_r13":None,"preserved":None,
                    "r13_change_count":0,"is_target":pending["is_target"]}
                frames.append(fr); stack.append(fr)
                if fr["is_target"]: target_frame=fr
                max_depth=max(max_depth,len(stack))
            else:
                if not stack: raise AuditError("rts_empty_stack")
                fr=stack[-1]
                if pending["return_token"]!=fr["return_token"]:
                    mismatches+=1; raise AuditError("rts_token_stack_mismatch")
                fr["return_r13"]=current_r13
                fr["preserved"]=(fr["entry_r13"]==current_r13)
                if fr["preserved"]: returned_match+=1
                else: returned_mismatch+=1
                if fr["is_target"]: target_returned=True
                stack.pop()
            pending=None
        ctl=row["control_kind"]
        if ctl in ("bsr","jsr"):
            pending={"kind":"call","type":ctl.upper(),"step":s,
                     "return_token":hx(row["post_pr"]),"target":hx(row["post_pc_if"]),
                     "is_target":row["target_bsr"]=="1"}
        elif ctl=="rts":
            pending={"kind":"return","type":"RTS","step":s,
                     "return_token":hx(row["pre_pr"]),"is_target":row["target_rts_candidate"]=="1"}
    if pending is not None: raise AuditError("unfinished_delay_slot")
    if stack: raise AuditError("unclosed_call_stack")
    if not target_returned or target_frame is None: raise AuditError("target_frame_not_returned")
    if target_frame["preserved"] is not True: raise AuditError("target_r13_boundary_mismatch")
    return {
      "schema_version":1,"stage":"stage115_control_flow_event_gate",
      "capture_complete":True,"rows":len(rows),"control_flow_events":len(controls),
      "normal_bsr_events":counts["bsr"],"normal_jsr_events":counts["jsr"],"normal_rts_events":counts["rts"],
      "pipeline_windows_verified":pipeline_windows,"all_control_transfer_windows_verified":pipeline_windows==len(controls),
      "target_bsr_rts_return_pipeline_verified":True,"inferred_call_stack_closed_at_target_return":True,
      "inferred_returned_frames_r13_boundary_matches":returned_match,
      "inferred_returned_frames_r13_boundary_mismatches":returned_mismatch,
      "max_inferred_call_depth":max_depth,"r13_change_events":r13_changes,
      "target_window_r13_change_events":r13_changes_in_target_window,
      "target_call_r13_entry_return_equal":True,
      "r13_unchanged_throughout_target_call":r13_changes_in_target_window==0,
      "all_path_r13_preservation_proven":False,
      "alternate_callsite_runtime_coverage_proven":False,
      "private_addresses_opcodes_registers_or_ram_values_emitted":False
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("trace",type=Path);ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args()
    try: result=audit(a.trace)
    except AuditError as e:
        print(json.dumps({"schema_version":1,"stage":"stage115_control_flow_event_gate","capture_complete":False,"failure":str(e),"private_values_emitted":False},sort_keys=True))
        return 2
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0
if __name__=="__main__": raise SystemExit(main())
