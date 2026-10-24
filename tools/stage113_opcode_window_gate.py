#!/usr/bin/env python3
"""Fail-closed validator for private Stage113 opcode windows; safe counts only."""
from __future__ import annotations
import argparse,csv,json
from pathlib import Path

HEADER = ["kind","relative_step","global_step","pre_pc","pre_pc_id","pre_pc_if","pre_pipe_id","pre_pipe_if","pre_r3","pre_r13","pre_r15","pre_pr","pre_sr","pre_byte","post_pc","post_pc_id","post_pc_if","post_pipe_id","post_pipe_if","post_r3","post_r13","post_r15","post_pr","post_sr","post_byte","byte_changed","rpc_equals_pr_candidate"]
HEX_FIELDS = {"pre_pc","pre_pc_id","pre_pc_if","pre_pipe_id","pre_pipe_if","pre_r3","pre_r13","pre_r15","pre_pr","pre_sr","post_pc","post_pc_id","post_pc_if","post_pipe_id","post_pipe_if","post_r3","post_r13","post_r15","post_pr","post_sr"}
class AuditError(ValueError): pass

def is_hex(v, width):
    return len(v)==width and all(c in "0123456789abcdefABCDEF" for c in v)

def audit(path: Path):
    if path.is_symlink() or not path.is_file(): raise AuditError("invalid_input")
    with path.open("r",encoding="ascii",newline="") as fp:
        rows=csv.reader(fp)
        if next(rows,None) != ["stage113_opcode_witness_v1"]: raise AuditError("bad_magic")
        if next(rows,None) != HEADER: raise AuditError("bad_header")
        count=0; context_count=0; step_count=0; last_global=0; last_rel=None
        byte_steps=[]; candidate_steps=[]; opcode_pc_rows=0; rts_candidate_steps=[]
        step_rows={}
        for row in rows:
            if len(row)!=len(HEADER): raise AuditError("column_count")
            d=dict(zip(HEADER,row)); count+=1
            if count>1024: raise AuditError("too_many_rows")
            if d["kind"] not in ("context","step"): raise AuditError("bad_kind")
            if not d["global_step"].isascii() or not d["global_step"].isdecimal(): raise AuditError("bad_global_step")
            g=int(d["global_step"])
            if g<=last_global: raise AuditError("global_order")
            last_global=g
            if not d["relative_step"].lstrip("-").isascii() or not d["relative_step"].lstrip("-").isdecimal(): raise AuditError("bad_relative_step")
            rel=int(d["relative_step"])
            if last_rel is not None and rel<=last_rel: raise AuditError("relative_order")
            last_rel=rel
            for f in ("pre_pc","pre_pc_id","pre_pc_if","pre_pipe_id","pre_pipe_if","pre_r13","pre_r15","pre_pr","pre_sr"):
                if not is_hex(d[f],8): raise AuditError("bad_pre_hex")
            if not is_hex(d["pre_byte"],2): raise AuditError("bad_pre_byte")
            if d["kind"]=="context":
                context_count+=1
                if any(d[f] for f in ("post_pc","post_pc_id","post_pc_if","post_pipe_id","post_pipe_if","post_r13","post_r15","post_pr","post_sr","post_byte")): raise AuditError("context_has_post")
                if d["byte_changed"]!="0" or d["rpc_equals_pr_candidate"]!="0": raise AuditError("context_flags")
                continue
            step_count+=1
            for f in HEX_FIELDS:
                if not is_hex(d[f],8): raise AuditError("bad_step_hex")
            if not is_hex(d["post_byte"],2): raise AuditError("bad_post_byte")
            if d["byte_changed"] not in ("0","1") or d["rpc_equals_pr_candidate"] not in ("0","1"): raise AuditError("bad_flags")
            if int(d["pre_pc_id"],16)!=0: opcode_pc_rows+=1
            if d["pre_byte"]!=d["post_byte"]: byte_steps.append(rel)
            if d["rpc_equals_pr_candidate"]=="1":
                candidate_steps.append(rel)
                if int(d["pre_pipe_id"],16)&0xffff==0x000b and int(d["post_pc"],16)==int(d["post_pr"],16): rts_candidate_steps.append(rel)
            step_rows[rel]=d
    if not count: raise AuditError("empty_trace")
    if len(byte_steps)>1: raise AuditError("multiple_byte_transitions_in_capture")
    if len(candidate_steps)>1: raise AuditError("multiple_candidates_in_capture")
    candidate=candidate_steps[0] if candidate_steps else None
    post_candidate_steps=sorted(rel for rel in step_rows if candidate is not None and candidate<rel<=candidate+64)
    post_candidate=len(post_candidate_steps)
    candidate_contiguous=candidate is not None and post_candidate_steps==list(range(candidate+1,candidate+65))
    trigger_window_contiguous=all(rel in step_rows for rel in range(1,257))
    byte_step=byte_steps[0] if byte_steps else None
    byte_row=step_rows.get(byte_step) if byte_step is not None else None
    return {
      "schema_version":1,"stage":"stage113_private_opcode_window_gate",
      "capture_structure_valid":True,"rows":count,"context_rows":context_count,"paired_step_rows":step_count,
      "instruction_pc_fields_available":opcode_pc_rows>0,"trigger_window_complete":trigger_window_contiguous,
      "target_byte_transition_rows":len(byte_steps),"target_byte_transition_inside_paired_step":byte_row is not None,
      "target_byte_transition_opcode_pc_available":bool(byte_row and int(byte_row["pre_pc_id"],16)!=0),
      "rpc_equals_pr_candidate_rows":len(candidate_steps),"candidate_has_rts_opcode_and_return_pc_match":bool(rts_candidate_steps),
      "post_candidate_step_rows":post_candidate,"candidate_window_complete":candidate_contiguous,
      "complete_call_return_proven":False,"all_path_r13_preservation_proven":False,
      "private_addresses_opcodes_registers_and_bytes_emitted":False
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--trace",type=Path,required=True);ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args()
    try: result=audit(a.trace)
    except (AuditError,OSError,UnicodeError) as e: raise SystemExit("stage113_opcode_gate_failed:"+type(e).__name__) from None
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("stage113_opcode_gate_pass")
    return 0
if __name__=="__main__": raise SystemExit(main())