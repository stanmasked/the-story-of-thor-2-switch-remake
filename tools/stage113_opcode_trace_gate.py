#!/usr/bin/env python3
"""Fail-closed parser for private Stage113 SH-2 opcode-dispatch traces; safe counts only."""
from __future__ import annotations
import argparse,csv,json
from collections import Counter,defaultdict
from pathlib import Path

HEADER="stage113_sh2_opcode_trace_v1"
HEX8=set("0123456789abcdefABCDEF")
class TraceError(ValueError): pass

def hx(value,width):
    return len(value)==width and all(c in HEX8 for c in value)

def audit(path:Path,max_steps:int=8192)->dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size>8_000_000:
        raise TraceError("invalid_input")
    if not 16<=max_steps<=8192:
        raise TraceError("invalid_limit")
    per_cpu=defaultdict(list)
    try:
        with path.open("r",encoding="ascii",newline="") as f:
            rows=csv.reader(f)
            try: head=next(rows)
            except StopIteration: raise TraceError("empty") from None
            if head != [HEADER]: raise TraceError("bad_header")
            count=0
            for row in rows:
                count+=1
                if count>32768: raise TraceError("too_many_rows")
                if len(row)!=12: raise TraceError("wrong_columns")
                cpu_s,step_s,phase,pipe_s,opcode_s,dispatch_s,*state=row
                if cpu_s not in ("0","1") or not step_s.isascii() or not step_s.isdecimal():
                    raise TraceError("bad_cpu_or_step")
                cpu=int(cpu_s);step=int(step_s)
                if phase not in ("pre","post"): raise TraceError("bad_phase")
                if not hx(pipe_s,8) or not hx(opcode_s,4) or not hx(dispatch_s,8):
                    raise TraceError("bad_opcode_encoding")
                if len(state)!=6 or not all(hx(v,8) for v in state):
                    raise TraceError("bad_state_encoding")
                pipe=int(pipe_s,16);opcode=int(opcode_s,16);dispatch=int(dispatch_s,16)
                if (pipe&0xFFFF)!=opcode or (pipe>>24)!=dispatch:
                    raise TraceError("pipe_opcode_mismatch")
                per_cpu[cpu].append((step,phase,pipe,opcode,dispatch,tuple(int(v,16) for v in state)))
    except (OSError,UnicodeError,csv.Error) as exc:
        raise TraceError("unreadable_trace") from None
    if not count: raise TraceError("no_rows")

    completed=[]
    cpu_counts={}
    for cpu,records in per_cpu.items():
        pending=None
        expected=0
        pairs=[]
        for step,phase,pipe,opcode,dispatch,state in records:
            if step!=expected:
                raise TraceError("step_sequence")
            if phase=="pre":
                if pending is not None: raise TraceError("duplicate_pre_without_post")
                pending=(step,pipe,opcode,dispatch,state)
            else:
                if pending is None: raise TraceError("orphan_post")
                ps,pp,po,pd,pstate=pending
                if ps!=step or (pp,po,pd)!=(pipe,opcode,dispatch):
                    raise TraceError("pre_post_dispatch_mismatch")
                pairs.append((po,pstate,state))
                pending=None
                expected+=1
        if pending is not None: raise TraceError("incomplete_instruction")
        if not pairs: raise TraceError("empty_cpu_trace")
        cpu_counts[str(cpu)]=len(pairs)
        completed.extend(pairs)

    rts=bsr=jsr=bsrf=rte=0
    r13_changes=pr_changes=0
    rts_after_bsr_same_pr=0
    for cpu,records in per_cpu.items():
        pairs=[]
        for i in range(0,len(records),2):
            a,b=records[i],records[i+1]
            pairs.append((a[3],a[5],b[5]))
        seen_bsr_pr=[]
        for opcode,pre,post in pairs:
            if opcode==0x000B:
                rts+=1
                if any(pr==pre[5] for pr in seen_bsr_pr):
                    rts_after_bsr_same_pr+=1
            if (opcode&0xF000)==0xB000:
                bsr+=1
                seen_bsr_pr.append(post[5])
            if (opcode&0xF0FF)==0x400B: jsr+=1
            if (opcode&0xF0FF)==0x0003: bsrf+=1
            if opcode==0x002B: rte+=1
            if pre[4]!=post[4]: r13_changes+=1
            if pre[5]!=post[5]: pr_changes+=1

    complete_to_limit=bool(cpu_counts) and all(n==max_steps for n in cpu_counts.values())
    return {
        "schema_version":1,
        "stage":"stage113_private_executed_opcode_trace",
        "trace_structure_valid":True,
        "cpu_traces":len(cpu_counts),
        "completed_instruction_pairs":len(completed),
        "cpu0_instruction_pairs":cpu_counts.get("0",0),
        "cpu1_instruction_pairs":cpu_counts.get("1",0),
        "configured_step_limit_reached_for_all_traced_cpus":complete_to_limit,
        "completed_rts_dispatches":rts,
        "completed_bsr_dispatches":bsr,
        "completed_jsr_dispatches":jsr,
        "completed_bsrf_dispatches":bsrf,
        "completed_rte_dispatches":rte,
        "r13_changed_across_completed_instructions":r13_changes,
        "pr_changed_across_completed_instructions":pr_changes,
        "rts_after_bsr_same_pr_candidates":rts_after_bsr_same_pr,
        "actual_call_return_proven":False,
        "all_path_r13_preservation_proven":False,
        "private_addresses_registers_and_opcode_words_emitted":False
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trace",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--max-steps",type=int,default=8192)
    a=p.parse_args()
    try: result=audit(a.trace,a.max_steps)
    except (TraceError,OSError,UnicodeError) as exc:
        raise SystemExit("stage113_opcode_trace_gate_failed:"+type(exc).__name__) from None
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("stage113_opcode_trace_gate_pass")
if __name__=="__main__": main()
