#!/usr/bin/env python3
"""Offline fail-closed SH-2 liveness analysis, private raw input, safe output only.

Never output private PC/PR/R13 fields, addresses or code bytes. Repetitive RPC
values are pipeline context only, not exact executed opcodes or call identity.
"""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from pathlib import Path

HEADER = 'stage109_sh2_steps_v1'
MAX_PAIRS = 1_000_000

class AuditError(ValueError):
    pass


def read(path: Path):
    if path.is_symlink() or not path.is_file():
        raise AuditError('invalid_input')
    with path.open('r', encoding='ascii', newline='') as fh:
        rows = csv.reader(fh)
        try:
            first = next(rows)
        except StopIteration:
            raise AuditError('missing_header') from None
        if first != [HEADER]:
            raise AuditError('wrong_header')
        pairs = []
        previous = None
        for index, row in enumerate(rows):
            if index >= 2*MAX_PAIRS:
                raise AuditError('excessive_rows')
            if len(row) != 12:
                raise AuditError('wrong_column_count')
            n,phase,*hexes=row
            if not n.isascii() or not n.isdecimal() or int(n) != index//2:
                raise AuditError('step_sequence')
            if phase != ('pre' if index%2 == 0 else 'post'):
                raise AuditError('missing_or_misordered_phase')
            if not all(len(h)==8 and all(c in '0123456789abcdefABCDEF' for c in h) for h in hexes):
                raise AuditError('invalid_register_encoding')
            state=tuple(int(h,16) for h in hexes)
            if index%2 == 0:
                previous=state
            else:
                if previous is None:
                    raise AuditError('orphan_post')
                pairs.append((previous,state))
                previous=None
        if not pairs:
            raise AuditError('empty_trace')
        return pairs


def tail_cycle(values, max_period=32, min_repetitions=4):
    """Return smallest strict repeating suffix period, never a PC or address."""
    n=len(values)
    for size in range(1,min(max_period,n//min_repetitions)+1):
        suffix=values[-size:]
        repetitions=0
        for end in range(n,0,-size):
            if end-size < 0 or values[end-size:end] != suffix:
                break
            repetitions += 1
        if repetitions>=min_repetitions:
            return size,repetitions
    return 0,0


def audit(path:Path):
    pairs=read(path)
    # SH-2 GetRegister PC_ID/PC_IF can be static during long stretches. RPC is
    # not proof of an executed instruction, but it can reveal bounded liveness.
    rpc=[before[2] for before,_ in pairs]
    r13=[before[3] for before,_ in pairs]
    pr=[before[4] for before,_ in pairs]
    period,reps=tail_cycle(rpc)
    pr_changes=sum(a!=b for a,b in zip(pr,pr[1:]))
    r13_changes=sum(a!=b for a,b in zip(r13,r13[1:]))
    return {
        'schema_version':1,'stage':'stage112_bounded_sh2_liveness',
        'trace_structure_valid':True,'complete_pre_post_pairs':len(pairs),
        'unique_rpc_pipeline_values':len(set(rpc)),
        'rpc_tail_cycle_period':period,'rpc_tail_cycle_repetitions':reps,
        'r13_value_changed_in_observed_pre_step_states':bool(r13_changes),
        'pr_changed_in_observed_pre_step_states':bool(pr_changes),
        'full_bsr_rts_return_verified':False,
        'all_path_register_preservation_proven':False,
        'exact_executing_opcode_attributed':False,
        'private_pc_or_register_values_emitted':False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    try:result=audit(args.trace)
    except (AuditError, OSError, UnicodeError) as exc:
        raise SystemExit('stage112_liveness_audit_failed:'+type(exc).__name__) from None
    args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print('stage112_liveness_audit_pass')

if __name__=='__main__':main()