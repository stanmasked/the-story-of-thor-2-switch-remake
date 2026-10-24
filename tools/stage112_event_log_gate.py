#!/usr/bin/env python3
"""Fail-closed reader of Stage112 private event logs; exposes safe counts only."""
from __future__ import annotations
import argparse,csv,json
from collections import Counter
from pathlib import Path

HEADER='stage112_sh2_events_v1'
TYPES={'start','r13_change','pr_change','byte_change','rpc_equals_pr_candidate','sample','step_limit'}

class AuditError(ValueError):pass

def audit(p:Path):
    if p.is_symlink() or not p.is_file():raise AuditError('invalid_input')
    counter=Counter();previous=-1;count=0;started=False;ended=False;last=0
    with p.open('r',encoding='ascii',newline='') as fp:
        rows=csv.reader(fp)
        try:h=next(rows)
        except StopIteration:raise AuditError('empty') from None
        if h != [HEADER]:raise AuditError('bad_header')
        for record in rows:
            count+=1
            if count>4096:raise AuditError('too_many_events')
            if len(record)!=6:raise AuditError('wrong_columns')
            step,kind,*hexes=record
            if not step.isascii() or not step.isdecimal():raise AuditError('wrong_step')
            value=int(step)
            if value<previous or value>2000000:raise AuditError('step_order')
            if kind not in TYPES:raise AuditError('unknown_event')
            if not all(len(v)==8 and all(ch in '0123456789abcdefABCDEF' for ch in v) for v in hexes[:3]):raise AuditError('invalid_register')
            if len(hexes[3])!=2 or any(ch not in '0123456789abcdefABCDEF' for ch in hexes[3]):raise AuditError('invalid_byte')
            if count==1 and (kind!='start' or value!=0):raise AuditError('first_not_start')
            if kind=='start':
                if started:raise AuditError('duplicate_start')
                started=True
            if ended:raise AuditError('event_after_stop')
            if kind=='step_limit':ended=True
            counter[kind]+=1;previous=value;last=value
    if not started:raise AuditError('not_triggered')
    return {'schema_version':1,'stage':'stage112_private_bounded_event_gate',
            'valid_observer_events':True,'event_count':count,'last_sampled_step':last,
            'step_limit_observed':ended,
            'r13_change_events':counter['r13_change'],
            'pr_change_events':counter['pr_change'],
            'control_byte_change_events':counter['byte_change'],
            'rpc_equals_pr_candidates':counter['rpc_equals_pr_candidate'],
            'periodic_samples':counter['sample'],
            'full_call_return_proven':False,
            'all_paths_r13_preservation_proven':False,
            'exact_executing_instruction_proven':False,
            'private_addresses_registers_and_bytes_emitted':False}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--trace',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args()
    try:r=audit(args.trace)
    except (AuditError,OSError,UnicodeError) as e:raise SystemExit('stage112_event_gate_failed:'+type(e).__name__) from None
    args.out.write_text(json.dumps(r,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    print('stage112_event_gate_pass')
if __name__=='__main__':main()