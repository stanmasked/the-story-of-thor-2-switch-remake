#!/usr/bin/env python3
"""Fail-closed validator of private SH2 dispatch-selected opcode evidence.

Only safe counters are exposed; selected opcode is NOT an executed-return proof.
A full BSR/RTS proof needs independently established dynamic call-site, delay
slot and return-site, not just a Pipe_ID word or PC pipeline coincidence.
"""
from __future__ import annotations
import argparse,csv,json,re
from collections import Counter
from pathlib import Path

HEADER='stage113_dispatch_selected_opcode_v1'
KINDS={'start','selected','pr_change','r13_change','sample','step_limit','event_cap'}
HEX8=re.compile(r'^[0-9a-fA-F]{8}$')

class GateError(ValueError):pass

def audit(path:Path)->dict:
 if path.is_symlink() or not path.is_file():raise GateError('invalid_file')
 counts=Counter();pairs=0;selected={};prev=-1;closed=False;start=False;laststep=0;row_count=0
 with path.open(encoding='ascii',newline='') as fp:
  reader=csv.reader(fp)
  try:head=next(reader)
  except StopIteration:raise GateError('empty') from None
  if head!=[HEADER]:raise GateError('bad_header')
  for i,row in enumerate(reader):
   if i>=16384:raise GateError('unbounded_input')
   row_count+=1
   if len(row)!=10:raise GateError('wrong_columns')
   step,phase,kind,*hexes=row
   if not step.isascii() or not step.isdecimal():raise GateError('bad_step')
   n=int(step)
   if n>2000000 or n<prev:raise GateError('step_order')
   if phase not in ('pre','post') or kind not in KINDS:raise GateError('invalid_event')
   if any(not HEX8.fullmatch(v) for v in hexes):raise GateError('bad_hex')
   if closed:raise GateError('events_after_termination')
   if i==0:
    if n!=0 or phase!='pre' or kind!='start':raise GateError('missing_start')
    start=True
   if kind=='start' and i!=0:raise GateError('duplicate_start')
   if kind=='selected':
    opcode=int(hexes[0],16)&0xffff
    if phase=='pre':
     if n in selected:raise GateError('duplicate_selected_pre')
     selected[n]=hexes[0]
     if (opcode&0xf000)==0xb000:counts['bsr_selected']+=1
     if (opcode&0xf0ff)==0x400b:counts['jsr_selected']+=1
     if opcode==0x000b:counts['rts_selected']+=1
    elif phase=='post':
     if selected.pop(n,None)!=hexes[0]:raise GateError('unpaired_selected_post')
     pairs+=1
   elif kind in ('step_limit','event_cap'):
    if phase!='post':raise GateError('bad_end_phase')
    if selected:raise GateError('open_opcode_pair')
    closed=True
   else:
    if kind not in ('start',) and phase!='post':raise GateError('unexpected_pre_event')
   counts[kind]+=1;prev=n;laststep=n
 if not start:raise GateError('empty_stream')
 if selected:raise GateError('incomplete_opcode_pair')
 return {'schema_version':1,'stage':'stage113_dispatch_selected_opcode_gate',
         'parsed_event_count':row_count,
         'selected_opcode_pre_post_pairs':pairs,
         'bsr_selected_records':counts['bsr_selected'],
         'jsr_selected_records':counts['jsr_selected'],
         'rts_selected_records':counts['rts_selected'],
         'r13_change_event_count':counts['r13_change'],
         'pr_change_event_count':counts['pr_change'],
         'step_limit_observed':bool(counts['step_limit']),
         'event_cap_observed':bool(counts['event_cap']),
         'capture_finished_with_marker':closed,
         'last_step_number':laststep,
         'selected_opcode_proves_execution':False,
         'complete_bsr_rts_return_proven':False,
         'r13_preservation_across_all_paths_proven':False,
         'raw_addresses_registers_or_opcodes_in_safe_output':False}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--trace',required=True,type=Path)
 p.add_argument('--out',required=True,type=Path)
 a=p.parse_args()
 try:r=audit(a.trace)
 except (GateError,OSError,UnicodeError):raise SystemExit('stage113_opcode_gate_failed') from None
 a.out.write_text(json.dumps(r,indent=2,sort_keys=True)+'\n')
 print('stage113_opcode_gate_pass')

if __name__=='__main__':main()