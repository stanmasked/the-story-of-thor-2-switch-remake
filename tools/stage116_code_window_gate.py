#!/usr/bin/env python3
"""Fail-closed safe aggregate for private Stage116 SH-2 code windows."""
from __future__ import annotations
import argparse,csv,json
from collections import Counter
from pathlib import Path
HEADER=['kind','relative_step','global_step','control_kind','pre_rpc','pre_pc_id','pre_pipe_id','pre_pr','pre_r13','post_pc_id','post_pipe_id','post_pr','post_r13','window_base','window_valid','selected_word_matches','window_hex']
MAGIC='stage116_sh2_code_window_v1'
KINDS={'bsr','jsr','rts'}
class AuditError(ValueError): pass

def _hex(s,n): return len(s)==n and all(c in '0123456789abcdefABCDEF' for c in s)
def audit(path:Path):
    if path.is_symlink() or not path.is_file(): raise AuditError('invalid_input')
    count=0; previous=-1; marker=None; kinds=Counter(); valid=matches=invalid=0
    with path.open('r',encoding='ascii',newline='') as fp:
        rd=csv.reader(fp)
        if next(rd,None)!=[MAGIC] or next(rd,None)!=HEADER: raise AuditError('bad_header')
        for row in rd:
            if len(row)!=len(HEADER): raise AuditError('wrong_columns')
            d=dict(zip(HEADER,row))
            if marker is not None: raise AuditError('row_after_terminal')
            if d['kind'] in ('complete','incomplete','event_cap'):
                if not d['relative_step'].isdecimal() or not d['global_step'].isdecimal(): raise AuditError('bad_terminal')
                if any(d[k] for k in HEADER[3:]): raise AuditError('terminal_payload')
                if int(d['relative_step'])<previous: raise AuditError('terminal_before_event')
                marker=d['kind']; continue
            if d['kind']!='step': raise AuditError('unknown_kind')
            if not d['relative_step'].isdecimal() or not d['global_step'].isdecimal(): raise AuditError('bad_step')
            step=int(d['relative_step']); glob=int(d['global_step'])
            if step<=previous or step>2_000_000 or glob>10_000_000_000: raise AuditError('step_order_or_bound')
            previous=step; count+=1
            if count>4096: raise AuditError('too_many_rows')
            if d['control_kind'] not in KINDS: raise AuditError('bad_control_kind')
            for k in ('pre_rpc','pre_pc_id','pre_pipe_id','pre_pr','pre_r13','post_pc_id','post_pipe_id','post_pr','post_r13','window_base'):
                if not _hex(d[k],8): raise AuditError('bad_hex_field')
            if d['window_valid'] not in ('0','1') or d['selected_word_matches'] not in ('0','1'): raise AuditError('bad_boolean')
            base=int(d['window_base'],16); pc=int(d['pre_pc_id'],16); pipe=int(d['pre_pipe_id'],16)
            if d['window_valid']=='1':
                if base&0xf or base<0x06000000 or base+48>0x06100000 or not _hex(d['window_hex'],96): raise AuditError('bad_window')
                if pc<base or pc+2>base+48: raise AuditError('pc_outside_window')
                off=(pc-base)*2; word=int(d['window_hex'][off:off+4],16)
                actual=int(word==(pipe&0xffff))
                if actual!=int(d['selected_word_matches']): raise AuditError('word_match_flag')
                valid+=1; matches+=actual
            else:
                if d['window_hex'] or d['selected_word_matches']!='0': raise AuditError('invalid_window_payload')
                invalid+=1
            kinds[d['control_kind']]+=1
    if marker!='complete' or count==0: raise AuditError('capture_incomplete')
    return {'schema_version':1,'stage':'stage116_private_code_window_gate','capture_complete':True,
            'control_transfer_windows':count,'bsr_windows':kinds['bsr'],'jsr_windows':kinds['jsr'],'rts_windows':kinds['rts'],
            'physical_workram_windows_valid':valid,'selected_instruction_words_match_window':matches,
            'windows_without_direct_workram':invalid,'source_file_provenance_established':False,
            'bios_callee_identified':False,'all_path_r13_preservation_proven':False,
            'private_addresses_opcodes_and_bytes_emitted':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--trace',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try: r=audit(a.trace)
    except (AuditError,OSError,UnicodeError) as exc: raise SystemExit('stage116_code_window_gate_failed:'+type(exc).__name__) from None
    a.out.write_text(json.dumps(r,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    print('stage116_code_window_gate_pass')
if __name__=='__main__': main()
