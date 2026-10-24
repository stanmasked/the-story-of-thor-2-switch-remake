#!/usr/bin/env python3
"""Fail-closed private-input RAM-state witness checker; safe aggregate only.

Never prints PC, R3, observed RAM bytes, private paths or source game data.
Consecutive step-state memory transitions do not by themselves prove opcode origin.
"""
from __future__ import annotations
import argparse, json, re, hashlib
from pathlib import Path

REG_ROW=re.compile(r'^(\d+),(pre|post),((?:[0-9a-fA-F]{8},){9}[0-9a-fA-F]{8})$')
RAM_ROW=re.compile(r'^(\d+),(pre|post),([0-9a-fA-F]{8}),([0-9a-fA-F]{8}),([0-9a-fA-F]{8}),([0-9a-fA-F]{8}),([0-9a-fA-F]{2}),([01])$')
HEAD_REG='stage109_sh2_steps_v1'
HEAD_RAM='stage111_sh2_highram_witness_v1'
MAX_BYTES=2_000_000
class EvidenceError(Exception):pass

def read_rows(path:Path,header:str,pattern:re.Pattern)->list[tuple[int,str,tuple[int,...]]]:
    try:
        if not path.is_file() or path.is_symlink() or path.stat().st_size>MAX_BYTES:
            raise EvidenceError('invalid_or_missing_trace')
        lines=path.read_text(encoding='ascii').splitlines()
    except (OSError, UnicodeError):raise EvidenceError('invalid_or_missing_trace') from None
    if not lines or lines[0]!=header or len(lines)<5 or len(lines)>8193 or (len(lines)-1)%2:
        raise EvidenceError('invalid_trace_shape')
    rows=[]
    for i,line in enumerate(lines[1:]):
        m=pattern.fullmatch(line)
        if not m or int(m.group(1))!=i//2 or m.group(2)!=('pre' if i%2==0 else 'post'):
            raise EvidenceError('invalid_trace_row')
        raw=m.groups()[2:]
        if header==HEAD_REG:
            values=tuple(int(x,16) for x in raw[0].split(','))
        else:
            values=tuple(int(x,16) for x in raw[:-1])+(int(raw[-1]),)
        rows.append((i//2,m.group(2),values))
    return rows

def session(reg_path:Path,mem_path:Path)->dict:
    if reg_path.resolve()==mem_path.resolve():raise EvidenceError('same_register_and_memory_file')
    regs=read_rows(reg_path,HEAD_REG,REG_ROW)
    mem=read_rows(mem_path,HEAD_RAM,RAM_ROW)
    if len(regs)!=len(mem):raise EvidenceError('step_count_mismatch')
    transitions=0
    valid_reads=0
    for r,w in zip(regs,mem):
        # Register CSV: PC_ID PC_IF RPC R13 PR R2 R3 R4 R5 R6
        # RAM CSV: PC_ID PC_IF RPC R3 RAM_byte valid_bit
        rv,wv=r[2],w[2]
        if r[:2]!=w[:2] or rv[:3]!=wv[:3] or rv[6]!=wv[3]:
            raise EvidenceError('register_memory_stream_mismatch')
        ok=(0x06000000<=wv[3]<0x08000000)
        if wv[5] != int(ok):raise EvidenceError('invalid_ram_address_flag')
        if not ok and wv[4] != 0:raise EvidenceError('invalid_read_must_be_zero')
        valid_reads+=int(ok)
    for i in range(0,len(mem),2):
        p,q=mem[i][2],mem[i+1][2]
        if p[5] and q[5] and p[3]==q[3] and p[4]!=q[4]:transitions+=1
    return {'full_step_pairs':len(regs)//2,
            'valid_backing_ram_snapshots':valid_reads,
            'same_pointer_pre_post_byte_changes':transitions,
            'memory_transition_seen':transitions>0}

def audit(ra:Path,ma:Path,rb:Path,mb:Path)->dict:
    files=(ra,ma,rb,mb)
    if len({p.resolve() for p in files}) != 4:raise EvidenceError('duplicate_session_file')
    a=session(ra,ma);b=session(rb,mb)
    return {'schema_version':1,'stage':'stage111_private_ram_witness_pair',
       'pass':True,'two_distinct_session_file_sets':True,'each_step_has_register_memory_alignment':True,
       'session_a_full_step_pairs':a['full_step_pairs'],'session_b_full_step_pairs':b['full_step_pairs'],
       'session_a_valid_ram_snapshots':a['valid_backing_ram_snapshots'],
       'session_b_valid_ram_snapshots':b['valid_backing_ram_snapshots'],
       'session_a_ram_transition_seen':a['memory_transition_seen'],
       'session_b_ram_transition_seen':b['memory_transition_seen'],
       'snapshot_bytes_identical_between_sessions':hashlib.sha256(ma.read_bytes()).digest()==hashlib.sha256(mb.read_bytes()).digest(),
       'opcode_origin_independently_proven':False,'call_return_verified':False,
       'stage104_unconditional_r13_preservation_proven':False,'private_addresses_bytes_or_register_values_emitted':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('register_a','memory_a','register_b','memory_b'):
        p.add_argument('--'+k.replace('_','-'),required=True,type=Path)
    p.add_argument('--safe-output',type=Path)
    a=p.parse_args()
    try:r=audit(a.register_a,a.memory_a,a.register_b,a.memory_b)
    except EvidenceError as exc:
        r={'schema_version':1,'stage':'stage111_private_ram_witness_pair','pass':False,'failure_code':str(exc),
        'opcode_origin_independently_proven':False,'call_return_verified':False,
        'stage104_unconditional_r13_preservation_proven':False,'private_addresses_bytes_or_register_values_emitted':False}
    data=json.dumps(r,indent=2)+'\n'
    if a.safe_output:a.safe_output.write_text(data,encoding='utf-8')
    print(data,end='')
    if not r['pass']:raise SystemExit(1)

if __name__=='__main__':main()