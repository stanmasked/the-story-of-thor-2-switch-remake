#!/usr/bin/env python3
"""Stage110 safe proof gate for two privately captured Saturn SH-2 traces.

Public code and synthetic tests only. Actual CSV, PC trigger, ISO and BIOS stay
on private storage. Output is a deliberately redacted set of Boolean statuses,
not a claim that a complete JSR/callee-return path was independently observed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

PINS = {
    'iso': (106954752, '25b0b2774d4621bd9f95a01fc5420ded37b481b61b3cdf515360d82b2cb7bb0d'),
    'bios': (524288, '96e106f740ab448cf89f0dd49dfbac7fe5391cb6bd6e14ad5e3061c13330266f'),
}
HEADER = 'stage109_sh2_steps_v1'
ROW = re.compile(r'^(\d+),(pre|post),((?:[0-9a-fA-F]{8},){9}[0-9a-fA-F]{8})$')
HEX_PC = re.compile(r'^[0-9a-fA-F]{8}$')
AUTOSTEP_LINE = re.compile(r'^debugger\.autostepmode\s+([01])$',re.M)
MAX_TRACE_SIZE = 2_000_000

class EvidenceError(Exception):
    """Only safe failure codes; no private paths or register values."""


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(1024*1024), b''):
                h.update(chunk)
    except OSError:
        raise EvidenceError('source_unavailable') from None
    return h.hexdigest()


def check_source(path: Path, pin: tuple[int, str]) -> None:
    try:
        if not path.is_file() or path.stat().st_size != pin[0]:
            raise EvidenceError('source_identity_mismatch')
    except OSError:
        raise EvidenceError('source_unavailable') from None
    if file_sha(path) != pin[1]:
        raise EvidenceError('source_identity_mismatch')


def check_config(path: Path) -> None:
    try:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise EvidenceError('invalid_emulator_config')
        config = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        raise EvidenceError('invalid_emulator_config') from None
    matches = AUTOSTEP_LINE.findall(config)
    if matches != ['0']:
        raise EvidenceError('debugger_autostep_must_be_disabled')


def read_pc(path: Path) -> int:
    try:
        if not path.is_file() or path.stat().st_size > 32:
            raise EvidenceError('invalid_private_pc')
        s = path.read_text(encoding='ascii').strip()
    except (OSError, UnicodeError):
        raise EvidenceError('invalid_private_pc') from None
    if not HEX_PC.fullmatch(s):
        raise EvidenceError('invalid_private_pc')
    return int(s, 16)


def read_trace(path: Path) -> list[tuple[int, int, tuple[int, ...]]]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_TRACE_SIZE:
            raise EvidenceError('invalid_trace')
        lines = path.read_text(encoding='ascii').splitlines()
    except (OSError, UnicodeError):
        raise EvidenceError('invalid_trace') from None
    if not lines or lines[0] != HEADER or len(lines) < 5 or (len(lines)-1) % 2 or len(lines) > 8193:
        raise EvidenceError('invalid_trace')
    result = []
    for i, line in enumerate(lines[1:]):
        m = ROW.fullmatch(line)
        if not m or int(m.group(1)) != i//2 or m.group(2) != ('pre' if i%2 == 0 else 'post'):
            raise EvidenceError('invalid_trace')
        result.append((int(m.group(1)), 0 if m.group(2)=='pre' else 1,
                       tuple(int(v, 16) for v in m.group(3).split(','))))
    # A post-execution state is the very next instruction's pre-execution state.
    for i in range(1, len(result)-1, 2):
        if result[i][2] != result[i+1][2]:
            raise EvidenceError('state_continuity_mismatch')
    return result


def audit(iso: Path, bios: Path, trace_a: Path, trace_b: Path,
          trigger: Path, config_a: Path, config_b: Path,
          pins: dict = PINS) -> dict:
    check_source(iso, pins['iso'])
    check_source(bios, pins['bios'])
    if trace_a.resolve() == trace_b.resolve() or config_a.resolve() == config_b.resolve():
        raise EvidenceError('sessions_not_distinct')
    check_config(config_a)
    check_config(config_b)
    target = read_pc(trigger)
    a, b = read_trace(trace_a), read_trace(trace_b)
    matches = []
    all_one = []
    for trace in (a, b):
        pre = [x for x in trace if x[1] == 0]
        hit = [x for x in pre if target in x[2][:3]]
        if len(hit) != 1 or hit[0][0] != 0:
            raise EvidenceError('target_not_uniquely_observed_at_record_start')
        if hit[0][2][3] != 1:
            raise EvidenceError('r13_not_one_at_observed_writer')
        matches.append(len(pre))
        all_one.append(all(r[2][3] == 1 for r in trace))
    return {
        'schema_version': 1,
        'stage': 'stage110_private_stage99_sh2_machine_pair_gate',
        'source_iso_bios_sha256_verified': True,
        'both_debugger_autostep_configs_disabled': True,
        'two_distinct_private_sessions': True,
        'session_a_valid_pairs': matches[0],
        'session_b_valid_pairs': matches[1],
        'private_stage99_trigger_unique_at_first_pair_in_both': True,
        'r13_one_at_trigger_in_both': True,
        'r13_one_throughout_session_a': all_one[0],
        'r13_one_throughout_session_b': all_one[1],
        'raw_trace_bytes_identical': file_sha(trace_a) == file_sha(trace_b),
        'callee_entry_return_verified': False,
        'stage104_unconditional_r13_preservation_proven': False,
        'private_addresses_registers_or_game_bytes_emitted': False,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    for k in ('iso','bios','trace_a','trace_b','trigger','config_a','config_b'):
        ap.add_argument('--'+k.replace('_','-'), required=True, type=Path)
    ap.add_argument('--safe-output', type=Path)
    args = ap.parse_args()
    try:
        result = audit(args.iso,args.bios,args.trace_a,args.trace_b,
                       args.trigger,args.config_a,args.config_b)
    except EvidenceError as e:
        result = {'schema_version':1, 'stage':'stage110_private_stage99_sh2_machine_pair_gate',
                  'pass':False,'failure_code':str(e),
                  'callee_entry_return_verified':False,
                  'stage104_unconditional_r13_preservation_proven':False,
                  'private_addresses_registers_or_game_bytes_emitted':False}
    else:
        result['pass'] = True
    s = json.dumps(result, indent=2)+'\n'
    if args.safe_output:
        args.safe_output.write_text(s, encoding='utf-8')
    print(s, end='')
    if not result['pass']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()