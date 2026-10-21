#!/usr/bin/env python3
"""Stage21: trace product factors and writer flag to three SP-relative byte loads.

Only aggregate findings are emitted. SP-relative offsets are data access
semantics, not offsets into the original game binary.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage20_vdp1_product_flow import matching_product_preludes, summarize_product_flow

STACK_FACTOR_PREFIX = (
    0xE014,  # MOV #20,R0
    0x05FC,  # MOV.B @(R0,R15),R5
    0xE020,  # MOV #32,R0
    0x03FC,  # MOV.B @(R0,R15),R3
)


def matching_stack_source_chains(data: bytes) -> list[dict]:
    """Find exact contiguous stack-source loads preceding Stage20's prelude."""
    result = []
    # Stage20's product prelude contains nine two-byte instructions.
    prelude_bytes = 18
    prefix_bytes = len(STACK_FACTOR_PREFIX) * 2
    for match in matching_product_preludes(data):
        prefix_start = match['block_start'] - prelude_bytes - prefix_bytes
        if prefix_start < 0:
            continue
        observed = tuple(be16(data, prefix_start + i * 2)
                         for i in range(len(STACK_FACTOR_PREFIX)))
        if observed == STACK_FACTOR_PREFIX:
            result.append({'block_start': match['block_start']})
    return result


def summarize_stack_sources(data: bytes) -> dict:
    matches = matching_stack_source_chains(data)
    stage20 = summarize_product_flow(data)
    chain_count = min(len(matches), stage20['preludes_linked_to_complete_stage19_count_writer'])
    return {
        'matching_three_stack_byte_sources': chain_count,
        'byte_factor_stack_offsets': [20, 32] if chain_count else [],
        'writer_enable_flag_stack_offset': 80 if chain_count else None,
        'per_source_count_formula': '(u8(stack[SP+20]) * u8(stack[SP+32])) >> 3' if chain_count else None,
        'writer_enable_condition': 'signed_byte(stack[SP+80]) == 1 and descriptor_count < 512' if chain_count else None,
        'notable_limits': [
            'Current R15 is used as SP; lifetime and initial population of these stack slots remain unknown.',
            'SP-relative byte locations do not identify original resource formats or fields.',
            'No real runtime values were captured.',
            'No original code offsets, source bytes, textures or other game assets are emitted.',
        ],
    }


def analyze(image: Path) -> dict:
    return {'schema_version': 1, 'stage': 'stage21_vdp1_stack_sources',
            'target_file': '0TH2.BIN', 'analysis': summarize_stack_sources(iso_file_payload(image))}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path)
    p.add_argument('-o', '--output', type=Path)
    args = p.parse_args()
    rendered = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    else:
        print(rendered)


if __name__ == '__main__':
    main()
