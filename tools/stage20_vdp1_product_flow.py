#!/usr/bin/env python3
"""Stage20: narrow SH-2 static product-to-count provenance audit.

Only aggregate metadata is emitted; no proprietary code or source offsets.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, find_guarded_writer_blocks, conditional_branch_target, iso_file_payload
from stage19_writer_argument_flow import producer_argument_patterns

# These SH-2 instruction words encode register operations, not game assets.
PRELUDE = (
    0x655C,  # EXTU.B R5,R5
    0x633C,  # EXTU.B R3,R3
    0xE050,  # MOV #80,R0
    0x253E,  # MULU.W R3,R5 -> MACL
    0x00FC,  # MOV.B @(R0,R15),R0 (stack index +80)
    0x051A,  # STS MACL,R5
    0x8801,  # CMP/EQ #1,R0
    None,    # BF/S skip descriptor block
    0x645D,  # EXTU.W R5,R4 (delay slot)
)


def matching_product_preludes(data: bytes) -> list[dict]:
    """Match contiguous producer prelude and validate same exit as guarded stores."""
    results = []
    for block in find_guarded_writer_blocks(data):
        start = block['start']
        if start < 2 * len(PRELUDE):
            continue
        words = [be16(data, start - len(PRELUDE) * 2 + i * 2)
                 for i in range(len(PRELUDE))]
        if any(actual != expected for actual, expected in zip(words, PRELUDE)
               if expected is not None):
            continue
        branch_offset = start - 4
        if words[7] & 0xFF00 != 0x8F00:
            continue
        if conditional_branch_target(branch_offset, words[7]) != block['exit']:
            continue
        results.append({'block_start': start, 'branch_common_exit': True})
    return results


def count_from_byte_factors(first: int, second: int) -> int:
    """SH-2 unsigned two-byte factors, MULU.W product, then >> 3."""
    if not (0 <= first <= 255 and 0 <= second <= 255):
        raise ValueError('Both arguments must be unsigned bytes')
    return (first * second) >> 3


def summarize_product_flow(data: bytes) -> dict:
    matches = matching_product_preludes(data)
    writer_blocks = [block for block in find_guarded_writer_blocks(data) if block['start'] >= 6]
    stage19 = producer_argument_patterns(data)
    complete_writer_starts = {
        block['start'] for block, item in zip(writer_blocks, stage19)
        if item.get('complete', item.get('complete_argument_flow', False))
    }
    complete_count = sum(match['block_start'] in complete_writer_starts for match in matches)
    return {
        'product_prelude_matches': len(matches),
        'preludes_linked_to_complete_stage19_count_writer': complete_count,
        'unsigned_input_factor_bits': [8, 8] if complete_count else None,
        'condition_source': 'MOV.B @(R0,R15),R0 after MOV #80,R0' if complete_count else None,
        'writer_condition': 'signed_byte_at_sp_plus_80 == 1 and descriptor_count < 512' if complete_count else None,
        'per_source_copy_count_formula': '(u8(R5_before_multiply) * u8(R3_before_multiply)) >> 3' if complete_count else None,
        'mathematical_max_product': 255 * 255 if complete_count else None,
        'mathematical_max_copy_count': count_from_byte_factors(255, 255) if complete_count else None,
        'limitations': [
            'Input factors and stack byte are not traced to a confirmed caller.',
            'Arithmetic bound is not an observed runtime count.',
            'Global uploader copy budget versus per-descriptor count is not reconciled.',
            'The scanner recognizes one contiguous SH-2 opcode signature, not complete control flow.',
            'No code offsets, source bytes, graphics, palettes, audio or video are exported.',
        ],
    }


def analyze(image: Path) -> dict:
    return {
        'schema_version': 1,
        'stage': 'stage20_vdp1_product_to_count',
        'target_file': '0TH2.BIN',
        'analysis': summarize_product_flow(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    rendered = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    else:
        print(rendered)


if __name__ == '__main__':
    main()
