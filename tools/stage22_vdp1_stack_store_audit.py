#!/usr/bin/env python3
"""Stage22: bounded audit of writes to stack byte parameters for the VDP1 uploader.

All report values are aggregate metadata. Exact program offsets and code bytes
are never exported; SP-relative semantic field positions may be reported.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage21_vdp1_stack_sources import matching_stack_source_chains

FRAME_ALLOC_OPCODE = 0x7FA8   # ADD #-88,R15 (SH-2)
STACK_SLOTS = (20, 32, 80)


def direct_stack_stores(data: bytes, start: int, end: int) -> list[tuple[int, int]]:
    """Recognize *certain* direct SP stores with constant offsets.

    A preceding MOV #imm,R0 must be adjacent to indexed stores. This deliberately
    excludes pointer-mediated copies, computed R0 offsets, and unrecognized code.
    """
    stores: list[tuple[int, int]] = []
    for pos in range(max(start, 2), min(end, len(data) - 1), 2):
        word = be16(data, pos)
        previous = be16(data, pos - 2)
        indexed_kind = word & 0xFF0F
        if indexed_kind in (0x0F04, 0x0F05, 0x0F06) and previous & 0xFF00 == 0xE000:
            offset = previous & 0xFF
            if offset < 128:
                width = {0x0F04: 1, 0x0F05: 2, 0x0F06: 4}[indexed_kind]
                stores.append((offset, width))
        elif word & 0xFF00 == 0x1F00:  # MOV.L Rm,@(disp,R15)
            stores.append(((word & 0xF) * 4, 4))
        elif word & 0xFFF0 == 0x8F00:  # MOV.B R0,@(disp,R15)
            stores.append((word & 0xF, 1))
        elif word & 0xFFF0 == 0x8F10:  # MOV.W R0,@(disp,R15)
            stores.append(((word & 0xF) * 2, 2))
    return stores


def count_known_sp_adjustments(data: bytes, start: int, end: int) -> int:
    """Count recognized explicit SP changes; absence is not full proof."""
    count = 0
    for pos in range(start, min(end, len(data) - 1), 2):
        word = be16(data, pos)
        # ADD #imm,R15; MOV.L Rm,@-R15; MOV.L @R15+,Rn;
        # MOV Rm,R15; ADD Rm,R15; SUB Rm,R15.
        if (
            word & 0xFF00 == 0x7F00
            or word & 0xFF0F == 0x2F06
            or word & 0xF0FF == 0x6006 and ((word >> 8) & 0xF) == 15
            or word & 0xF00F == 0x6003 and ((word >> 8) & 0xF) == 15
            or word & 0xFF0F in (0x3F0C, 0x3F08)
        ):
            count += 1
    return count


def find_stack_frame(data: bytes, byte_read_start: int, search_bytes: int = 4096) -> int | None:
    """Locate nearest known 88-byte local allocation preceding source loads."""
    if byte_read_start < 0:
        return None
    begin = max(0, byte_read_start - search_bytes)
    for pos in range(byte_read_start - 2, begin - 1, -2):
        if be16(data, pos) == FRAME_ALLOC_OPCODE:
            return pos
    return None


def saved_register_push_count(data: bytes, frame_offset: int) -> int:
    """Count characteristic longword pushes in the 28 bytes before allocation."""
    return sum(
        be16(data, pos) & 0xFF0F == 0x2F06
        for pos in range(max(0, frame_offset - 28), frame_offset, 2)
    )


def summarize_stack_store_audit(data: bytes) -> dict:
    chains = matching_stack_source_chains(data)
    with_frame = 0
    frame_push_counts = []
    strict_store_totals = []
    slots = {offset: 0 for offset in STACK_SLOTS}
    explicit_sp_adjustments = 0
    for chain in chains:
        byte_read_start = chain['block_start'] - 26  # Stage20 (18B) + Stage21 (8B)
        frame = find_stack_frame(data, byte_read_start)
        if frame is None:
            continue
        with_frame += 1
        frame_push_counts.append(saved_register_push_count(data, frame))
        stores = direct_stack_stores(data, frame + 2, byte_read_start)
        strict_store_totals.append(len(stores))
        explicit_sp_adjustments += count_known_sp_adjustments(data, frame + 2, byte_read_start)
        for offset, width in stores:
            for slot in STACK_SLOTS:
                if offset <= slot < offset + width:
                    slots[slot] += 1
    return {
        'matched_stage21_factor_load_chains': len(chains),
        'chains_with_nearby_88_byte_local_frame_allocation': with_frame,
        'saved_register_push_counts_before_frame_allocation': frame_push_counts,
        'strict_direct_stack_stores_before_factor_loads': strict_store_totals,
        'strict_direct_store_counts_by_stack_slot': {
            f'SP+{slot}': slots[slot] for slot in STACK_SLOTS
        },
        'recognized_sp_adjustments_inside_examined_frame': explicit_sp_adjustments,
        'interpretation': (
            'Two direct stores to SP+80 and zero recognized direct stores to SP+20 '
            'or SP+32 indicate that the writer-enable flag is populated locally, '
            'while both factor slots still require indirect-write or caller analysis. '
            'Zero recognized direct stores is not proof that a slot is uninitialized.'
        ),
        'limitations': [
            'Only a narrow set of direct writes and SP updates is recognized.',
            'Computed-index stores, indirect writes through a saved pointer, and calls are not followed.',
            'The frame is identified by an opcode signature, not full function disassembly.',
            'There are no observed runtime values for the source bytes.',
            'No original program offsets, raw bytes, sprites, palettes or audio are emitted.',
        ],
    }


def analyze(image: Path) -> dict:
    return {
        'schema_version': 1,
        'stage': 'stage22_vdp1_stack_store_audit',
        'target_file': '0TH2.BIN',
        'analysis': summarize_stack_store_audit(iso_file_payload(image)),
    }


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
