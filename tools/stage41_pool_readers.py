#!/usr/bin/env python3
"""Stage41: independent readers of the same 276-byte slot pool.

Static SH-2 patterns only, not proof that a particular cloned object was
processed in gameplay. Output is aggregate-only; original ISO stays private.
"""
from __future__ import annotations
import argparse
import json
from collections import Counter
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal, CODE_LOAD_BASE
from stage39_writer_function_dispatch import find_writer_entries
from stage40_pool_clone_audit import (
    check_pool_slot_selector, inspect_writer_clone, movw_pc_literal,
)

SCAN_BYTES = 128
FREE_OPS = {
    0x02: 0xE500, 0x04: 0xE62B, 0x06: 0x6341, 0x08: 0x2338,
    0x0A: 0x8B01, 0x0C: 0x000B, 0x0E: 0x6043,
    0x12: 0x7501, 0x14: 0x3563, 0x16: 0x8FF6,
    0x18: 0x343C, 0x1A: 0xE000, 0x1C: 0x000B, 0x1E: 0x0009,
}


def pool_base(data: bytes) -> tuple[int, int, int] | None:
    """Resolve Stage40's writer to the exact 43x276 pool selector."""
    matches = []
    for writer in find_writer_entries(data):
        clone = inspect_writer_clone(data, writer["entry"])
        if clone is None:
            continue
        helper = movl_literal(data, writer["entry"] + 0x68)
        if helper is None:
            continue
        location = helper[1] - CODE_LOAD_BASE
        selector = check_pool_slot_selector(data, location)
        literal = movl_literal(data, location)
        if selector is not None and literal is not None and literal[2] == 5:
            matches.append((literal[1], selector["slot_stride_bytes"],
                            selector["slot_capacity"]))
    return matches[0] if len(matches) == 1 else None


def checked_index_read_sites(data: bytes, base_load: int) -> list[tuple[int, int]]:
    """MOV #126,R0; MOV.W @(R0,R4),R0; CMP/EQ #index,R0."""
    sites = []
    for pos in range(base_load + 2,
                     min(len(data) - 6, base_load + SCAN_BYTES), 2):
        if (be16(data, pos) == 0xE07E
                and be16(data, pos + 2) == 0x004D
                and be16(data, pos + 4) & 0xFF00 == 0x8800):
            sites.append((pos, be16(data, pos + 4) & 0xFF))
    return sites


def marker_before_index(data: bytes, load: int, first_read: int) -> int | None:
    """Verify that the leading word of a pool record is tested first."""
    for pos in range(load + 2, first_read, 2):
        if (be16(data, pos) == 0x6041
                and be16(data, pos + 2) & 0xFF00 == 0x8800
                and be16(data, pos + 4) & 0xFF00 in (0x8B00, 0x8F00)):
            return be16(data, pos + 2) & 0xFF
    return None


def stride_276_after_index(data: bytes, first_read: int) -> bool:
    """Require PC-word 276 and nearby ADD R2/R3,R4 in bounded region."""
    for pos in range(first_read + 4,
                     min(len(data) - 11, first_read + 88), 2):
        word = movw_pc_literal(data, pos)
        if word is None or word[1] != 276:
            continue
        reg = (be16(data, pos) >> 8) & 15
        if reg not in (2, 3):
            continue
        add_opcode = 0x340C | (reg << 4)
        if any(be16(data, pos + offset) == add_opcode
               for offset in (2, 4, 6, 8, 10)):
            return True
    return False


def find_pool_index_readers(data: bytes, base: int) -> list[dict]:
    groups = []
    for pos in range(0, len(data) - 6, 2):
        ref = movl_literal(data, pos)
        if ref is None or ref[1] != base or ref[2] != 4:
            continue
        sites = checked_index_read_sites(data, pos)
        if not sites:
            continue
        marker = marker_before_index(data, pos, sites[0][0])
        if marker is None or not stride_276_after_index(data, sites[0][0]):
            continue
        groups.append({
            "loader": pos, "marker": marker,
            "compares": [value for _, value in sites], "sites": len(sites),
        })
    return groups


def check_unmarked_free_slot_finder(data: bytes, pos: int, base: int) -> bool:
    if pos < 0 or pos & 1 or pos + 0x20 > len(data):
        return False
    literal = movl_literal(data, pos)
    if literal is None or literal[1] != base or literal[2] != 4:
        return False
    if any(be16(data, pos + off) != op for off, op in FREE_OPS.items()):
        return False
    if be16(data, pos + 0x10) & 0xFF00 != 0x9300:
        return False
    stride = movw_pc_literal(data, pos + 0x10)
    return bool(stride and stride[1] == 276)


def find_unmarked_finders(data: bytes, base: int) -> list[int]:
    return [
        pos for pos in range(0, len(data) - 0x20, 2)
        if check_unmarked_free_slot_finder(data, pos, base)
    ]


def summarize_pool_readers(data: bytes) -> dict:
    origin = pool_base(data)
    if origin is None:
        return {
            "verified_cloned_slot_pool": False,
            "limitations": ["No complete Stage40 slot-pool provenance found."],
        }
    base, stride, capacity = origin
    references = [
        pos for pos in range(0, len(data) - 6, 2)
        if (ref := movl_literal(data, pos)) is not None and ref[1] == base
    ]
    groups = find_pool_index_readers(data, base)
    counts = Counter(value for g in groups for value in g["compares"])
    finders = find_unmarked_finders(data, base)
    return {
        "verified_cloned_slot_pool": True,
        "pool_slot_capacity": capacity,
        "pool_stride_bytes": stride,
        "pool_pc_relative_movl_loads": len(references),
        "pool_pc_relative_movl_into_r4": sum(
            (be16(data, pos) >> 8) & 15 == 4 for pos in references
        ),
        "distinct_pool_based_index_reader_groups": len(groups),
        "pool_index_field_offset_bytes": 126 if groups else None,
        "index_word_read_and_immediate_compare_sites":
            sum(g["sites"] for g in groups),
        "first_word_marker_values_examined":
            sorted(g["marker"] for g in groups),
        "index_values_compared_in_matched_readers": sorted(counts),
        "comparison_counts_by_index":
            {str(key): counts[key] for key in sorted(counts)},
        "matched_reader_comparisons_for_cloned_index_38": counts[38],
        "independent_unmarked_free_slot_scanners": len(finders),
        "independent_scan_capacity": 43 if finders else None,
        "independent_scan_stride_bytes": 276 if finders else None,
        "independent_free_scan_returns_slot_without_marking": bool(finders),
        "cloned_index_38_consumed_by_68_entry_dispatcher_proven": False,
        "interpretation": (
            "Four code regions load the same slot-pool base as Stage40, "
            "examine a first-word marker and the word at +126, then walk "
            "276-byte records. Another routine scans 43 slots and returns "
            "a free pointer without marking it. None of the compared values "
            "in these four regions is 38. Shared pool layout does not "
            "establish runtime linkage to the 68-entry dispatcher."
        ),
        "limitations": [
            "Matches are bounded SH-2 opcode patterns, not full CFG coverage.",
            "Per-group comparisons can lie on conditional or unreachable paths.",
            "No index-38 comparison here does not imply none exists elsewhere.",
            "No clone instance pointer has been observed in a Saturn trace.",
            "VDP1 command emission and pixel decoding remain unconfirmed.",
            "No original file offsets, code bytes or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage41_pool_index_readers",
        "target_file": "0TH2.BIN",
        "analysis": summarize_pool_readers(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
