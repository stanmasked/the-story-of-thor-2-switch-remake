#!/usr/bin/env python3
"""Stage36: check two SH-2 signed-word indexed indirect function dispatches.

The owner's Saturn ISO is processed privately. Output contains only aggregate
metadata, not the program's source byte positions or game assets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import (
    CODE_LOAD_BASE, discover_inner_wrappers, find_tail_callers,
    find_table_runs, movl_literal,
)

INDEX_FIELD_BYTE_OFFSET = 126
FUNCTION_POINTER_WIDTH = 4


def signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def index_slot(index: int, anchor_index: int, entries: int) -> int | None:
    """Mathematical address bounds, NOT an observed game bounds guard."""
    if entries < 1 or not 0 <= anchor_index < entries:
        raise ValueError("invalid table shape")
    effective = anchor_index + signed16(index)
    return effective if 0 <= effective < entries else None


def _pointer_table(data: bytes) -> dict | None:
    chains = [
        table for wrapper in discover_inner_wrappers(data)
        for caller in find_tail_callers(data, wrapper["entry"])
        for table in find_table_runs(data, caller["entry"])
    ]
    return max(chains, key=lambda item: item["entries"]) if chains else None


def match_indexed_dispatch(data: bytes, literal_pos: int,
                           pointer_address: int) -> dict | None:
    """Match the two observed SH-2 signed-word-indexed JMP patterns.

    Both read signed16 from R14+126, multiply the index by four and load an
    indirect code pointer. The second also restores R12 and R13 before JMP;
    both restore R14 in the branch delay slot. This does not prove reachability.
    """
    if literal_pos < 12 or literal_pos & 1 or literal_pos + 12 > len(data):
        return None
    literal = movl_literal(data, literal_pos)
    if literal is None or literal[1] != pointer_address or literal[2] != 0:
        return None

    def at(relative: int) -> int:
        return be16(data, literal_pos + relative)

    base_form = (
        at(-10) == 0xE07E  # offset in bytes
        and at(-8) == 0x4F26
        and at(-6) == 0x64E3
        and at(-4) == 0x02ED  # MOV.W @(R0,R14),R2
        and at(-2) == 0x4208  # SHLL2 R2
        and at(2) == 0x032E   # MOV.L @(R0,R2),R3
        and at(4) == 0x432B   # JMP @R3
        and at(6) == 0x6EF6  # restore R14 in delay slot
    )
    selected_cell_form = (
        at(-12) == 0x64E3
        and at(-10) == 0xE07E
        and at(-8) == 0x4F26
        and at(-6) == 0x64E3
        and at(-4) == 0x03ED  # MOV.W @(R0,R14),R3
        and at(-2) == 0x4308  # SHLL2 R3
        and at(2) == 0x023E   # MOV.L @(R0,R3),R2
        and at(4) == 0x6CF6  # restore R12
        and at(6) == 0x6DF6  # restore R13
        and at(8) == 0x422B   # JMP @R2
        and at(10) == 0x6EF6 # restore R14 in delay slot
    )
    if not (base_form or selected_cell_form):
        return None
    return {
        "index_register": 2 if base_form else 3,
        "jump_register": 3 if base_form else 2,
        "index_pointer_register_at_read": 14,
        "epilogue": ("immediate_jmp_r14_delay" if base_form
                     else "r12_r13_then_jmp_r14_delay"),
        "index_width_bits": 16,
        "index_signed": True,
        "index_scale_bytes": FUNCTION_POINTER_WIDTH,
    }


def scan_dispatches(data: bytes) -> dict:
    table = _pointer_table(data)
    if table is None:
        return {"complete_dispatch_patterns": 0, "linked_pointer_table": False,
                "limitations": ["No complete table-to-wrapper signature was found."]}
    size = table["entries"]
    selected = table["entry_index_zero_based"]
    anchors = (
        ("table_start", CODE_LOAD_BASE + table["table_start"], 0),
        ("selected_function_cell", CODE_LOAD_BASE + table["entry_cell"], selected),
    )
    findings = []
    for name, ptr, origin in anchors:
        for pos in range(12, len(data) - 12, 2):
            matched = match_indexed_dispatch(data, pos, ptr)
            if matched is not None:
                findings.append({"anchor": name, "origin": origin, **matched})

    return {
        "linked_pointer_table": True,
        "table_entry_count": size,
        "selected_function_slot_one_based": selected + 1,
        "complete_dispatch_patterns": len(findings),
        "dispatches_using_table_start": sum(
            x["anchor"] == "table_start" for x in findings),
        "dispatches_using_selected_cell": sum(
            x["anchor"] == "selected_function_cell" for x in findings),
        "shared_signed_index_field_byte_offset":
            INDEX_FIELD_BYTE_OFFSET if findings else None,
        "index_source": "signed16(memory[R14+126])" if findings else None,
        "index_shift_left_bits": 2 if findings else None,
        "table_pointer_stride_bytes": FUNCTION_POINTER_WIDTH if findings else None,
        "dispatch_epilogue_forms": sorted(set(x["epilogue"] for x in findings)),
        "both_dispatches_read_index_from_saved_r14": (
            len(findings) == 2
            and all(x["index_pointer_register_at_read"] == 14 for x in findings)
        ),
        "valid_index_ranges_as_mathematical_model": {
            "table_start": [0, size - 1],
            "selected_function_cell": [-selected, size - selected - 1],
        } if findings else {},
        "index_to_select_outer_function": {
            "table_start": selected,
            "selected_function_cell": 0,
        } if findings else {},
        "local_index_bounds_guard_verified": False,
        "limitations": [
            "The reported ranges are mathematical table bounds, not observed game checks.",
            "No full caller CFG has been reconstructed; earlier bounds checks may exist.",
            "Two matching dispatch suffixes are not all indirect jumps in the game.",
            "The table may contain addresses never selected during gameplay.",
            "No runtime index values, VDP1 command emission or pixel decoder are confirmed.",
            "No executable offsets, original program bytes or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage36_signed_index_dispatch",
        "target_file": "0TH2.BIN",
        "analysis": scan_dispatches(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
