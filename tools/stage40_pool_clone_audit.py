#!/usr/bin/env python3
"""Stage40: statically link the writer's slot selection and 276-byte copy.

The Saturn ISO stays local. Only numerical aggregate observations and limits
are exported; no source-program offsets or original protected game bytes.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import CODE_LOAD_BASE, movl_literal
from stage39_writer_function_dispatch import find_writer_entries, validate_returned_object

POOL_OPS = {
    0x02:0xE7FF, 0x04:0xE62B, 0x06:0x6351, 0x08:0x2338,
    0x0A:0x8B04, 0x0C:0x2571,
    0x10:0x0545, 0x12:0x000B, 0x14:0x6053,
    0x16:0x76FF, 0x1A:0x4615, 0x1C:0x8DF3,
    0x1E:0x353C, 0x20:0xE000, 0x22:0x000B, 0x24:0x0009,
}
COPY_OPS = (
    0x6653, 0xE545, 0x75FD, 0x6246, 0x2558, 0x2622, 0x7604,
    0x6246, 0x2622, 0x6246, 0x7604, 0x2622,
    0x8FF4, 0x7604, 0x000B, 0x0009,
)


def movw_pc_literal(data: bytes, pos: int) -> tuple[int, int] | None:
    if pos < 0 or pos & 1 or pos + 2 > len(data):
        return None
    op = be16(data, pos)
    if op & 0xF000 != 0x9000:
        return None
    loc = pos + 4 + 2 * (op & 0xFF)
    if loc + 2 > len(data):
        return None
    val = be16(data, loc)
    return loc, val - 0x10000 if val & 0x8000 else val


def check_pool_slot_selector(data: bytes, start: int) -> dict | None:
    if start < 0 or start & 1 or start + 0x26 > len(data):
        return None
    if be16(data, start) & 0xFF00 != 0xD500:
        return None
    if any(be16(data, start + off) != word for off, word in POOL_OPS.items()):
        return None
    if (be16(data, start + 0x0E) & 0xFF00 != 0x9000
            or be16(data, start + 0x18) & 0xFF00 != 0x9300):
        return None
    init = movw_pc_literal(data, start + 0x0E)
    stride = movw_pc_literal(data, start + 0x18)
    base = movl_literal(data, start)
    if init is None or stride is None or base is None:
        return None
    if init[1] <= 0 or stride[1] <= 0 or stride[1] % 4 or base[2] != 5:
        return None
    # BF branch skips the successful allocation; BT/S loops back to test.
    if (start + 0x0A + 4 + 2 * 4 != start + 0x16
            or start + 0x1C + 4 + 2 * (-13) != start + 0x06):
        return None
    return {
        "slot_capacity": 43,
        "slot_stride_bytes": stride[1],
        "pool_scan_uses_first_word_zero_as_free": True,
        "selected_slot_marked_signed_word_minus_one": True,
        "slot_initialization_word_offset": init[1],
        "failure_returns_null_R0": True,
        "success_returns_slot_pointer_R0": True,
    }


def check_copy_helper(data: bytes, start: int) -> dict | None:
    if (start < 0 or start & 1
            or start + 2 * len(COPY_OPS) > len(data)):
        return None
    if any(be16(data, start + 2 * i) != op
           for i, op in enumerate(COPY_OPS)):
        return None
    return {
        "source_pointer_register": "R4",
        "destination_pointer_register": "R5",
        "long_words_copied": 69,
        "unrolled_words_per_iteration": 3,
        "loop_iterations": 23,
        "copied_bytes": 69 * 4,
        "loop_branch_delay_slot_advances_destination": True,
    }


def inspect_writer_clone(data: bytes, entry: int) -> dict | None:
    if entry < 0 or entry & 1 or entry + 0x90 > len(data):
        return None
    if validate_returned_object(data, entry) is None:
        return None
    first = movl_literal(data, entry + 0x68)
    second = movl_literal(data, entry + 0x78)
    if first is None or second is None or first[2] != 3 or second[2] != 3:
        return None
    pool = check_pool_slot_selector(data, first[1] - CODE_LOAD_BASE)
    copy = check_copy_helper(data, second[1] - CODE_LOAD_BASE)
    if pool is None or copy is None:
        return None
    if pool["slot_stride_bytes"] != copy["copied_bytes"]:
        return None
    if (be16(data, entry + 0x7A) != 0x65E3
            or be16(data, entry + 0x7C) != 0x430B
            or be16(data, entry + 0x7E) != 0x64D3):
        return None
    before = movw_pc_literal(data, entry + 0x66)
    if before is None or be16(data, entry + 0x6A) != 0x430B:
        return None
    return {
        "pool": pool, "copy": copy,
        "first_helper_argument_from_pc_word_literal": True,
        "first_helper_argument": before[1],
        "copy_source": "saved_original_R13",
        "copy_destination": "new_slot_R14_from_nonzero_R0",
        "copied_object_index_updated_to": 38,
    }


def summarize_clone(data: bytes) -> dict:
    matches = [
        result for writer in find_writer_entries(data)
        if (result := inspect_writer_clone(data, writer["entry"])) is not None
    ]
    if not matches:
        return {"complete_pool_copy_writer_chains": 0,
                "limitations": ["No complete pool/copy/writer signature found."]}
    one = matches[0]
    pool, copy = one["pool"], one["copy"]
    return {
        "complete_pool_copy_writer_chains": len(matches),
        "pool_capacity_slots": pool["slot_capacity"],
        "slot_stride_bytes": pool["slot_stride_bytes"],
        "free_slot_first_word_zero_test": pool["pool_scan_uses_first_word_zero_as_free"],
        "selected_slot_marked_minus_one_before_copy":
            pool["selected_slot_marked_signed_word_minus_one"],
        "selected_slot_initial_word_field_offset":
            pool["slot_initialization_word_offset"],
        "null_return_when_no_slot": pool["failure_returns_null_R0"],
        "copy_words": copy["long_words_copied"],
        "copy_bytes": copy["copied_bytes"],
        "copy_iterations": copy["loop_iterations"],
        "copy_source": one["copy_source"],
        "copy_destination": one["copy_destination"],
        "initial_allocator_argument_value": one["first_helper_argument"],
        "copied_object_index_updated_to": one["copied_object_index_updated_to"],
        "copy_size_equals_slot_stride": copy["copied_bytes"] == pool["slot_stride_bytes"],
        "writer_and_later_dispatcher_alias_verified": False,
        "runtime_execution_verified": False,
        "interpretation": (
            "The writer selects one of up to 43 zero-marked pool slots of "
            "276 bytes, copies 69 long words (276 bytes) from the original "
            "R13 structure to the new R14 slot, and then changes the copy "
            "index to 38. Execution and later dispatch are not observed."
        ),
        "limitations": [
            "Pool capacity is not measured live occupancy.",
            "The free-slot markers may be overwritten by the whole-struct copy.",
            "Later callers of this cloned object and VDP1 output remain unproven.",
            "Original program positions and protected assets are never exported.",
        ],
    }


def analyze(path: Path) -> dict:
    return {"schema_version": 1, "stage": "stage40_pool_clone_provenance",
            "target_file": "0TH2.BIN",
            "analysis": summarize_clone(iso_file_payload(path))}


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
