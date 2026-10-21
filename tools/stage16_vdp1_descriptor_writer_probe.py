#!/usr/bin/env python3
"""Stage 16: identify code that appends VDP1 descriptors to the staging buffer.

The analyzer emits aggregate metadata only. It does not export source offsets,
raw code bytes, or original game assets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage03_index_tables import MAX_PROBE_BYTES
from stage14_vdp1_record_copy_probe import be16, be32, mov_l_pc_target
from stage15_vdp1_callsite_probe import (
    BUFFER_POINTER_SLOT_ADDRESS,
    DESCRIPTOR_BUFFER_ADDRESS,
    TOTAL_RECORD_COUNT_ADDRESS,
    pc_relative_reference_count,
)

CAPACITY_ENTRIES = 0x0200


def mov_w_pc_target(instruction_offset: int, opcode: int, data_size: int) -> int | None:
    """Resolve SH-2 MOV.W @(disp,PC),Rn using its PC+4 relative address."""
    if instruction_offset < 0 or instruction_offset + 2 > data_size:
        return None
    if opcode & 0xF000 != 0x9000:
        return None
    target = instruction_offset + 4 + (opcode & 0x00FF) * 2
    if target < 0 or target + 2 > data_size:
        return None
    return target


def find_next_opcode(data: bytes, start: int, stop: int, expected: int) -> int | None:
    """Find an opcode in a bounded forward window; returned offsets stay internal."""
    for offset in range(start, min(stop, len(data) - 1) + 1, 2):
        if be16(data, offset) == expected:
            return offset
    return None


def find_counter_load(data: bytes, start: int, stop: int) -> int | None:
    """Find MOV.L PC,R3 resolving to the shared total-record counter."""
    for offset in range(start, min(stop, len(data) - 1) + 1, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000 or ((opcode >> 8) & 0x0F) != 3:
            continue
        target = mov_l_pc_target(offset, opcode, len(data))
        if target is not None and be32(data, target) == TOTAL_RECORD_COUNT_ADDRESS:
            return offset
    return None


def descriptor_writer_candidates(data: bytes) -> list[dict]:
    """Recognize the capacity guard, 4/2/2 writes, count increment and pointer advance."""
    candidates = []
    for guard_offset in range(0, len(data) - 10, 2):
        count_load = be16(data, guard_offset)
        if count_load & 0xF000 != 0xD000 or ((count_load >> 8) & 0x0F) != 3:
            continue
        count_literal = mov_l_pc_target(guard_offset, count_load, len(data))
        if count_literal is None or be32(data, count_literal) != TOTAL_RECORD_COUNT_ADDRESS:
            continue
        if be16(data, guard_offset + 2) != 0x6231:  # MOV.W @R3,R2
            continue

        capacity_load_offset = guard_offset + 4
        capacity_load = be16(data, capacity_load_offset)
        capacity_literal = mov_w_pc_target(capacity_load_offset, capacity_load, len(data))
        if capacity_literal is None or be16(data, capacity_literal) != CAPACITY_ENTRIES:
            continue
        if be16(data, guard_offset + 6) != 0x3213:  # CMP/GE R1,R2
            continue
        branch = be16(data, guard_offset + 8)
        if branch & 0xFF00 != 0x8900:  # BT skips writer when count >= capacity
            continue

        window_start = guard_offset + 10
        window_stop = min(len(data) - 2, guard_offset + 112)
        initial_pointer_load = find_next_opcode(data, window_start, window_stop, 0x6382)
        source_store = find_next_opcode(data, window_start, window_stop, 0x2322)
        if initial_pointer_load is None or source_store is None or initial_pointer_load >= source_store:
            continue

        destination_pointer_load = find_next_opcode(data, source_store + 2, window_stop, 0x6382)
        if destination_pointer_load is None:
            continue
        add_four = find_next_opcode(data, destination_pointer_load + 2, window_stop, 0x7304)
        if add_four is None:
            continue
        destination_store = find_next_opcode(data, add_four + 2, window_stop, 0x2301)
        if destination_store is None:
            continue

        count_pointer_load = find_next_opcode(data, destination_store + 2, window_stop, 0x6382)
        if count_pointer_load is None:
            continue
        add_six = find_next_opcode(data, count_pointer_load + 2, window_stop, 0x7306)
        if add_six is None:
            continue
        per_source_count_store = find_next_opcode(data, add_six + 2, window_stop, 0x2321)
        if per_source_count_store is None:
            continue

        counter_update = find_counter_load(data, per_source_count_store + 2, window_stop)
        if counter_update is None or counter_update + 6 >= len(data):
            continue
        if not (
            be16(data, counter_update + 2) == 0x6131
            and be16(data, counter_update + 4) == 0x7101
            and be16(data, counter_update + 6) == 0x2311
        ):
            continue

        advanced_pointer_load = find_next_opcode(data, counter_update + 8, window_stop, 0x6382)
        if advanced_pointer_load is None or advanced_pointer_load + 4 >= len(data):
            continue
        if not (
            be16(data, advanced_pointer_load + 2) == 0x7308
            and be16(data, advanced_pointer_load + 4) == 0x2832
        ):
            continue

        # The source address is base + index*8; the per-source count is the R5 value >> 3.
        source_scale = False
        for offset in range(initial_pointer_load + 2, source_store, 2):
            if (
                be16(data, offset) == 0x4208
                and offset + 4 < source_store
                and be16(data, offset + 2) == 0x4200
                and be16(data, offset + 4) == 0x321C
            ):
                source_scale = True
                break
        argument_copy = find_next_opcode(data, source_store + 2, per_source_count_store, 0x6243)
        right_shifts = (
            sum(
                be16(data, offset) == 0x4221
                for offset in range(argument_copy + 2, per_source_count_store, 2)
            )
            if argument_copy is not None else 0
        )
        candidates.append({
            "capacity_entries": be16(data, capacity_literal),
            "source_scale_confirmed": source_scale,
            "per_source_count_shift_right_count": right_shifts,
            "descriptor_fields_confirmed": True,
            "counter_increment_confirmed": True,
            "pointer_advance_confirmed": True,
        })
    return candidates


def summarize_writer_analysis(data: bytes) -> dict:
    """Return the descriptor-writer findings without exact source offsets."""
    candidates = descriptor_writer_candidates(data)
    return {
        "descriptor_writer_candidate_count": len(candidates),
        "buffer_pointer_slot_runtime_address": f"0x{BUFFER_POINTER_SLOT_ADDRESS:08X}",
        "descriptor_buffer_runtime_address": f"0x{DESCRIPTOR_BUFFER_ADDRESS:08X}",
        "total_record_budget_runtime_address": f"0x{TOTAL_RECORD_COUNT_ADDRESS:08X}",
        "buffer_pointer_slot_literal_reference_count": pc_relative_reference_count(
            data, BUFFER_POINTER_SLOT_ADDRESS
        ),
        "descriptor_buffer_literal_reference_count": pc_relative_reference_count(
            data, DESCRIPTOR_BUFFER_ADDRESS
        ),
        "total_record_budget_literal_reference_count": pc_relative_reference_count(
            data, TOTAL_RECORD_COUNT_ADDRESS
        ),
        "descriptor_capacity_entries": candidates[0]["capacity_entries"] if candidates else None,
        "descriptor_entry_size_bytes": 8 if candidates else None,
        "descriptor_field_offsets_bytes": [0, 4, 6] if candidates else [],
        "source_address_uses_base_plus_index_times_eight": bool(
            candidates and candidates[0]["source_scale_confirmed"]
        ),
        "per_source_count_is_r5_value_shifted_right_by_three": bool(
            candidates and candidates[0]["per_source_count_shift_right_count"] == 3
        ),
        "global_budget_incremented_once_per_descriptor": bool(
            candidates and candidates[0]["counter_increment_confirmed"]
        ),
        "buffer_pointer_advanced_by_eight_bytes": bool(
            candidates and candidates[0]["pointer_advance_confirmed"]
        ),
        "accounting_invariant_needs_r5_dataflow_validation": bool(
            candidates and candidates[0]["per_source_count_shift_right_count"] == 3
        ),
        "interpretation": (
            "A candidate writer fills an 8-byte staging descriptor: a 32-bit source address, "
            "a 16-bit destination cursor at +4, and a 16-bit per-source record count at +6. "
            "It increments the shared counter once and advances the descriptor pointer by 8. "
            "The per-source count is calculated from an input shifted right by three. Because "
            "the upload routine decrements its shared budget for each 32-byte copy, callers "
            "must be traced to confirm whether this writer always emits one copy per descriptor "
            "or whether another accounting path is involved."
        ),
        "limitations": [
            "The analyzer recognizes a narrow instruction sequence, not all SH-2 control flow.",
            "The descriptor buffer is runtime memory; its actual values are not reconstructed here.",
            "The source-address base table and destination-cursor semantics remain only partially understood.",
            "No exact source offsets, original bytes, textures, palettes, audio, or video are emitted.",
            "No native game engine or Nintendo Switch NRO is produced.",
        ],
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    target = next(
        (entry for entry in disc["game_files"] if entry["path"].upper() == "/0TH2.BIN"),
        None,
    )
    if target is None:
        raise ValueError("Expected /0TH2.BIN in the ISO root directory")
    if target["size_bytes"] > MAX_PROBE_BYTES:
        raise ValueError("/0TH2.BIN exceeds the safe probe size")

    with image.open("rb") as stream:
        stream.seek(target["extent_sector"] * SECTOR)
        data = stream.read(target["size_bytes"])
    if len(data) != target["size_bytes"]:
        raise ValueError("Short read from /0TH2.BIN")

    return {
        "schema_version": 1,
        "stage": "stage16_vdp1_descriptor_writer",
        "disc_sha256": disc["sha256"],
        "disc_product": disc["saturn_header"]["product"],
        "target_file": target["path"],
        "target_file_size_bytes": target["size_bytes"],
        "analysis": summarize_writer_analysis(data),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Private local Sega Saturn ISO")
    parser.add_argument("-o", "--output", type=Path, help="Metadata-only JSON output path")
    args = parser.parse_args()
    output = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print("Stage 16 metadata-only report saved:", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
