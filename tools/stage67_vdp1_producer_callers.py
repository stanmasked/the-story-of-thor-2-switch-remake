#!/usr/bin/env python3
"""Stage67: trace static caller relationships for the VDP1 descriptor producer.

The probe emits aggregate metadata only. It is a narrow SH-2 pattern scan, not
a full control-flow graph or a live Saturn execution trace.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage14_vdp1_record_copy_probe import be16, be32, mov_l_pc_target
from stage17_writer_callsite_audit import writer_guard_positions
from stage18_writer_guard_flow import iso_file_payload

GLOBAL_POINTER_TABLE = 0x06088B14
GLOBAL_STATE_OBJECT = 0x06088D14
GLOBAL_COMPARE_WORD = 0x0609BA88
GLOBAL_STATE_FIELD_OFFSET = 0x0098

# Prologue surrounding the Stage16 descriptor-writer candidate. This signature
# is deliberately narrow and is used only to find a likely function boundary.
PRODUCER_PROLOGUE = (
    0x2FE6, 0xE600, 0x2FD6, 0xE05C, 0x2FC6, 0x6D43, 0x2FB6,
    0x2FA6, 0x2F96, 0x2F86, 0x4F22, 0x4F12, 0x7FA8,
)
# Wrapper preserves its incoming R4 pointer in R14 before calling the producer.
WRAPPER_PROLOGUE = (0x2FE6, 0x6E43, 0x2FD6, 0x2FC6, 0x2FB6, 0x4F22)
MOV_R14_TO_R4 = 0x64E3
NOP = 0x0009


def find_pattern(data: bytes, pattern: tuple[int, ...], start: int = 0,
                 end: int | None = None) -> list[int]:
    """Return internal aligned positions of a short instruction signature."""
    if end is None:
        end = len(data)
    width = len(pattern) * 2
    return [
        pos for pos in range(max(0, start), min(end, len(data)) - width + 1, 2)
        if all(be16(data, pos + index * 2) == word
               for index, word in enumerate(pattern))
    ]


def bsr_target(position: int, opcode: int) -> int | None:
    """Resolve the SH-2 BSR signed 12-bit PC-relative target."""
    if position < 0 or position & 1 or opcode & 0xF000 != 0xB000:
        return None
    displacement = opcode & 0x0FFF
    if displacement & 0x0800:
        displacement -= 0x1000
    return position + 4 + displacement * 2


def direct_bsr_callers(data: bytes, target: int) -> list[int]:
    """Find direct BSR instructions targeting one internal candidate entry."""
    return [
        pos for pos in range(0, len(data) - 1, 2)
        if bsr_target(pos, be16(data, pos)) == target
    ]


def mov_w_pc_target(position: int, opcode: int, data_size: int) -> int | None:
    """Resolve SH-2 MOV.W @(disp,PC),Rn."""
    if position < 0 or position & 1 or position + 2 > data_size:
        return None
    if opcode & 0xF000 != 0x9000:
        return None
    target = position + 4 + (opcode & 0x00FF) * 2
    return target if target + 2 <= data_size else None


def find_producer_entries(data: bytes) -> list[int]:
    """Associate the Stage16 writer guard with the nearest preceding prologue."""
    entries: set[int] = set()
    for guard in writer_guard_positions(data):
        lower_bound = max(0, guard - 0x1000)
        candidates = find_pattern(data, PRODUCER_PROLOGUE, lower_bound, guard + 2)
        if candidates:
            entries.add(candidates[-1])
    return sorted(entries)


def find_wrapper_entry(data: bytes, before_position: int) -> int | None:
    """Find the nearest matching wrapper prologue before the first producer call."""
    candidates = find_pattern(
        data, WRAPPER_PROLOGUE, max(0, before_position - 0x800), before_position
    )
    return candidates[-1] if candidates else None


def _literal_reference_before(data: bytes, before: int, register: int,
                              value: int, lookback: int) -> int | None:
    """Find a bounded PC-relative MOV.L reference to a known runtime address."""
    for pos in range(max(0, before - lookback), before, 2):
        opcode = be16(data, pos)
        if opcode & 0xF000 != 0xD000 or ((opcode >> 8) & 0x0F) != register:
            continue
        literal = mov_l_pc_target(pos, opcode, len(data))
        if literal is not None and be32(data, literal) == value:
            return pos
    return None


def classify_wrapper_input(data: bytes, call_position: int) -> str:
    """Classify only three directly observed R4 setup idioms before the wrapper."""
    delay = be16(data, call_position + 2)
    if (
        delay == 0x04AE  # MOV.L @(R0,R10),R4
        and _literal_reference_before(
            data, call_position, 10, GLOBAL_POINTER_TABLE, 24
        ) is not None
    ):
        return "global_pointer_table_lookup_using_R10"
    if (
        delay == 0x044E  # MOV.L @(R0,R4),R4
        and _literal_reference_before(
            data, call_position, 0, GLOBAL_POINTER_TABLE, 16
        ) is not None
        and call_position >= 2
        and be16(data, call_position - 2) == 0x4408  # SHLL2 R4
    ):
        return "global_pointer_table_lookup_using_R4_index"
    if (
        delay == NOP
        and call_position >= 2
        and be16(data, call_position - 2) == 0x54F2  # MOV.L @(8,SP),R4
    ):
        return "caller_stack_SP_plus_8"
    return "other_or_unresolved"


def find_global_field98_guards(data: bytes, producer_entry: int) -> list[dict]:
    """Find the bounded global-field comparison that branches around a producer call.

    The report contains only a count. Exact instruction positions and bytes are
    kept internal to this function and are never serialized.
    """
    matches = []
    for object_load in range(0, len(data) - 1, 2):
        opcode = be16(data, object_load)
        if opcode & 0xF000 != 0xD000 or ((opcode >> 8) & 0x0F) != 4:
            continue
        literal = mov_l_pc_target(object_load, opcode, len(data))
        if literal is None or be32(data, literal) != GLOBAL_STATE_OBJECT:
            continue

        stop = min(len(data) - 2, object_load + 64)
        for compare_load in range(object_load + 2, stop, 2):
            op = be16(data, compare_load)
            if op & 0xF000 != 0xD000 or ((op >> 8) & 0x0F) != 1:
                continue
            target = mov_l_pc_target(compare_load, op, len(data))
            if target is None or be32(data, target) != GLOBAL_COMPARE_WORD:
                continue
            if compare_load + 4 >= len(data) or be16(data, compare_load + 2) != 0x6312:
                continue

            for field_load in range(compare_load + 4, min(stop, compare_load + 16), 2):
                field_op = be16(data, field_load)
                if field_op & 0xF000 != 0x9000 or ((field_op >> 8) & 0x0F) != 0:
                    continue
                field_literal = mov_w_pc_target(field_load, field_op, len(data))
                if field_literal is None or be16(data, field_literal) != GLOBAL_STATE_FIELD_OFFSET:
                    continue
                if (
                    field_load + 10 > len(data)
                    or be16(data, field_load + 2) != 0x024E  # MOV.L @(R0,R4),R2
                    or be16(data, field_load + 4) != 0x3230  # CMP/EQ R3,R2
                ):
                    continue

                branch_position = field_load + 6
                branch = be16(data, branch_position)
                if branch & 0xFF00 != 0x8900:  # BT skips the call when equal
                    continue
                displacement = branch & 0xFF
                if displacement & 0x80:
                    displacement -= 0x100
                branch_target = branch_position + 4 + displacement * 2
                call_position = branch_position + 2
                if (
                    bsr_target(call_position, be16(data, call_position)) == producer_entry
                    and branch_target >= call_position + 4
                ):
                    matches.append({
                        "branch_skips_producer_call_when_field_matches": True,
                    })
    return matches


def find_stack60_descriptor_slot_candidates(data: bytes) -> list[dict]:
    """Find the nested word -> SP+60 -> scaled descriptor-slot address pattern.

    This only establishes the instruction/dataflow sequence. It does not infer
    the semantic type of the 16-bit intermediate value.
    """
    candidates = set()
    for offset_load in range(0, len(data) - 1, 2):
        op = be16(data, offset_load)
        if op & 0xF000 != 0x9000 or ((op >> 8) & 0x0F) != 0:
            continue
        literal = mov_w_pc_target(offset_load, op, len(data))
        if literal is None or be16(data, literal) != 0x00AC:
            continue

        nested_loads = [
            pos for pos in range(offset_load + 2, min(len(data) - 1, offset_load + 14), 2)
            if be16(data, pos) == 0x09DE  # MOV.L @(R0,R13),R9
        ]
        for nested_load in nested_loads:
            stop = min(len(data) - 6, nested_load + 0x180)
            for word_load in range(nested_load + 2, stop, 2):
                if be16(data, word_load) != 0x6291:  # MOV.W @R9,R2
                    continue
                if (
                    be16(data, word_load + 2) != 0xE03C  # MOV #60,R0
                    or be16(data, word_load + 4) != 0x0F25  # MOV.W R2,@(R0,SP)
                ):
                    continue
                store_position = word_load + 4

                read_stop = min(len(data) - 20, store_position + 0x500)
                for stack_read in range(store_position + 2, read_stop, 2):
                    if not (
                        be16(data, stack_read) == 0xE03C
                        and be16(data, stack_read + 2) == 0x6382
                        and be16(data, stack_read + 4) == 0x02FD  # MOV.W @(R0,SP),R2
                    ):
                        continue
                    index_literal_load = stack_read + 6
                    index_op = be16(data, index_literal_load)
                    index_literal = mov_w_pc_target(
                        index_literal_load, index_op, len(data)
                    )
                    if (
                        index_literal is None
                        or be16(data, index_literal) != 0x0098
                        or be16(data, stack_read + 8) != 0x622D  # MOV.W @(R0,R2),R2
                        or be16(data, stack_read + 10) != 0x01DE  # MOV.L @(R0,R13),R1
                        or be16(data, stack_read + 12) != 0x4208  # SHLL2 R2
                        or be16(data, stack_read + 14) != 0x4200  # SHLL R2
                        or be16(data, stack_read + 16) != 0x321C  # ADD R1,R2
                        or be16(data, stack_read + 18) != 0x2322  # MOV.L R3,@R2
                    ):
                        continue
                    candidates.add((offset_load, nested_load, store_position, stack_read))
    return [
        {
            "nested_pointer_field_0xAC": True,
            "stack_slot_SP_plus_60": True,
            "index_field_offset_0x98": True,
            "descriptor_slot_base_field_plus_9": True,
            "index_scale_8": True,
        }
        for _ in candidates
    ]


def summarize(data: bytes) -> dict:
    producer_entries = find_producer_entries(data)
    producer_calls: list[tuple[int, int]] = []
    for entry in producer_entries:
        producer_calls.extend((call, entry) for call in direct_bsr_callers(data, entry))

    wrapper_entries = []
    wrapper_calls: list[tuple[int, int]] = []
    if producer_calls:
        first_call = min(call for call, _ in producer_calls)
        wrapper = find_wrapper_entry(data, first_call)
        if wrapper is not None:
            wrapper_entries.append(wrapper)
            wrapper_calls.extend((call, wrapper) for call in direct_bsr_callers(data, wrapper))

    input_kinds = [
        classify_wrapper_input(data, call) for call, _ in wrapper_calls
    ]
    input_counts = {
        kind: input_kinds.count(kind)
        for kind in (
            "global_pointer_table_lookup_using_R10",
            "global_pointer_table_lookup_using_R4_index",
            "caller_stack_SP_plus_8",
            "other_or_unresolved",
        )
    }
    field_guards = [
        guard
        for entry in producer_entries
        for guard in find_global_field98_guards(data, entry)
    ]
    stack60_chains = find_stack60_descriptor_slot_candidates(data)

    return {
        "descriptor_writer_guard_candidates": len(writer_guard_positions(data)),
        "producer_function_entry_candidates": len(producer_entries),
        "producer_direct_bsr_call_sites": len(producer_calls),
        "producer_calls_forwarding_saved_R14_to_R4": sum(
            be16(data, call + 2) == MOV_R14_TO_R4 for call, _ in producer_calls
        ),
        "producer_direct_calls_inside_wrapper_candidate": sum(
            1 for call, _ in producer_calls
            if wrapper_entries and wrapper_entries[0] < call < min(producer_entries)
        ),
        "wrapper_function_entry_candidates": len(wrapper_entries),
        "wrapper_direct_bsr_caller_sites": len(wrapper_calls),
        "wrapper_input_source_candidate_counts": input_counts,
        "global_state_field_0x98_comparison_candidates": len(field_guards),
        "field_equality_branches_skipping_producer_call": sum(
            item["branch_skips_producer_call_when_field_matches"]
            for item in field_guards
        ),
        "stack_SP_plus_60_nested_pointer_to_descriptor_slot_candidates": len(stack60_chains),
        "descriptor_slot_index_uses_nested_field_plus_0x98": sum(
            item["index_field_offset_0x98"] for item in stack60_chains
        ),
        "descriptor_slot_address_uses_R13_plus_9_and_index_times_8": sum(
            item["descriptor_slot_base_field_plus_9"] and item["index_scale_8"]
            for item in stack60_chains
        ),
        "interpretation": (
            "The descriptor-writer candidate belongs to a function reached by four "
            "direct BSR sites. Each site executes MOV R14,R4 in its delay slot, "
            "forwarding the wrapper's saved input pointer. The wrapper itself has "
            "three direct callers: two bounded patterns fetch an R4 pointer from a "
            "global pointer table, while one loads a pointer from caller SP+8. A "
            "separate static guard compares a global structure field at +0x98 with "
            "a global word and branches around one producer call when they match. "
            "These are static call/data-flow candidates, not runtime observations."
        ),
        "limitations": [
            "The probe uses narrow prologue, BSR and instruction-window signatures, not a complete SH-2 control-flow graph.",
            "Only direct BSR callers are counted; indirect calls and alternate entries may be missed.",
            "The pointer table at 0x06088B14 is runtime data; its actual entries are not available from the executable alone.",
            "The semantic type and lifecycle of the field at global-object offset 0x98 remain unknown.",
            "No runtime values, Saturn frame trace, original code bytes or game resources are emitted.",
            "This tool does not produce a native game engine or Nintendo Switch NRO.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage67_vdp1_producer_callers",
        "target_file": "0TH2.BIN",
        "analysis": summarize(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
