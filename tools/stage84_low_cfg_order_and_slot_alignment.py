#!/usr/bin/env python3
"""Stage84: direct-CFG ordering for an unpaired callback/writer pair in TH2.LOW.

Also checks whether raw service-slot byte matches are aligned longword entries.
No offsets, instruction words, or game payload bytes are emitted.
"""
from __future__ import annotations

import argparse
import json
from collections import deque
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import (
    LENGTH_SOURCE_GLOBAL,
    _direct_store_sites,
    _resolve_callback,
)
from stage76_length_field_feedback_cfg import _find_routine_prologues
from stage81_callback64_callsite_census import literal_backed_jsr_sites
from stage83_unpaired_callback_context_audit import generic_prologue_candidates

SERVICE_SLOT_A = 0x06000300
SERVICE_SLOT_B = 0x06000310


def _is_jsr(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x400B


def _is_jmp(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x402B


def _cfg_pair_order(
    data: bytes,
    entry: int,
    end_bound: int,
    callback_site: int,
    writer_site: int,
    max_states: int = 100_000,
) -> dict:
    queue = deque([(entry, False, False)])
    visited: set[tuple[int, bool, bool]] = set()
    callback_writer_states: set[bool] = set()
    writer_callback_states: set[bool] = set()
    exits: set[tuple[int, bool, bool]] = set()

    def mark_site(pos: int, writer_seen: bool, callback_seen: bool):
        if pos == callback_site:
            callback_writer_states.add(writer_seen)
            callback_seen = True
        if pos == writer_site:
            writer_callback_states.add(callback_seen)
            writer_seen = True
        return writer_seen, callback_seen

    def delay_state(pos: int, writer_seen: bool, callback_seen: bool):
        return mark_site(pos, writer_seen, callback_seen)

    while queue and len(visited) < max_states:
        pos, writer_seen, callback_seen = queue.popleft()
        if pos < entry or pos >= end_bound or pos + 2 > len(data):
            exits.add((pos, writer_seen, callback_seen))
            continue
        state = (pos, writer_seen, callback_seen)
        if state in visited:
            continue
        visited.add(state)
        writer_seen, callback_seen = mark_site(
            pos, writer_seen, callback_seen
        )

        opcode = be16(data, pos)
        branch = branch_destination(pos, opcode)
        if branch is not None:
            kind, destination = branch
            if kind in ("BRA", "BSR"):
                after_writer, after_callback = delay_state(
                    pos + 2, writer_seen, callback_seen
                )
                if kind == "BSR":
                    queue.append((pos + 4, after_writer, after_callback))
                elif entry <= destination < end_bound:
                    queue.append((destination, after_writer, after_callback))
                else:
                    exits.add((pos, after_writer, after_callback))
                continue
            if kind.endswith("/S"):
                after_writer, after_callback = delay_state(
                    pos + 2, writer_seen, callback_seen
                )
                for next_pos in (destination, pos + 4):
                    if entry <= next_pos < end_bound:
                        queue.append((next_pos, after_writer, after_callback))
                    else:
                        exits.add((pos, after_writer, after_callback))
                continue
            for next_pos in (destination, pos + 2):
                if entry <= next_pos < end_bound:
                    queue.append((next_pos, writer_seen, callback_seen))
                else:
                    exits.add((pos, writer_seen, callback_seen))
            continue

        if opcode in (0x000B, 0x002B) or _is_jmp(opcode):
            after_writer, after_callback = delay_state(
                pos + 2, writer_seen, callback_seen
            )
            exits.add((pos, after_writer, after_callback))
            continue
        if _is_jsr(opcode):
            after_writer, after_callback = delay_state(
                pos + 2, writer_seen, callback_seen
            )
            queue.append((pos + 4, after_writer, after_callback))
            continue
        queue.append((pos + 2, writer_seen, callback_seen))

    return {
        "candidate_function_cfg_states_visited": len(visited),
        "callback_reached_with_writer_already_seen": (
            callback_writer_states == {True}
        ),
        "callback_reached_without_writer_already_seen": (
            False in callback_writer_states
        ),
        "writer_reached_after_callback_on_a_direct_path": (
            True in writer_callback_states
        ),
        "writer_reached_without_prior_callback_on_a_direct_path": (
            False in writer_callback_states
        ),
        "callback_reachability_states": len(callback_writer_states),
        "writer_reachability_states": len(writer_callback_states),
        "cfg_state_limit_reached": bool(queue),
        "indirect_callee_memory_effects_modeled": False,
        "alternate_function_entries_excluded": False,
    }


def _raw_alignment_summary(data: bytes, value: int) -> dict:
    needle = value.to_bytes(4, "big")
    positions = []
    offset = 0
    while True:
        offset = data.find(needle, offset)
        if offset < 0:
            break
        positions.append(offset)
        offset += 1
    literal_pool_positions = set()
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is not None:
            literal_pool_positions.add(literal[0])
    return {
        "raw_big_endian_occurrences": len(positions),
        "occurrences_aligned_to_halfword": sum(pos % 2 == 0 for pos in positions),
        "occurrences_aligned_to_longword": sum(pos % 4 == 0 for pos in positions),
        "occurrences_used_as_pc_literal_pool_words": sum(
            pos in literal_pool_positions for pos in positions
        ),
        "raw_occurrences_prove_pointer_table": False,
    }


def _later_writer_pairs(
    data: bytes,
    callback_sites: list[int],
    writer_sites: list[int],
    prologues: list[int],
) -> list[tuple[int, int, int, int]]:
    writer_set = set(writer_sites)
    result = []
    for callback in callback_sites:
        if callback - 6 in writer_set:
            continue
        previous = [pos for pos in prologues if pos < callback]
        following = [pos for pos in prologues if pos > callback]
        if not previous:
            continue
        entry = max(previous)
        end_bound = min(following) if following else len(data)
        for writer in writer_sites:
            if callback < writer < end_bound and entry <= writer:
                result.append((entry, end_bound, callback, writer))
    return result


def analyze(image: Path) -> dict:
    main_data = iso_file_payload(image, b"0TH2.BIN")
    low_data = iso_file_payload(image, b"TH2.LOW")
    callback_entry, _, callback_chain = _resolve_callback(main_data)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_chain and callback_entry is not None else None
    )
    stores = set(_direct_store_sites(main_data, LENGTH_SOURCE_GLOBAL))
    prologues = _find_routine_prologues(main_data)
    entries = [pos for pos in prologues if stores and pos < min(stores)]
    writer_entry = max(entries) if entries else None
    writer_address = (
        CODE_LOAD_ADDRESS + writer_entry if writer_entry is not None else None
    )
    if callback_address is None or writer_address is None:
        return {
            "schema_version": 1,
            "stage": "stage84_low_cfg_order_and_slot_alignment",
            "analysis": {
                "callback_id64_chain_verified": callback_chain,
                "targets_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    callback_sites = literal_backed_jsr_sites(low_data, callback_address)
    writer_sites = literal_backed_jsr_sites(
        low_data, writer_address
    )
    intervals = _later_writer_pairs(
        low_data, callback_sites, writer_sites,
        generic_prologue_candidates(low_data),
    )
    pair_cfg = {}
    if len(intervals) == 1:
        entry, end_bound, callback_site, writer_site = intervals[0]
        pair_cfg = _cfg_pair_order(
            low_data, entry, end_bound, callback_site, writer_site
        )
    return {
        "schema_version": 1,
        "stage": "stage84_low_cfg_order_and_slot_alignment",
        "target_files": ["0TH2.BIN", "TH2.LOW"],
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "targets_resolved": True,
            "unpaired_callback_later_writer_intervals_found": len(intervals),
            **pair_cfg,
            "low_service_slot_a": _raw_alignment_summary(
                low_data, SERVICE_SLOT_A
            ),
            "low_service_slot_b": _raw_alignment_summary(
                low_data, SERVICE_SLOT_B
            ),
            "source_initialized_before_all_callback_reads_proven": False,
            "global_length_upper_bound_proven": False,
            "runtime_callback_execution_confirmed": False,
            "runtime_dma_completion_confirmed": False,
            "same_frame_submit_timing_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
        },
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
        print(rendered, end="")


if __name__ == "__main__":
    main()
