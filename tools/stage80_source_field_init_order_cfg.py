#!/usr/bin/env python3
"""Stage80: CFG coverage of the VDP1 length-source writers and caller order.

Only aggregate evidence is emitted. A static call sequence is not a runtime
trace, and all-writer-exit coverage does not rule out alternate entry paths.
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


def _generic_prologue_candidates(data: bytes) -> list[int]:
    """Find conservative stack-frame starts to bound the analyzed routine."""
    found = []
    for pos in range(0, len(data) - 0x24, 2):
        if be16(data, pos) != 0x2FE6:  # MOV.L R14,@-R15
            continue
        words = [be16(data, pos + offset) for offset in range(2, 0x24, 2)]
        try:
            r13_push = words.index(0x2FD6)
            r12_push = words.index(0x2FC6)
            pr_push = words.index(0x4F22)
        except ValueError:
            continue
        if r13_push < r12_push < pr_push and pr_push <= 0x10:
            found.append(pos)
    return found


def _is_jsr(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x400B


def _is_jmp(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x402B


def _cfg_store_coverage(
    data: bytes,
    entry: int,
    end_bound: int,
    store_sites: set[int],
    max_states: int = 100_000,
) -> dict:
    """Traverse direct SH-2 flow, treating BSR/JSR callees as returning."""
    queue = deque([(entry, False)])
    visited: set[tuple[int, bool]] = set()
    executed_stores: set[int] = set()
    exits: dict[str, set[tuple[int, bool]]] = {
        "rts": set(),
        "rte": set(),
        "tail_branch": set(),
        "indirect_jump": set(),
        "conditional_out_of_bound": set(),
        "fallthrough": set(),
    }

    def apply_delay(pos: int, written: bool) -> bool:
        if pos in store_sites:
            executed_stores.add(pos)
            return True
        return written

    while queue and len(visited) < max_states:
        pos, written = queue.popleft()
        if pos < entry or pos >= end_bound or pos + 2 > len(data):
            exits["fallthrough"].add((pos, written))
            continue
        state = (pos, written)
        if state in visited:
            continue
        visited.add(state)
        if pos in store_sites:
            executed_stores.add(pos)
            written = True

        opcode = be16(data, pos)
        branch = branch_destination(pos, opcode)
        if branch is not None:
            kind, destination = branch
            if kind in ("BRA", "BSR"):
                after_delay = apply_delay(pos + 2, written)
                if kind == "BSR":
                    queue.append((pos + 4, after_delay))
                elif entry <= destination < end_bound:
                    queue.append((destination, after_delay))
                else:
                    exits["tail_branch"].add((pos, after_delay))
                continue
            if kind.endswith("/S"):
                after_delay = apply_delay(pos + 2, written)
                for next_pos in (destination, pos + 4):
                    if entry <= next_pos < end_bound:
                        queue.append((next_pos, after_delay))
                    else:
                        exits["conditional_out_of_bound"].add((pos, after_delay))
                continue
            for next_pos in (destination, pos + 2):
                if entry <= next_pos < end_bound:
                    queue.append((next_pos, written))
                else:
                    exits["conditional_out_of_bound"].add((pos, written))
            continue

        if opcode == 0x000B:  # RTS
            after_delay = apply_delay(pos + 2, written)
            exits["rts"].add((pos, after_delay))
            continue
        if opcode == 0x002B:  # RTE
            after_delay = apply_delay(pos + 2, written)
            exits["rte"].add((pos, after_delay))
            continue
        if _is_jmp(opcode):
            after_delay = apply_delay(pos + 2, written)
            exits["indirect_jump"].add((pos, after_delay))
            continue
        if _is_jsr(opcode):
            after_delay = apply_delay(pos + 2, written)
            queue.append((pos + 4, after_delay))
            continue
        queue.append((pos + 2, written))

    all_exits = set().union(*exits.values())
    return {
        "writer_cfg_states_visited": len(visited),
        "writer_source_store_sites_reached": len(executed_stores),
        "writer_rts_exit_states_after_source_store": sum(
            written for _, written in exits["rts"]
        ),
        "writer_rts_exit_states_without_source_store": sum(
            not written for _, written in exits["rts"]
        ),
        "writer_tail_exit_states_after_source_store": sum(
            written for _, written in exits["tail_branch"]
        ),
        "writer_tail_exit_states_without_source_store": sum(
            not written for _, written in exits["tail_branch"]
        ),
        "writer_indirect_exit_states_without_source_store": sum(
            not written for _, written in exits["indirect_jump"]
        ),
        "writer_other_exit_states_without_source_store": sum(
            not written for key in ("rte", "conditional_out_of_bound", "fallthrough")
            for _, written in exits[key]
        ),
        "writer_all_observed_exit_states_follow_source_store": (
            bool(all_exits) and all(written for _, written in all_exits)
        ),
        "writer_cfg_state_limit_reached": bool(queue),
        "alternate_indirect_entries_excluded": False,
        "callee_memory_side_effects_fully_modeled": False,
    }


def _writer_call_sites(data: bytes, writer_entry: int) -> list[int]:
    writer_address = CODE_LOAD_ADDRESS + writer_entry
    result = set()
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None or literal[1] != writer_address:
            continue
        register = literal[2]
        if be16(data, pos + 2) == (0x400B | (register << 8)):
            result.add(pos + 2)
    return sorted(result)


def _count_followed_by_callback(
    data: bytes, call_sites: list[int], callback_address: int
) -> dict:
    matches = set()
    nop_delays = 0
    for call_pos in call_sites:
        if be16(data, call_pos + 2) == 0x0009:
            nop_delays += 1
        next_load = movl_literal(data, call_pos + 4)
        if next_load is None or next_load[1] != callback_address:
            continue
        if be16(data, call_pos + 6) != (0x400B | (next_load[2] << 8)):
            continue
        matches.add(call_pos)
    return {
        "literal_backed_writer_jsr_sites": len(call_sites),
        "writer_jsr_sites_with_nop_delay_slot": nop_delays,
        "writer_then_callback_id64_jsr_sequences": len(matches),
        "all_observed_writer_calls_followed_by_callback_id64": (
            bool(call_sites) and len(matches) == len(call_sites)
        ),
        "global_callback_order_proven": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    callback_entry, _, callback_chain = _resolve_callback(data)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_chain and callback_entry is not None else None
    )
    store_sites = set(_direct_store_sites(data, LENGTH_SOURCE_GLOBAL))
    prologues = _find_routine_prologues(data)
    candidates = [pos for pos in prologues if store_sites and pos < min(store_sites)]
    writer_entry = max(candidates) if candidates else None
    generic = _generic_prologue_candidates(data)
    following = (
        [pos for pos in generic if writer_entry is not None and pos > writer_entry]
        if writer_entry is not None else []
    )
    end_bound = min(following) if following else None

    cfg = {}
    if writer_entry is not None and end_bound is not None and store_sites:
        cfg = _cfg_store_coverage(data, writer_entry, end_bound, store_sites)
    calls = _writer_call_sites(data, writer_entry) if writer_entry is not None else []
    call_order = (
        _count_followed_by_callback(data, calls, callback_address)
        if callback_address is not None else {
            "literal_backed_writer_jsr_sites": len(calls),
            "writer_jsr_sites_with_nop_delay_slot": 0,
            "writer_then_callback_id64_jsr_sequences": 0,
            "all_observed_writer_calls_followed_by_callback_id64": False,
            "global_callback_order_proven": False,
        }
    )
    return {
        "schema_version": 1,
        "stage": "stage80_source_field_init_order_cfg",
        "target_file": "0TH2.BIN",
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "writer_routine_entry_and_next_boundary_resolved": (
                writer_entry is not None and end_bound is not None
            ),
            "recognized_source_field_store_sites": len(store_sites),
            **cfg,
            **call_order,
            "source_field_initialized_before_all_callback_calls_proven": False,
            "global_length_upper_bound_proven": False,
            "runtime_callback_invocation_confirmed": False,
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
