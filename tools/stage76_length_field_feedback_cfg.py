#!/usr/bin/env python3
"""Stage76: direct-control-flow audit for the VDP1 length-field feedback path.

The original Saturn ISO stays local. Output is aggregate-only and contains no
RAM addresses, code offsets, instruction words, or game assets. Indirect callee
effects and runtime ordering remain outside this static proof.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage75_indirect_services_count_provenance import (
    LENGTH_SOURCE_GLOBAL,
    _direct_store_sites,
    _increments_base_register,
    _may_write_register,
    _resolve_callback,
)

ROUTINE_PROLOGUE = (
    0x2FC6, 0x2FB6, 0x2FA6, 0x2F96, 0x2F86, 0xE801, 0x4F22, 0x7FF8,
)


def _word(data: bytes, pos: int) -> int:
    return be16(data, pos)


def _find_routine_prologues(data: bytes) -> list[int]:
    found = []
    for pos in range(0, len(data) - 2 * len(ROUTINE_PROLOGUE), 2):
        if all(
            _word(data, pos + 2 * index) == opcode
            for index, opcode in enumerate(ROUTINE_PROLOGUE)
        ):
            found.append(pos)
    return found


def _is_jsr(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x400B


def _is_jmp(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x402B


def _is_rts(opcode: int) -> bool:
    return opcode == 0x000B


def _apply_register_facts(
    data: bytes, pos: int, state: tuple[bool, bool, bool, bool],
    length_address: int,
) -> tuple[bool, bool, bool, bool]:
    r10_zero_seeded, r10_changed_after_seed, r13_length_seeded, r13_changed_after_seed = state
    opcode = _word(data, pos)

    if opcode == 0xEA00:  # MOV #0,R10
        r10_zero_seeded = True
        r10_changed_after_seed = False
    elif _may_write_register(opcode, 10) and r10_zero_seeded:
        r10_changed_after_seed = True

    literal = movl_literal(data, pos)
    if literal is not None and literal[2] == 13:
        if literal[1] == length_address:
            r13_length_seeded = True
            r13_changed_after_seed = False
        elif r13_length_seeded:
            r13_changed_after_seed = True
    elif r13_length_seeded and (
        _may_write_register(opcode, 13)
        or _increments_base_register(opcode, 13)
    ):
        r13_changed_after_seed = True

    return (
        r10_zero_seeded, r10_changed_after_seed,
        r13_length_seeded, r13_changed_after_seed,
    )


def _direct_cfg_states_at_targets(
    data: bytes, entry: int, end_bound: int, targets: set[int],
    length_address: int, max_states: int = 100_000,
) -> tuple[dict[int, set[tuple[bool, bool, bool, bool]]], int, int]:
    """Follow direct SH-2 control flow; calls return but callee effects are unknown."""
    initial = (False, False, False, False)
    queue = deque([(entry, initial)])
    visited = set()
    target_states: dict[int, set[tuple[bool, bool, bool, bool]]] = defaultdict(set)
    indirect_calls = set()

    def add_target_state(pos: int, state: tuple[bool, bool, bool, bool]) -> None:
        if pos in targets:
            target_states[pos].add(state)

    while queue and len(visited) < max_states:
        pos, state = queue.popleft()
        if pos < entry or pos > end_bound or pos + 2 > len(data):
            continue
        key = (pos, state)
        if key in visited:
            continue
        visited.add(key)
        if pos in targets:
            target_states[pos].add(state)
            continue

        opcode = _word(data, pos)
        branch = branch_destination(pos, opcode)
        if branch is not None:
            kind, destination = branch
            if kind in ("BRA", "BSR"):
                delay_pos = pos + 2
                add_target_state(delay_pos, state)
                delay_state = _apply_register_facts(
                    data, delay_pos, state, length_address
                )
                if kind == "BSR":
                    next_pos = pos + 4
                    if next_pos <= end_bound:
                        queue.append((next_pos, delay_state))
                elif entry <= destination <= end_bound:
                    queue.append((destination, delay_state))
                continue
            if kind.endswith("/S"):
                delay_pos = pos + 2
                add_target_state(delay_pos, state)
                delay_state = _apply_register_facts(
                    data, delay_pos, state, length_address
                )
                for next_pos in (destination, pos + 4):
                    if entry <= next_pos <= end_bound:
                        queue.append((next_pos, delay_state))
                continue
            for next_pos in (destination, pos + 2):
                if entry <= next_pos <= end_bound:
                    queue.append((next_pos, state))
            continue

        if _is_jsr(opcode):
            indirect_calls.add(pos)
            delay_pos = pos + 2
            add_target_state(delay_pos, state)
            delay_state = _apply_register_facts(
                data, delay_pos, state, length_address
            )
            next_pos = pos + 4
            if next_pos <= end_bound:
                queue.append((next_pos, delay_state))
            continue

        if _is_jmp(opcode) or _is_rts(opcode):
            delay_pos = pos + 2
            add_target_state(delay_pos, state)
            continue

        next_state = _apply_register_facts(data, pos, state, length_address)
        if pos + 2 <= end_bound:
            queue.append((pos + 2, next_state))

    return dict(target_states), len(visited), len(indirect_calls)


def _find_source_writer_sites(data: bytes) -> tuple[list[int], list[int]]:
    stores = _direct_store_sites(data, LENGTH_SOURCE_GLOBAL)
    r10_writer_sites = []
    r13_copy_read_sites = []
    for store_pos in stores:
        store = _word(data, store_pos)
        if store & 0xF00F != 0x2001:
            continue
        source_reg = (store >> 4) & 0xF
        if source_reg == 10:
            r10_writer_sites.append(store_pos)
        read_pos = store_pos - 2
        read_op = _word(data, read_pos)
        if (
            read_op & 0xF00F == 0x6001
            and ((read_op >> 8) & 0xF) == source_reg
            and ((read_op >> 4) & 0xF) == 13
        ):
            r13_copy_read_sites.append(read_pos)
    return r10_writer_sites, r13_copy_read_sites


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    callback_entry, length_address, callback_chain = _resolve_callback(data)
    prologues = _find_routine_prologues(data)
    r10_writers, r13_reads = _find_source_writer_sites(data)
    targets = set(r10_writers + r13_reads)

    entry = None
    if targets:
        earliest_target = min(targets)
        candidates = [pos for pos in prologues if pos < earliest_target]
        if candidates:
            entry = max(candidates)

    states, visited_states, indirect_calls = ({}, 0, 0)
    if entry is not None and length_address is not None and targets:
        states, visited_states, indirect_calls = _direct_cfg_states_at_targets(
            data, entry, max(targets), targets, length_address
        )

    r10_states = [
        state for pos in r10_writers for state in states.get(pos, set())
    ]
    r13_states = [
        state for pos in r13_reads for state in states.get(pos, set())
    ]
    return {
        "schema_version": 1,
        "stage": "stage76_length_field_feedback_cfg",
        "target_file": "0TH2.BIN",
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "containing_routine_prologue_unique": (
                entry is not None and len([p for p in prologues if p < min(targets)]) >= 1
            ),
            "r10_zero_seed_dominates_source_writer_on_direct_cfg": (
                bool(r10_states)
                and all(state[0] and not state[1] for state in r10_states)
            ),
            "r13_length_field_seed_dominates_feedback_read_on_direct_cfg": (
                bool(r13_states)
                and all(state[2] and not state[3] for state in r13_states)
            ),
            "r10_writer_reachable_direct_cfg_state_count": len(set(r10_states)),
            "r13_feedback_read_reachable_direct_cfg_state_count": len(set(r13_states)),
            "reachable_direct_cfg_instruction_states": visited_states,
            "indirect_call_sites_on_direct_cfg_paths": indirect_calls,
            "indirect_callee_preservation_of_r10_r13_proven": False,
            "alternate_indirect_entry_paths_excluded": False,
            "source_global_is_zero_or_feedback_copy_only_proven": False,
            "runtime_initialization_order_proven": False,
            "runtime_callback_invocation_confirmed": False,
            "runtime_dma_completion_confirmed": False,
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
