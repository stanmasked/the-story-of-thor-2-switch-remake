#!/usr/bin/env python3
"""Stage90: bounded direct-CFG audit for non-prologue leaf-return candidates.

Delay slots are included in the executed-instruction count. Indirect jumps and
out-of-bound branches are reported as exits, not guessed. Calls are modeled as
returning; callee side effects and register values are not modeled.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict, deque
from pathlib import Path

from stage18_writer_guard_flow import be16
from stage35_table_tail_link import branch_destination
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage86_set_module_signature_audit import read_root_payloads
from stage87_set_filename_loader_context import _is_jsr
from stage88_filename_helper_callchain import (
    _first_preserved_filename_call,
    _function_end,
    _resolve_call_sites,
)
from stage89_leaf_entry_shape_audit import classify_target_entry


def audit_direct_cfg(
    data: bytes, entry: int, end: int, max_states: int = 10000
) -> dict:
    queue = deque([entry])
    nodes: set[int] = set()
    delay_slots: set[int] = set()
    edges: dict[int, set[int]] = defaultdict(set)
    rts_sites: set[int] = set()
    exits: Counter[str] = Counter()
    call_sites: set[int] = set()
    conditional_branches: set[int] = set()
    unconditional_branches: set[int] = set()
    indirect_jumps: set[int] = set()

    def enqueue_or_exit(source: int, destination: int, kind: str) -> None:
        if entry <= destination < end and destination + 2 <= len(data):
            edges[source].add(destination)
            queue.append(destination)
        else:
            exits[kind] += 1

    while queue and len(nodes) < max_states:
        pos = queue.popleft()
        if pos in nodes:
            continue
        if pos < entry or pos >= end or pos + 2 > len(data):
            exits["invalid_or_out_of_bound_entry"] += 1
            continue
        nodes.add(pos)
        opcode = be16(data, pos)
        branch = branch_destination(pos, opcode)

        if branch is not None:
            kind, destination = branch
            if kind in ("BRA", "BSR"):
                delay = pos + 2
                if delay + 2 > len(data) or delay >= end:
                    exits["delay_slot_outside_bound"] += 1
                    continue
                delay_slots.add(delay)
                if kind == "BSR":
                    call_sites.add(pos)
                    enqueue_or_exit(pos, pos + 4, "call_fallthrough_outside_bound")
                else:
                    unconditional_branches.add(pos)
                    enqueue_or_exit(pos, destination, "branch_target_outside_bound")
                continue

            if kind.endswith("/S"):
                delay = pos + 2
                if delay + 2 > len(data) or delay >= end:
                    exits["delay_slot_outside_bound"] += 1
                    continue
                delay_slots.add(delay)
                conditional_branches.add(pos)
                enqueue_or_exit(pos, destination, "conditional_target_outside_bound")
                enqueue_or_exit(pos, pos + 4, "conditional_fallthrough_outside_bound")
                continue

            conditional_branches.add(pos)
            enqueue_or_exit(pos, destination, "conditional_target_outside_bound")
            enqueue_or_exit(pos, pos + 2, "conditional_fallthrough_outside_bound")
            continue

        if opcode == 0x000B:  # RTS, with an executed delay slot
            delay = pos + 2
            if delay + 2 <= len(data) and delay < end:
                delay_slots.add(delay)
                rts_sites.add(pos)
                exits["rts"] += 1
            else:
                exits["rts_delay_slot_outside_bound"] += 1
            continue

        if opcode == 0x002B:  # RTE
            delay = pos + 2
            if delay + 2 <= len(data) and delay < end:
                delay_slots.add(delay)
                exits["rte"] += 1
            else:
                exits["rte_delay_slot_outside_bound"] += 1
            continue

        if (opcode & 0xF0FF) == 0x402B:  # JMP @Rn
            delay = pos + 2
            if delay + 2 <= len(data) and delay < end:
                delay_slots.add(delay)
                indirect_jumps.add(pos)
                exits["indirect_jump"] += 1
            else:
                exits["jmp_delay_slot_outside_bound"] += 1
            continue

        if _is_jsr(opcode):
            delay = pos + 2
            if delay + 2 <= len(data) and delay < end:
                delay_slots.add(delay)
                call_sites.add(pos)
                enqueue_or_exit(pos, pos + 4, "call_fallthrough_outside_bound")
            else:
                exits["jsr_delay_slot_outside_bound"] += 1
            continue

        enqueue_or_exit(pos, pos + 2, "fallthrough_outside_bound")

    state_limit_reached = bool(queue)
    if state_limit_reached:
        exits["state_limit"] += 1

    # Detect cycles in the bounded direct-flow graph without mistaking a join
    # reached from two branches for a loop.
    colors: dict[int, int] = {}
    cycle_detected = False

    def visit(node: int) -> None:
        nonlocal cycle_detected
        colors[node] = 1
        for successor in edges.get(node, ()):
            if successor not in nodes:
                continue
            if colors.get(successor) == 1:
                cycle_detected = True
            elif colors.get(successor, 0) == 0:
                visit(successor)
        colors[node] = 2

    for node in nodes:
        if colors.get(node, 0) == 0:
            visit(node)

    non_rts_exits = sum(count for kind, count in exits.items() if kind != "rts")
    all_observed_exits_are_rts = bool(exits) and non_rts_exits == 0
    return {
        "candidate_interval_bytes": max(0, end - entry),
        "reachable_instruction_addresses_including_delay_slots": len(nodes | delay_slots),
        "reachable_rts_sites": len(rts_sites),
        "reachable_call_sites": len(call_sites),
        "reachable_conditional_branches": len(conditional_branches),
        "reachable_unconditional_branches": len(unconditional_branches),
        "reachable_indirect_jumps": len(indirect_jumps),
        "observed_exit_kinds": dict(exits),
        "all_observed_exits_are_rts": all_observed_exits_are_rts,
        "cycle_detected": cycle_detected,
        "state_limit_reached": state_limit_reached,
        "all_paths_proven_to_terminate_at_rts": (
            all_observed_exits_are_rts and not cycle_detected and not state_limit_reached
        ),
        "indirect_callee_effects_modeled": False,
        "register_dataflow_modeled": False,
        "runtime_reachability_proven": False,
    }


def _callchain_leaf_targets(data: bytes) -> list[tuple[str, int]]:
    first_call = _first_preserved_filename_call(data)
    if first_call is None:
        return []
    helper_entry = first_call[2] - CODE_LOAD_ADDRESS
    if not 0 <= helper_entry < len(data):
        return []
    helper_end = _function_end(data, helper_entry)
    first_targets = [
        target for _, target in _resolve_call_sites(data, helper_entry, helper_end)
        if target is not None
    ]
    if not first_targets:
        return []
    nested_entry = first_targets[0] - CODE_LOAD_ADDRESS
    if not 0 <= nested_entry < len(data):
        return []
    nested_end = _function_end(data, nested_entry)
    nested_targets = [
        target for _, target in _resolve_call_sites(data, nested_entry, nested_end)
        if target is not None
    ]
    candidates = []
    for target in nested_targets:
        shape = classify_target_entry(data, target)
        if shape in ("straight_line_leaf_return", "conditional_early_return"):
            candidates.append((shape, target))
    if not nested_targets:
        return candidates
    next_entry = nested_targets[0] - CODE_LOAD_ADDRESS
    if not 0 <= next_entry < len(data):
        return candidates
    next_end = _function_end(data, next_entry)
    next_targets = [
        target for _, target in _resolve_call_sites(data, next_entry, next_end)
        if target is not None
    ]
    for target in next_targets:
        shape = classify_target_entry(data, target)
        if shape in ("straight_line_leaf_return", "conditional_early_return"):
            candidates.append((shape, target))
    return candidates


def analyze(image: Path) -> dict:
    root = read_root_payloads(image)
    main = root["payloads"].get("0TH2.BIN", b"")
    if not main:
        return {
            "schema_version": 1,
            "stage": "stage90_leaf_entry_direct_cfg",
            "analysis": {
                "main_executable_present": False,
                "leaf_candidate_cfgs_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }
    candidates = _callchain_leaf_targets(main)
    if not candidates:
        return {
            "schema_version": 1,
            "stage": "stage90_leaf_entry_direct_cfg",
            "analysis": {
                "main_executable_present": True,
                "leaf_candidate_cfgs_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    aggregate: dict[str, dict] = {}
    for shape in ("straight_line_leaf_return", "conditional_early_return"):
        items = []
        for candidate_shape, target in candidates:
            if candidate_shape != shape:
                continue
            entry = target - CODE_LOAD_ADDRESS
            end = _function_end(main, entry)
            items.append(audit_direct_cfg(main, entry, end))
        if not items:
            continue
        aggregate[shape] = {
            "candidate_count": len(items),
            "total_reachable_instruction_addresses": sum(
                item["reachable_instruction_addresses_including_delay_slots"] for item in items
            ),
            "min_reachable_instruction_addresses": min(
                item["reachable_instruction_addresses_including_delay_slots"] for item in items
            ),
            "max_reachable_instruction_addresses": max(
                item["reachable_instruction_addresses_including_delay_slots"] for item in items
            ),
            "total_reachable_rts_sites": sum(item["reachable_rts_sites"] for item in items),
            "candidates_with_cycles": sum(item["cycle_detected"] for item in items),
            "candidates_with_only_rts_exits": sum(item["all_observed_exits_are_rts"] for item in items),
            "candidates_proven_to_terminate_on_all_paths": sum(
                item["all_paths_proven_to_terminate_at_rts"] for item in items
            ),
            "any_state_limit_reached": any(item["state_limit_reached"] for item in items),
        }
    return {
        "schema_version": 1,
        "stage": "stage90_leaf_entry_direct_cfg",
        "target_file": "0TH2.BIN",
        "analysis": {
            "leaf_candidate_cfgs_resolved": True,
            "leaf_candidate_results": aggregate,
            "delay_slots_modeled": True,
            "conditional_branches_explored_both_ways": True,
            "indirect_jumps_reported_not_guessed": True,
            "prologue_bounded_intervals_prove_function_identity": False,
            "runtime_file_io_semantics_confirmed": False,
            "runtime_set07_execution_confirmed": False,
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
