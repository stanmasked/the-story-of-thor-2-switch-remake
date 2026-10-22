#!/usr/bin/env python3
"""Stage77: interprocedural preservation audit for the length-field writer path.

The original Saturn ISO remains local. Output is aggregate-only: no RAM
addresses, instruction offsets, instruction words, or game assets are emitted.
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
    _increments_base_register,
    _may_write_register,
    _resolve_callback,
)
from stage76_length_field_feedback_cfg import (
    _find_routine_prologues,
    _find_source_writer_sites,
)


def _word(data: bytes, pos: int) -> int:
    return be16(data, pos)


def _is_jsr(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x400B


def _is_jmp(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x402B


def _is_rts(opcode: int) -> bool:
    return opcode == 0x000B


def _main_path_calls(
    data: bytes, entry: int, end_bound: int, targets: set[int]
) -> tuple[set[int], set[int], set[int]]:
    queue = deque([entry])
    visited = set()
    direct_targets = set()
    direct_sites = set()
    indirect_sites = set()

    def record_delay(pos: int) -> None:
        if pos in targets:
            visited.add(pos)

    while queue:
        pos = queue.popleft()
        if pos < entry or pos > end_bound or pos + 2 > len(data) or pos in visited:
            continue
        visited.add(pos)
        if pos in targets:
            continue
        opcode = _word(data, pos)
        branch = branch_destination(pos, opcode)
        if branch is not None:
            kind, destination = branch
            if kind in ("BRA", "BSR"):
                delay_pos = pos + 2
                record_delay(delay_pos)
                if kind == "BSR":
                    direct_targets.add(destination)
                    direct_sites.add(pos)
                    if pos + 4 <= end_bound:
                        queue.append(pos + 4)
                elif entry <= destination <= end_bound:
                    queue.append(destination)
                continue
            if kind.endswith("/S"):
                delay_pos = pos + 2
                record_delay(delay_pos)
                for next_pos in (destination, pos + 4):
                    if entry <= next_pos <= end_bound:
                        queue.append(next_pos)
                continue
            for next_pos in (destination, pos + 2):
                if entry <= next_pos <= end_bound:
                    queue.append(next_pos)
            continue
        if _is_jsr(opcode):
            indirect_sites.add(pos)
            record_delay(pos + 2)
            if pos + 4 <= end_bound:
                queue.append(pos + 4)
            continue
        if _is_jmp(opcode) or _is_rts(opcode):
            record_delay(pos + 2)
            continue
        if pos + 2 <= end_bound:
            queue.append(pos + 2)
    return direct_targets, direct_sites, indirect_sites


def _resolve_indirect_call_target(data: bytes, call_pos: int) -> int | None:
    opcode = _word(data, call_pos)
    if not (_is_jsr(opcode) or _is_jmp(opcode)):
        return None
    register = (opcode >> 8) & 0xF
    candidates = []
    for pos in range(max(0, call_pos - 0x30), call_pos, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[2] == register:
            candidates.append((pos, literal[1]))
    for load_pos, value in reversed(candidates):
        if any(
            _may_write_register(_word(data, pos), register)
            for pos in range(load_pos + 2, call_pos, 2)
        ):
            continue
        if CODE_LOAD_ADDRESS <= value < CODE_LOAD_ADDRESS + len(data):
            return value - CODE_LOAD_ADDRESS
        return None
    return None


def _reachable_function(data: bytes, entry: int, max_nodes: int = 20000) -> dict:
    queue = deque([entry])
    visited = set()
    direct_calls = set()
    indirect_calls = set()
    indirect_jumps = set()
    indirect_targets = {}
    tail_branches = set()
    returns = set()

    while queue and len(visited) < max_nodes:
        pos = queue.popleft()
        if pos < 0 or pos + 2 > len(data) or pos in visited:
            continue
        visited.add(pos)
        opcode = _word(data, pos)
        branch = branch_destination(pos, opcode)
        if branch is not None:
            kind, destination = branch
            if kind == "BRA":
                delay_pos = pos + 2
                if delay_pos + 2 <= len(data):
                    visited.add(delay_pos)
                tail_branches.add((pos, destination))
                if 0 <= destination < len(data) - 1:
                    queue.append(destination)
                continue
            if kind == "BSR":
                direct_calls.add(destination)
                if pos + 2 + 2 <= len(data):
                    visited.add(pos + 2)
                if pos + 4 + 2 <= len(data):
                    queue.append(pos + 4)
                continue
            if kind.endswith("/S"):
                delay_pos = pos + 2
                if delay_pos + 2 <= len(data):
                    visited.add(delay_pos)
                for next_pos in (destination, pos + 4):
                    if 0 <= next_pos < len(data) - 1:
                        queue.append(next_pos)
                continue
            for next_pos in (destination, pos + 2):
                if 0 <= next_pos < len(data) - 1:
                    queue.append(next_pos)
            continue
        if _is_jsr(opcode):
            indirect_calls.add(pos)
            indirect_targets[pos] = _resolve_indirect_call_target(data, pos)
            if pos + 2 + 2 <= len(data):
                visited.add(pos + 2)
            if pos + 4 + 2 <= len(data):
                queue.append(pos + 4)
            continue
        if _is_jmp(opcode):
            indirect_jumps.add(pos)
            indirect_targets[pos] = _resolve_indirect_call_target(data, pos)
            if pos + 2 + 2 <= len(data):
                visited.add(pos + 2)
            continue
        if _is_rts(opcode):
            returns.add(pos)
            if pos + 2 + 2 <= len(data):
                visited.add(pos + 2)
            continue
        if pos + 2 + 2 <= len(data):
            queue.append(pos + 2)

    return {
        "nodes": visited,
        "direct_calls": direct_calls,
        "indirect_calls": indirect_calls,
        "indirect_jumps": indirect_jumps,
        "indirect_targets": indirect_targets,
        "tail_branches": tail_branches,
        "returns": returns,
        "node_limit_reached": bool(queue),
    }


def _r13_preserved_by_saver(data: bytes, entry: int, graph: dict) -> bool:
    nodes = graph["nodes"]
    if not all(_word(data, entry + offset) == opcode for offset, opcode in (
        (0x00, 0x2FE6), (0x04, 0x2FD6), (0x0A, 0x6D53),
    )):
        return False
    r13_writes = sorted(
        pos for pos in nodes
        if _may_write_register(_word(data, pos), 13)
        or _increments_base_register(_word(data, pos), 13)
    )
    expected = sorted(
        pos for pos in nodes
        if _word(data, pos) in (0x6D53, 0x6DF6)
    )
    if r13_writes != expected or _word(data, entry + 0x04) != 0x2FD6:
        return False
    tail_exits = [
        pos for pos, target in graph["tail_branches"]
        if target in graph["direct_calls"]
    ]
    if not tail_exits:
        return False
    return all(_word(data, pos - 2) == 0x6DF6 for pos in tail_exits)


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    callback_entry, length_address, callback_chain = _resolve_callback(data)
    prologues = _find_routine_prologues(data)
    r10_writers, r13_reads = _find_source_writer_sites(data)
    targets = set(r10_writers + r13_reads)
    main_entry = None
    if targets:
        candidates = [pos for pos in prologues if pos < min(targets)]
        if candidates:
            main_entry = max(candidates)

    main_direct_targets = set()
    main_direct_sites = set()
    main_indirect_sites = set()
    if main_entry is not None and targets:
        (
            main_direct_targets, main_direct_sites, main_indirect_sites
        ) = _main_path_calls(data, main_entry, max(targets), targets)

    function_graphs = {}
    pending = list(main_direct_targets)
    resolved_targets = set()
    while pending and len(function_graphs) < 32:
        entry = pending.pop()
        if entry in function_graphs:
            continue
        graph = _reachable_function(data, entry)
        function_graphs[entry] = graph
        pending.extend(target for target in graph["direct_calls"] if target not in function_graphs)
        for target in graph["indirect_targets"].values():
            if target is None:
                unresolved_indirect_calls += 1
            else:
                resolved_targets.add(target)
                if target not in function_graphs:
                    pending.append(target)

    r10_write_free = bool(function_graphs) and all(
        not any(_may_write_register(_word(data, pos), 10) for pos in graph["nodes"])
        for graph in function_graphs.values()
    )
    r13_preserved_by_graph = {}
    r13_saver_verified = False
    for entry, graph in function_graphs.items():
        writes_r13 = any(
            _may_write_register(_word(data, pos), 13)
            or _increments_base_register(_word(data, pos), 13)
            for pos in graph["nodes"]
        )
        preserved = not writes_r13
        if writes_r13:
            preserved = _r13_preserved_by_saver(data, entry, graph)
            r13_saver_verified |= preserved
        r13_preserved_by_graph[entry] = preserved
    r13_preserved = bool(function_graphs) and all(r13_preserved_by_graph.values())
    unresolved_indirect_call_sites = sum(
        1 for graph in function_graphs.values()
        for target in graph["indirect_targets"].values() if target is None
    )
    all_targets_closed = (
        bool(main_direct_targets)
        and not unresolved_indirect_call_sites
        and not any(graph["node_limit_reached"] for graph in function_graphs.values())
        and all(graph["returns"] for graph in function_graphs.values())
    )
    return {
        "schema_version": 1,
        "stage": "stage77_callee_register_preservation",
        "target_file": "0TH2.BIN",
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "main_direct_bsr_sites_to_feedback_writers": len(main_direct_sites),
            "main_unique_direct_callee_targets": len(main_direct_targets),
            "main_indirect_jsr_sites_to_feedback_writers": len(main_indirect_sites),
            "callee_graph_functions_analyzed": len(function_graphs),
            "nested_indirect_transfer_targets_resolved": len(resolved_targets),
            "unresolved_nested_indirect_transfer_sites": unresolved_indirect_call_sites,
            "all_reachable_callee_targets_closed": all_targets_closed,
            "r10_preserved_by_analyzed_callee_graph": r10_write_free,
            "r13_preservation_wrapper_found": r13_saver_verified,
            "r13_preserved_by_analyzed_callee_graph": r13_preserved,
            "discovered_callee_graph_preserves_r10_r13": (
                all_targets_closed and r10_write_free and r13_preserved
            ),
            "alternate_runtime_indirect_entries_excluded": False,
            "source_global_initialization_order_proven": False,
            "global_length_count_upper_bound_proven": False,
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
