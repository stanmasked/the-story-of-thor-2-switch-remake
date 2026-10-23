#!/usr/bin/env python3
"""Stage92: decode SET07 entry guards and loader-return handling.

Reads the private Saturn ISO locally. Output is aggregate-only: no addresses,
code offsets, instruction bytes, or original payloads are emitted.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict, deque
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import (
    _all_occurrences,
    _be16,
    _branch,
    _find_main_th2_low_load,
    _find_set07_callsite,
    _find_set_table_loader_targets,
    _generic_prologues,
)


def _delay_aware_cfg(data: bytes, start: int, end: int, max_states: int = 50000) -> dict:
    """Reachability CFG where delayed branches execute their slot before transfer.

    This is an intraprocedural structural walk, not a symbolic execution engine.
    JSR/BSR/BSRF are treated as returning; indirect JMP/BRAF and RTS/RTE exit.
    """
    queue = deque([(start, None)])
    seen_states: set[tuple[int, tuple[int, ...] | None]] = set()
    nodes: set[int] = set()
    delay_slots: set[int] = set()
    edges: dict[int, set[int]] = defaultdict(set)
    exits: Counter[str] = Counter()

    def valid(pc: int) -> bool:
        return start <= pc < end and pc + 2 <= len(data) and not (pc & 1)

    def queue_targets(source: int, targets: tuple[int, ...]) -> None:
        for target in targets:
            if valid(target):
                edges[source].add(target)
                queue.append((target, None))
            else:
                exits["out_of_bound_successor"] += 1

    while queue and len(seen_states) < max_states:
        pc, pending = queue.popleft()
        state = (pc, pending)
        if state in seen_states:
            continue
        seen_states.add(state)
        if not valid(pc):
            exits["invalid_or_out_of_bound_state"] += 1
            continue
        nodes.add(pc)

        # A pending successor set means this instruction is a branch delay slot.
        # Execute it as a normal instruction, then apply the pending transfer.
        if pending is not None:
            queue_targets(pc, pending)
            continue

        op = _be16(data, pc)
        branch = _branch(pc, op)
        if branch is None:
            queue_targets(pc, (pc + 2,))
            continue

        kind, target, delayed = branch
        if delayed:
            slot = pc + 2
            if not valid(slot):
                exits["delay_slot_outside_bound"] += 1
                continue
            delay_slots.add(slot)
            if kind == "BRA":
                after = (target,) if target is not None else ()
            elif kind in ("BSR", "JSR", "BSRF"):
                after = (pc + 4,)
            elif kind in ("BT/S", "BF/S"):
                after = tuple(x for x in (target, pc + 4) if x is not None)
            else:  # JMP, BRAF, RTS, RTE
                after = ()
            edges[pc].add(slot)
            queue.append((slot, after))
            continue

        if kind in ("BT", "BF"):
            queue_targets(pc, tuple(x for x in (target, pc + 2) if x is not None))
        elif kind == "BSR":
            queue_targets(pc, (pc + 2,))
        else:
            exits[f"terminal_{kind.lower()}"] += 1

    if queue:
        exits["state_limit_reached"] += 1
    return {
        "nodes": nodes,
        "delay_slots": delay_slots,
        "edges": {node: set(targets) for node, targets in edges.items()},
        "exit_counts": dict(exits),
        "state_count": len(seen_states),
    }


def _dominators(entry: int, nodes: set[int], edges: dict[int, set[int]]) -> dict[int, set[int]]:
    predecessors: dict[int, set[int]] = {node: set() for node in nodes}
    for source, targets in edges.items():
        for target in targets:
            if target in predecessors:
                predecessors[target].add(source)
    dom = {node: ({node} if node == entry else set(nodes)) for node in nodes}
    changed = True
    while changed:
        changed = False
        for node in nodes:
            if node == entry:
                continue
            preds = predecessors[node]
            common = set.intersection(*(dom[p] for p in preds)) if preds else set()
            updated = {node} | common
            if updated != dom[node]:
                dom[node] = updated
                changed = True
    return dom


def _find_guard_predicates(data: bytes, name_pos: int, continuation: int) -> dict:
    lower = max(0, name_pos - 0x200)
    global_eq = []
    r5_eq = []
    r4_eq = []
    mask_gate = []
    alternate_mask_gate = []

    for pos in range(lower, name_pos, 2):
        if pos + 6 > len(data):
            continue
        op = _be16(data, pos)
        op1 = _be16(data, pos + 2)
        op2 = _be16(data, pos + 4)
        b = _branch(pos + 4, op2)
        if op == 0x6031 and op1 == 0x8860 and b and b[0] == "BF" and b[1] == continuation:
            global_eq.append(pos)
        if op == 0x6053 and op1 == 0x8806 and b and b[0] == "BF" and b[1] == continuation:
            r5_eq.append(pos)
        if op == 0x604F and op1 == 0x880F and b and b[0] == "BF" and b[1] == continuation:
            r4_eq.append(pos)
        if op == 0x6031 and op1 == 0xC860 and b and b[0] == "BT/S" and b[1] == continuation:
            if pos + 8 <= len(data):
                mask_gate.append({"test": pos + 2, "branch": pos + 4, "delay_slot": pos + 6, "delay_slot_opcode": _be16(data, pos + 6)})
        if op == 0x6031 and op1 == 0xC810 and b and b[0] == "BF" and b[1] != continuation:
            alternate_mask_gate.append({"test": pos + 2, "branch": pos + 4, "target": b[1]})

    mask = mask_gate[0] if mask_gate else None
    alternate = alternate_mask_gate[0] if alternate_mask_gate else None
    return {
        "global_state_word_equals_0x60_guard_found": bool(global_eq),
        "r5_equals_6_guard_found": bool(r5_eq),
        "r4_equals_15_guard_found": bool(r4_eq),
        "tst_0x60_branch_skips_entry_when_mask_is_zero": mask is not None,
        "tst_0x60_fallthrough_requires_nonzero_mask": mask is not None,
        "mask_guard_delay_slot_copies_r14_to_r4": bool(mask and mask["delay_slot_opcode"] == 0x64E1),
        "r4_guard_follows_mask_guard_delay_slot": bool(mask and r4_eq and mask["delay_slot"] < r4_eq[0]),
        "tst_0x10_nonzero_selects_alternate_path": alternate is not None,
        "three_value_guard_count": min(len(global_eq), len(r5_eq), len(r4_eq)),
    }


def _r14_delay_slot_dominates_r4_guard(data: bytes, cfg: dict, entry: int, name_pos: int, continuation: int) -> bool:
    lower = max(0, name_pos - 0x200)
    mask_pos = next((pos for pos in range(lower, name_pos, 2)
                     if _be16(data, pos) == 0x6031 and _be16(data, pos + 2) == 0xC860
                     and (_branch(pos + 4, _be16(data, pos + 4)) or (None, None, False))[0] == "BT/S"
                     and (_branch(pos + 4, _be16(data, pos + 4)) or (None, None, False))[1] == continuation), None)
    r4_cmp_branch = next((pos + 4 for pos in range(lower, name_pos, 2)
                          if _be16(data, pos) == 0x604F and _be16(data, pos + 2) == 0x880F
                          and (_branch(pos + 4, _be16(data, pos + 4)) or (None, None, False))[0] == "BF"
                          and (_branch(pos + 4, _be16(data, pos + 4)) or (None, None, False))[1] == continuation), None)
    delay_slot = mask_pos + 6 if mask_pos is not None else None
    dom = _dominators(entry, cfg["nodes"], cfg["edges"]) if entry in cfg["nodes"] else {}
    return bool(
        delay_slot is not None and r4_cmp_branch is not None
        and delay_slot in cfg["delay_slots"]
        and delay_slot in dom.get(r4_cmp_branch, set())
        and _be16(data, delay_slot) == 0x64E1
    )


def _loader_result_summary(data: bytes, name_pos: int, buffer_base: int) -> dict:
    load_call_pos = name_pos + 4
    entry_target_load_pos = name_pos + 8
    entry_call_pos = name_pos + 10
    if entry_call_pos + 4 > len(data):
        return {
            "load_call_to_entry_shape_matches": False,
            "loader_result_explicitly_checked_before_entry": None,
            "entry_call_uses_same_destination_buffer": False,
        }
    entry_load = movl_literal(data, entry_target_load_pos)
    same_buffer = (
        entry_load is not None and entry_load[2] == 3 and entry_load[1] == buffer_base
        and _be16(data, load_call_pos) == 0x420B
        and _be16(data, load_call_pos + 2) == 0x0009
        and _be16(data, entry_call_pos) == 0x430B
        and _be16(data, entry_call_pos + 2) == 0x0009
    )
    # The only instruction between the loader's return/delay slot and the entry
    # JSR is a literal load into R3. It neither tests R0 nor branches on status.
    no_test = same_buffer and _branch(entry_target_load_pos, _be16(data, entry_target_load_pos)) is None
    return {
        "load_call_to_entry_shape_matches": same_buffer,
        "loader_result_explicitly_checked_before_entry": False if no_test else None,
        "entry_call_uses_same_destination_buffer": same_buffer,
        "only_intervening_instruction_loads_entry_target": no_test,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    low = payloads.get("TH2.LOW", b"")
    _, set_targets = _find_set_table_loader_targets(main) if main else ({}, [])
    main_low_summary, low_targets, low_bases = _find_main_th2_low_load(main) if main else ({}, [], [])
    base = low_bases[0] if len(set(low_bases)) == 1 else None
    loader_targets = set(set_targets).union(low_targets)
    callsite = _find_set07_callsite(low, base, loader_targets) if low and base is not None else None
    if callsite is None:
        return {
            "schema_version": 1,
            "stage": "stage92_set07_guard_predicate_audit",
            "analysis": {
                "set07_load_entry_callsite_found": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    name_pos, buffer_base = callsite
    entry_call_pos = name_pos + 10
    continuation = name_pos + 14
    prologues = _generic_prologues(low)
    previous = [pos for pos in prologues if pos < name_pos]
    following = [pos for pos in prologues if pos > entry_call_pos]
    function_start = max(previous) if previous else 0
    function_end = min(following) if following else len(low)
    cfg = _delay_aware_cfg(low, function_start, function_end)
    guards = _find_guard_predicates(low, name_pos, continuation)
    loader = _loader_result_summary(low, name_pos, buffer_base)
    r14_from_r4_guard_proven = _r14_delay_slot_dominates_r4_guard(
        low, cfg, function_start, name_pos, continuation
    )

    return {
        "schema_version": 1,
        "stage": "stage92_set07_guard_predicate_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "same_loader_target_used_for_th2_low_and_set_table": bool(set(set_targets).intersection(low_targets)),
            "set07_load_entry_callsite_found": True,
            "delay_aware_cfg_reaches_loader_call": name_pos + 4 in cfg["nodes"],
            "delay_aware_cfg_reaches_entry_call": entry_call_pos in cfg["nodes"],
            "delay_aware_cfg_instruction_count": len(cfg["nodes"]),
            "delay_slot_count_in_cfg": len(cfg["delay_slots"]),
            "r14_to_r4_delay_slot_dominates_r4_guard": r14_from_r4_guard_proven,
            "guards": guards,
            "loader_return": loader,
            "runtime_overlay_execution_confirmed": False,
            "runtime_loader_success_confirmed": False,
            "runtime_callback_execution_confirmed": False,
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
