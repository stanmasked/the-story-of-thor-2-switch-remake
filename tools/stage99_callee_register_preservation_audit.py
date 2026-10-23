#!/usr/bin/env python3
"""Stage99: audit R13 preservation across calls before the second control-byte store.

The original Saturn ISO is read locally. JSON output is aggregate-only: no
addresses, offsets, instruction bytes, or extracted payloads are emitted.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, deque
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import _may_write_register
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import (
    _be16,
    _branch,
    _find_main_th2_low_load,
    _find_set_table_loader_targets,
)
from stage92_set07_guard_predicate_audit import _delay_aware_cfg, _dominators
from stage93_loader_wrapper_and_set07_entry_audit import _summarize_loader_wrapper
from stage94_error_helper_return_audit import _summarize_error_helper
from stage97_optional_target_provenance_cfg import _find_error_helper_entry_window
from stage98_control_byte_writer_audit import (
    _caller_entry_anchors,
    _scan_control_byte_writers,
    _site_reachability,
    _source_register_seed_summary,
)

R13_SAVE = 0x2FD6  # MOV.L R13,@-R15
R13_RESTORE = 0x6DF6  # MOV.L @R15+,R13
RETURN_OPS = {0x000B, 0x002B}
MAX_FUNCTION_WINDOW = 0x400


def _function_end(data: bytes, entry: int) -> int:
    """Bound a candidate function at its first linear RTS/RTE plus delay slot."""
    stop = min(len(data), entry + MAX_FUNCTION_WINDOW)
    for pos in range(entry, max(entry, stop - 1), 2):
        if _be16(data, pos) in RETURN_OPS:
            return min(len(data), pos + 4)
    return stop


def _resolve_call_target(data: bytes, entry: int, pos: int) -> dict:
    """Resolve direct calls and literal-backed JSRs; retain pointer-slot ambiguity."""
    opcode = _be16(data, pos)
    branch = _branch(pos, opcode)
    if branch is None:
        return {"kind": "unresolved", "value": None}
    kind, target, _delayed = branch
    if kind in ("BSR", "BSRF"):
        return {"kind": "direct", "value": target}
    if kind != "JSR":
        return {"kind": "unresolved", "value": None}

    register = (opcode >> 8) & 0xF
    pointer_dereference = False
    for candidate in range(pos - 2, entry - 1, -2):
        op = _be16(data, candidate)
        # MOV.L @Rn,Rn: a literal first supplied a pointer-slot address, then
        # this instruction replaced it with the slot's runtime contents.
        if (
            op & 0xF00F == 0x6002
            and ((op >> 8) & 0xF) == register
            and ((op >> 4) & 0xF) == register
        ):
            pointer_dereference = True
            continue
        literal = movl_literal(data, candidate)
        if literal is not None and literal[2] == register:
            return {
                "kind": "pointer_slot" if pointer_dereference else "literal",
                "value": literal[1],
            }
        if _may_write_register(op, register):
            return {"kind": "unresolved", "value": None}
    return {"kind": "unresolved", "value": None}


def _save_restore_proven(data: bytes, entry: int, end: int) -> bool:
    """Require a saved R13 and a dominating restore before every return/tail exit."""
    cfg = _delay_aware_cfg(data, entry, end)
    nodes = cfg["nodes"]
    if entry not in nodes:
        return False
    dominators = _dominators(entry, nodes, cfg["edges"])
    saves = [p for p in nodes if _be16(data, p) == R13_SAVE]
    restores = [p for p in nodes if _be16(data, p) == R13_RESTORE]
    exits = []
    for pos in nodes:
        opcode = _be16(data, pos)
        if opcode in RETURN_OPS:
            exits.append(pos)
            continue
        branch = _branch(pos, opcode)
        if (
            branch is not None
            and branch[0] in ("BRA", "JMP", "BRAF")
            and branch[1] is not None
            and not entry <= branch[1] < end
        ):
            exits.append(pos)
    if not exits or not saves or not restores:
        return False
    for exit_pos in exits:
        preserved = any(
            restore in dominators.get(exit_pos, set())
            and any(save in dominators.get(restore, set()) for save in saves)
            for restore in restores
        )
        if not preserved:
            return False
    return True


def _reachable_calls_and_tail_exits(data: bytes, entry: int, end: int, cfg: dict) -> list[tuple[int, str, dict]]:
    calls = []
    states = cfg["state_nodes"]
    for pos in sorted(cfg["nodes"]):
        if (pos, None) not in states:
            continue
        branch = _branch(pos, _be16(data, pos))
        if branch is None:
            continue
        kind, target, _delayed = branch
        if kind in ("JSR", "BSR", "BSRF"):
            calls.append((pos, kind, _resolve_call_target(data, entry, pos)))
        elif (
            kind in ("BRA", "JMP", "BRAF")
            and target is not None
            and not entry <= target < end
        ):
            calls.append((pos, "TAIL", {"kind": "direct", "value": target}))
    return calls


def _direct_r13_write_count(data: bytes, nodes: set[int]) -> int:
    return sum(
        1
        for pos in nodes
        if _be16(data, pos) not in (R13_SAVE, R13_RESTORE)
        and _may_write_register(_be16(data, pos), 13)
    )


def _callee_r13_preservation(
    data: bytes, entry: int, depth: int = 0, visited: frozenset[int] = frozenset()
) -> bool | None:
    """Prove preservation from save/restore or a closed in-image call graph.

    None means a dynamic or out-of-image callee prevents a proof. A detected
    direct R13 write without a dominating restore is a definite failure.
    """
    if entry < 0 or entry + 2 > len(data) or depth > 8 or entry in visited:
        return None
    end = _function_end(data, entry)
    cfg = _delay_aware_cfg(data, entry, end)
    if _save_restore_proven(data, entry, end):
        return True
    if _direct_r13_write_count(data, cfg["nodes"]):
        return False

    callees = _reachable_calls_and_tail_exits(data, entry, end, cfg)
    if not callees:
        return True
    results = []
    for _pos, _kind, resolved in callees:
        kind = resolved["kind"]
        value = resolved["value"]
        if kind == "pointer_slot":
            results.append(None)
            continue
        if kind == "literal":
            if value is None or not CODE_LOAD_ADDRESS <= value < CODE_LOAD_ADDRESS + len(data):
                results.append(None)
                continue
            target_entry = value - CODE_LOAD_ADDRESS
        elif kind == "direct":
            if value is None or not 0 <= value < len(data):
                results.append(None)
                continue
            target_entry = value
        else:
            results.append(None)
            continue
        results.append(
            _callee_r13_preservation(data, target_entry, depth + 1, visited | {entry})
        )
    if any(result is False for result in results):
        return False
    if all(result is True for result in results):
        return True
    return None


def _reachable_nodes_that_can_reach(cfg: dict, target: int) -> set[int]:
    reverse: dict[int, set[int]] = {node: set() for node in cfg["nodes"]}
    for source, targets in cfg["edges"].items():
        for dest in targets:
            if dest in reverse:
                reverse[dest].add(source)
    seen = set()
    queue = deque([target])
    while queue:
        node = queue.popleft()
        if node in seen:
            continue
        seen.add(node)
        queue.extend(reverse.get(node, ()))
    return seen


def _pre_store_calls(data: bytes, entry: int, end: int, store_site: int) -> list[dict]:
    cfg = _delay_aware_cfg(data, entry, end)
    can_reach_store = _reachable_nodes_that_can_reach(cfg, store_site)
    calls = []
    for pos in sorted(cfg["nodes"]):
        if pos >= store_site or pos not in can_reach_store or (pos, None) not in cfg["state_nodes"]:
            continue
        branch = _branch(pos, _be16(data, pos))
        if branch is None or branch[0] not in ("JSR", "BSR", "BSRF"):
            continue
        # A call whose delay slot is the store executes the store before the
        # callee starts, so that callee is not a prior writer-value dependency.
        if pos + 2 == store_site:
            continue
        resolved = _resolve_call_target(data, entry, pos)
        calls.append({
            "kind": branch[0],
            "target_kind": resolved["kind"],
            "target_value": resolved["value"],
            "call_site": pos,
        })
    return calls


def _wrapper_success_path_summary(data: bytes) -> dict:
    _, set_targets = _find_set_table_loader_targets(data)
    _, low_targets, _ = _find_main_th2_low_load(data)
    common = set(set_targets).intersection(low_targets)
    if len(common) != 1:
        return {"recognized": False, "normal_success_path_preserves_r13": False}
    wrapper_entry = next(iter(common)) - CODE_LOAD_ADDRESS
    wrapper = _summarize_loader_wrapper(data, wrapper_entry)
    if not (
        wrapper.get("wrapper_signature_found", False)
        and wrapper.get("first_result_checked_for_nonnegative_value", False)
        and wrapper.get("second_result_checked_for_nonnegative_value", False)
    ):
        return {"recognized": False, "normal_success_path_preserves_r13": False}

    helper_a = movl_literal(data, wrapper_entry + 4)
    helper_b = movl_literal(data, wrapper_entry + 0x1C)
    if not (
        helper_a is not None and helper_a[2] == 3
        and helper_b is not None and helper_b[2] == 3
    ):
        return {"recognized": True, "normal_success_path_preserves_r13": False}

    a_entry = helper_a[1] - CODE_LOAD_ADDRESS
    b_entry = helper_b[1] - CODE_LOAD_ADDRESS
    a_preserves = _callee_r13_preservation(data, a_entry)
    b_preserves = _callee_r13_preservation(data, b_entry)
    end = _function_end(data, wrapper_entry)
    wrapper_cfg = _delay_aware_cfg(data, wrapper_entry, end)
    wrapper_writes = _direct_r13_write_count(data, wrapper_cfg["nodes"])
    return {
        "recognized": True,
        "first_loader_helper_preserves_r13": a_preserves is True,
        "second_loader_helper_preserves_r13": b_preserves is True,
        "wrapper_direct_r13_write_count": wrapper_writes,
        "normal_success_path_preserves_r13": (
            a_preserves is True and b_preserves is True and wrapper_writes == 0
        ),
        "error_path_preservation_resolved": False,
        "error_path_runtime_nonreturning_confirmed": False,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    helper_window = _find_error_helper_entry_window(main)
    if helper_window is None:
        return {
            "schema_version": 1,
            "stage": "stage99_callee_register_preservation_audit",
            "analysis": {
                "error_helper_entry_anchor_found": False,
                "second_control_byte_writer_found": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    helper_entry = helper_window[0]
    state_literal = movl_literal(main, helper_entry)
    if state_literal is None or state_literal[2] != 2:
        return {
            "schema_version": 1,
            "stage": "stage99_callee_register_preservation_audit",
            "analysis": {
                "error_helper_entry_anchor_found": True,
                "control_byte_pointer_extraction_confirmed": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    control_byte = state_literal[1]
    per_module = _scan_control_byte_writers(payloads, control_byte)
    main_sites = per_module.get("0TH2.BIN", {}).get("store_sites", {})
    r13_sites = [
        site for site, detail in main_sites.items()
        if detail.get("source_register") == 13 and detail.get("width") == 1
    ]
    site_reachability, _reachable_anchor_count = _site_reachability(main, set(r13_sites))
    reachable_sites = [site for site in r13_sites if site in site_reachability]
    if len(reachable_sites) != 1:
        return {
            "schema_version": 1,
            "stage": "stage99_callee_register_preservation_audit",
            "analysis": {
                "error_helper_entry_anchor_found": True,
                "second_control_byte_writer_found": False,
                "r13_writer_candidate_count": len(r13_sites),
                "reachable_r13_writer_candidate_count": len(reachable_sites),
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    store_site = reachable_sites[0]
    site_detail = main_sites[store_site]
    caller_entry = site_reachability[store_site]["entry"]
    caller_end = site_reachability[store_site]["end"]
    source = _source_register_seed_summary(main, caller_entry, store_site, 13)
    calls = _pre_store_calls(main, caller_entry, caller_end, store_site)
    wrapper_summary = _wrapper_success_path_summary(main)

    call_summaries = []
    unresolved_pointer_slots = []
    for index, call in enumerate(calls, 1):
        target_kind = call["target_kind"]
        target_value = call["target_value"]
        if target_kind == "literal" and target_value is not None and CODE_LOAD_ADDRESS <= target_value < CODE_LOAD_ADDRESS + len(main):
            target_entry = target_value - CODE_LOAD_ADDRESS
            preserves = _callee_r13_preservation(main, target_entry)
            if target_value == next(iter(set(_find_set_table_loader_targets(main)[1]).intersection(_find_main_th2_low_load(main)[1])), None):
                role = "loader_wrapper"
                preserves = None
            else:
                role = "in_image_callee"
            if preserves is None and role != "loader_wrapper":
                end = _function_end(main, target_entry)
                cfg = _delay_aware_cfg(main, target_entry, end)
                for _nested_pos, _nested_kind, resolved in _reachable_calls_and_tail_exits(main, target_entry, end, cfg):
                    if resolved["kind"] == "pointer_slot" and resolved["value"] is not None:
                        unresolved_pointer_slots.append(resolved["value"])
        elif target_kind == "direct":
            role = "in_image_direct_callee" if target_value is not None and 0 <= target_value < len(main) else "out_of_image_direct_callee"
            preserves = _callee_r13_preservation(main, target_value) if role == "in_image_direct_callee" else None
        elif target_kind == "pointer_slot":
            role = "unresolved_pointer_slot_callee"
            preserves = None
            if target_value is not None:
                unresolved_pointer_slots.append(target_value)
        else:
            role = "unresolved_callee"
            preserves = None
        call_summaries.append({
            "order": index,
            "role": role,
            "r13_preservation_proven": preserves is True,
            "r13_preservation_definite_failure": preserves is False,
            "r13_preservation_unresolved": preserves is None,
        })

    # The only low-memory pointer slot observed in the first in-image callee is
    # scanned across all eligible root payloads; no matching store means its
    # runtime initialization is outside the scanned disc payload set.
    unique_slots = sorted(set(unresolved_pointer_slots))
    external_slot_writer_candidates = 0
    external_slot_exact_reference_count = 0
    if unique_slots:
        slot_audit = _scan_control_byte_writers(payloads, unique_slots[0])
        external_slot_writer_candidates = sum(
            item["exact_effective_address_store_candidate_count"]
            for item in slot_audit.values()
        )
        external_slot_exact_reference_count = sum(
            item["exact_control_byte_literal_reference_count"]
            for item in slot_audit.values()
        )

    # Count conditional branches on a CFG path that can still reach the store.
    caller_cfg = _delay_aware_cfg(main, caller_entry, caller_end)
    can_reach_store = _reachable_nodes_that_can_reach(caller_cfg, store_site)
    conditional_branches = sum(
        1
        for pos in caller_cfg["nodes"]
        if pos < store_site and pos in can_reach_store
        and (branch := _branch(pos, _be16(main, pos))) is not None
        and branch[0] in ("BT", "BF", "BT/S", "BF/S")
    )

    # The store is itself the delay slot of a later BSR; its callee begins only
    # after the store has already executed.
    previous_instruction = store_site - 2
    final_branch = _branch(previous_instruction, _be16(main, previous_instruction))
    store_is_call_delay_slot = bool(
        final_branch is not None
        and final_branch[0] in ("BSR", "JSR", "BSRF")
        and previous_instruction + 2 == store_site
    )

    error_summary = _summarize_error_helper(main, helper_entry)
    all_prior_calls_preserve = (
        len(call_summaries) == 3
        and all(item["r13_preservation_proven"] for item in call_summaries)
        and wrapper_summary.get("normal_success_path_preserves_r13", False)
    )
    seed_one = source.get("last_immediate_seed_found", False) and source.get("last_immediate_seed_value") == 1

    return {
        "schema_version": 1,
        "stage": "stage99_callee_register_preservation_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get("full_payloads_scanned", len(payloads)),
            "large_files_skipped_from_code_scan": root.get("large_files_skipped_from_code_scan", 0),
            "error_helper_entry_anchor_found": True,
            "second_control_byte_writer_found": True,
            "second_writer_source_register_seeded_to_one": seed_one,
            "pre_store_call_count": len(call_summaries),
            "pre_store_conditional_branch_count": conditional_branches,
            "pre_store_call_summaries": call_summaries,
            "first_callee_direct_r13_write_count": (
                _direct_r13_write_count(
                    main,
                    _delay_aware_cfg(
                        main,
                        calls[0]["target_value"] - CODE_LOAD_ADDRESS,
                        _function_end(main, calls[0]["target_value"] - CODE_LOAD_ADDRESS),
                    )["nodes"],
                )
                if calls and calls[0]["target_kind"] == "literal"
                and calls[0]["target_value"] is not None
                and CODE_LOAD_ADDRESS <= calls[0]["target_value"] < CODE_LOAD_ADDRESS + len(main)
                else None
            ),
            "first_callee_has_unresolved_indirect_pointer_call": bool(unique_slots),
            "unresolved_pointer_slot_store_candidates_across_scanned_root_payloads": external_slot_writer_candidates,
            "unresolved_pointer_slot_exact_reference_count_across_scanned_root_payloads": external_slot_exact_reference_count,
            "second_call_r13_save_restore_proven": len(call_summaries) >= 2 and call_summaries[1]["r13_preservation_proven"],
            "loader_wrapper_recognized": wrapper_summary.get("recognized", False),
            "loader_wrapper_first_helper_preserves_r13": wrapper_summary.get("first_loader_helper_preserves_r13", False),
            "loader_wrapper_second_helper_preserves_r13": wrapper_summary.get("second_loader_helper_preserves_r13", False),
            "loader_wrapper_normal_success_path_preserves_r13": wrapper_summary.get("normal_success_path_preserves_r13", False),
            "loader_wrapper_error_path_preservation_resolved": wrapper_summary.get("error_path_preservation_resolved", False),
            "error_helper_nonreturning_by_layout_candidate": error_summary.get("helper_appears_nonreturning_by_layout", False),
            "error_helper_runtime_nonreturning_confirmed": False,
            "second_writer_is_final_call_delay_slot": store_is_call_delay_slot,
            "second_writer_value_proven_on_all_static_paths": False,
            "second_writer_value_if_all_pre_store_callees_preserve_r13_and_wrapper_returns_successfully": (
                1 if seed_one and store_is_call_delay_slot else None
            ),
            "all_prior_call_preservation_proven": all_prior_calls_preserve,
            "runtime_control_byte_value_confirmed": False,
            "runtime_error_branch_selection_confirmed": False,
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
