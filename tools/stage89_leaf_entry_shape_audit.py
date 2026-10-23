#!/usr/bin/env python3
"""Stage89: distinguish prologue entries from short leaf-return call targets.

The original Saturn ISO stays local. Early-RTS shapes are candidate function
boundaries, not proof of runtime semantics or complete control-flow reachability.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from stage18_writer_guard_flow import be16
from stage35_table_tail_link import branch_destination
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage86_set_module_signature_audit import read_root_payloads
from stage87_set_filename_loader_context import _is_jsr
from stage88_filename_helper_callchain import (
    _first_preserved_filename_call,
    _function_end,
    _has_frame_prologue,
    _resolve_call_sites,
)


def classify_target_entry(data: bytes, target: int) -> str:
    if not CODE_LOAD_ADDRESS <= target < CODE_LOAD_ADDRESS + len(data):
        return "outside_main_executable"
    entry = target - CODE_LOAD_ADDRESS
    if _has_frame_prologue(data, entry):
        return "frame_prologue"
    stop = min(len(data) - 1, entry + 0x20)
    rts_pos = next(
        (pos for pos in range(entry, stop, 2) if be16(data, pos) == 0x000B),
        None,
    )
    if rts_pos is None:
        return "no_early_rts"
    prior_positions = range(entry, rts_pos, 2)
    prior_opcodes = [(pos, be16(data, pos)) for pos in prior_positions]
    has_call = any(
        _is_jsr(opcode)
        or (branch_destination(pos, opcode) or (None, None))[0] == "BSR"
        for pos, opcode in prior_opcodes
    )
    has_branch = any(
        branch_destination(pos, opcode) is not None
        for pos, opcode in prior_opcodes
    )
    if has_call:
        return "early_return_after_call"
    if has_branch:
        return "conditional_early_return"
    return "straight_line_leaf_return"


def summarize_layer(data: bytes, entry: int, end: int) -> dict:
    calls = _resolve_call_sites(data, entry, end)
    resolved = [target for _, target in calls if target is not None]
    unique_targets = sorted(set(resolved))
    classes = Counter(classify_target_entry(data, target) for target in unique_targets)
    return {
        "jsr_like_sites": len(calls),
        "jsr_sites_with_resolved_literal_targets": len(resolved),
        "unique_targets": len(unique_targets),
        "unique_targets_with_frame_prologue": classes["frame_prologue"],
        "unique_targets_with_straight_line_leaf_return": classes["straight_line_leaf_return"],
        "unique_targets_with_conditional_early_return": classes["conditional_early_return"],
        "unique_targets_with_early_return_after_call": classes["early_return_after_call"],
        "unique_targets_without_frame_prologue_or_early_rts": classes["no_early_rts"],
        "targets_outside_main_executable": classes["outside_main_executable"],
        "all_jsr_targets_resolved": bool(calls) and len(resolved) == len(calls),
        "target_classification_is_runtime_proof": False,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image)
    main = root["payloads"].get("0TH2.BIN", b"")
    first_call = _first_preserved_filename_call(main) if main else None
    if first_call is None:
        return {
            "schema_version": 1,
            "stage": "stage89_leaf_entry_shape_audit",
            "analysis": {
                "filename_helper_call_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }
    _, _, helper_target = first_call
    helper_entry = helper_target - CODE_LOAD_ADDRESS
    if not 0 <= helper_entry < len(main):
        return {
            "schema_version": 1,
            "stage": "stage89_leaf_entry_shape_audit",
            "analysis": {
                "filename_helper_call_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    helper_end = _function_end(main, helper_entry)
    layer1_calls = _resolve_call_sites(main, helper_entry, helper_end)
    layer1_targets = [target for _, target in layer1_calls if target is not None]
    first_nested_target = next(iter(layer1_targets), None)
    layer2 = {}
    layer3 = {}
    if first_nested_target is not None:
        entry2 = first_nested_target - CODE_LOAD_ADDRESS
        if 0 <= entry2 < len(main):
            end2 = _function_end(main, entry2)
            layer2 = summarize_layer(main, entry2, end2)
            calls2 = _resolve_call_sites(main, entry2, end2)
            targets2 = [target for _, target in calls2 if target is not None]
            second_nested_target = next(iter(targets2), None)
            if second_nested_target is not None:
                entry3 = second_nested_target - CODE_LOAD_ADDRESS
                if 0 <= entry3 < len(main):
                    end3 = _function_end(main, entry3)
                    layer3 = summarize_layer(main, entry3, end3)

    layer1 = summarize_layer(main, helper_entry, helper_end)
    no_prologue_targets = [
        target for target in set(layer1_targets)
        if not _has_frame_prologue(main, target - CODE_LOAD_ADDRESS)
    ]
    return {
        "schema_version": 1,
        "stage": "stage89_leaf_entry_shape_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            "filename_helper_call_resolved": True,
            "first_helper_targets": layer1,
            "first_nested_callee_targets": layer2,
            "next_nested_callee_targets": layer3,
            "first_helper_targets_without_frame_prologue": len(no_prologue_targets),
            "candidate_interval_boundaries_can_hide_leaf_functions": True,
            "prologue_interval_membership_proves_same_function": False,
            "set07_loader_semantics_confirmed": False,
            "file_open_or_read_semantics_confirmed": False,
            "runtime_file_loading_confirmed": False,
            "runtime_set07_execution_confirmed": False,
            "runtime_pointer_registration_proven": False,
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
