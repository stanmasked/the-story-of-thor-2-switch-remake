#!/usr/bin/env python3
"""Stage91: check whether RTS delay-slot addresses are independently referenced.

The scan distinguishes a literal-backed call target from a raw address word.
It does not prove that computed or table-based entry paths are absent.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16
from stage35_table_tail_link import branch_destination
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage86_set_module_signature_audit import read_root_payloads
from stage87_set_filename_loader_context import (
    _call_target_from_recent_literal,
    _is_jsr,
    _pc_literal_refs,
)
from stage88_filename_helper_callchain import (
    _first_preserved_filename_call,
    _function_end,
    _resolve_call_sites,
)
from stage89_leaf_entry_shape_audit import classify_target_entry


def summarize_address_references(
    data: bytes, target_offset: int, payloads: dict[str, bytes]
) -> dict:
    target_address = CODE_LOAD_ADDRESS + target_offset
    pc_refs = len(_pc_literal_refs(data, target_address))
    resolved_calls = sum(
        1 for _, target in _resolve_call_sites(data, 0, len(data))
        if target == target_address
    )
    needle = target_address.to_bytes(4, "big")
    raw_words = sum(payload.count(needle) for payload in payloads.values())
    branch_targets = 0
    for pos in range(0, len(data) - 1, 2):
        branch = branch_destination(pos, be16(data, pos))
        if branch is not None and branch[1] == target_offset:
            branch_targets += 1
    return {
        "pc_relative_literal_refs": pc_refs,
        "resolved_literal_backed_jsr_calls": resolved_calls,
        "raw_big_endian_words_in_scanned_root_payloads": raw_words,
        "direct_branch_target_refs": branch_targets,
        "has_frame_prologue_signature": (
            target_offset >= 0 and target_offset + 2 <= len(data)
            and be16(data, target_offset) == 0x2FE6
            and (
                be16(data, target_offset + 2) == 0x4F22
                or any(
                    be16(data, target_offset + offset) == 0x4F22
                    for offset in range(2, 0x1A, 2)
                    if target_offset + offset + 2 <= len(data)
                )
            )
        ),
        "direct_entry_evidence_present": bool(
            pc_refs or resolved_calls or raw_words or branch_targets
        ),
    }


def _leaf_targets_from_callchain(data: bytes) -> list[tuple[str, int]]:
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


def _first_rts_in_window(data: bytes, target_offset: int) -> int | None:
    end = _function_end(data, target_offset)
    stop = min(end, target_offset + 0x20)
    return next(
        (pos for pos in range(target_offset, stop, 2) if be16(data, pos) == 0x000B),
        None,
    )


def analyze(image: Path) -> dict:
    root = read_root_payloads(image)
    main = root["payloads"].get("0TH2.BIN", b"")
    if not main:
        return {
            "schema_version": 1,
            "stage": "stage91_delay_slot_entry_reference_audit",
            "analysis": {
                "main_executable_present": False,
                "leaf_delay_slots_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }
    candidates = _leaf_targets_from_callchain(main)
    profiles = []
    for shape, target in candidates:
        target_offset = target - CODE_LOAD_ADDRESS
        rts_pos = _first_rts_in_window(main, target_offset)
        if rts_pos is None:
            continue
        delay_offset = rts_pos + 2
        target_refs = summarize_address_references(main, target_offset, root["payloads"])
        delay_refs = summarize_address_references(main, delay_offset, root["payloads"])
        profiles.append({
            "target_shape": shape,
            "target_pc_literal_refs": target_refs["pc_relative_literal_refs"],
            "target_resolved_jsr_calls": target_refs["resolved_literal_backed_jsr_calls"],
            "target_raw_words_in_scanned_root_payloads": target_refs[
                "raw_big_endian_words_in_scanned_root_payloads"
            ],
            "delay_slot_pc_literal_refs": delay_refs["pc_relative_literal_refs"],
            "delay_slot_resolved_jsr_calls": delay_refs["resolved_literal_backed_jsr_calls"],
            "delay_slot_raw_words_in_scanned_root_payloads": delay_refs[
                "raw_big_endian_words_in_scanned_root_payloads"
            ],
            "delay_slot_direct_branch_target_refs": delay_refs["direct_branch_target_refs"],
            "delay_slot_has_frame_prologue_signature": delay_refs[
                "has_frame_prologue_signature"
            ],
            "delay_slot_has_direct_entry_evidence": delay_refs[
                "direct_entry_evidence_present"
            ],
        })
    return {
        "schema_version": 1,
        "stage": "stage91_delay_slot_entry_reference_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            "leaf_delay_slots_resolved": len(profiles) == len(candidates) and bool(profiles),
            "scanned_root_payloads": root["full_payloads_scanned"],
            "large_files_prefix_scanned_only": root["large_files_prefix_scanned"],
            "leaf_target_profiles": profiles,
            "all_observed_delay_slots_have_no_direct_entry_evidence": (
                bool(profiles)
                and all(not item["delay_slot_has_direct_entry_evidence"] for item in profiles)
            ),
            "computed_or_table_dispatch_excluded": False,
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
