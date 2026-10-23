#!/usr/bin/env python3
"""Stage88: trace the SET00 filename pointer through nested call candidates.

The original Saturn ISO stays local. This is a bounded literal-backed call
census, not a complete disassembler or proof of file I/O semantics.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import _may_write_register
from stage83_unpaired_callback_context_audit import generic_prologue_candidates
from stage86_set_module_signature_audit import read_root_payloads
from stage87_set_filename_loader_context import (
    SET_NAMES,
    _call_target_from_recent_literal,
    _is_jsr,
    _occurrences,
    _pc_literal_refs,
)

ARGUMENT_REGISTER = 1


def _has_frame_prologue(data: bytes, entry: int) -> bool:
    if entry < 0 or entry + 2 > len(data) or be16(data, entry) != 0x2FE6:
        return False
    if entry + 4 <= len(data) and be16(data, entry + 2) == 0x4F22:
        return True
    words = [
        be16(data, entry + offset)
        for offset in range(2, 0x1A, 2)
        if entry + offset + 2 <= len(data)
    ]
    try:
        pr_position = words.index(0x4F22)
    except ValueError:
        return False
    pushes = [
        index for index, opcode in enumerate(words)
        if opcode in (0x2FD6, 0x2FC6, 0x2FB6, 0x2FA6, 0x2F96, 0x2F86)
    ]
    return bool(pushes) and min(pushes) < pr_position


def _function_end(data: bytes, entry: int) -> int:
    following = [pos for pos in generic_prologue_candidates(data) if pos > entry]
    return min(following) if following else len(data)


def _inside_candidate_interval(
    data_length: int, target_offset: int, prologues: list[int]
) -> bool:
    if target_offset < 0 or target_offset >= data_length or target_offset in prologues:
        return False
    previous = [pos for pos in prologues if pos < target_offset]
    if not previous:
        return False
    start = max(previous)
    following = [pos for pos in prologues if pos > start]
    end = min(following) if following else data_length
    return start < target_offset < end


def _resolve_call_sites(data: bytes, entry: int, end: int) -> list[tuple[int, int | None]]:
    calls = []
    for pos in range(entry, max(entry, end - 1), 2):
        if _is_jsr(be16(data, pos)):
            calls.append((pos, _call_target_from_recent_literal(data, pos)))
    return calls


def summarize_function(data: bytes, entry: int, end: int) -> dict:
    calls = _resolve_call_sites(data, entry, end)
    resolved = [target for _, target in calls if target is not None]
    in_executable = [
        target for target in resolved
        if CODE_LOAD_ADDRESS <= target < CODE_LOAD_ADDRESS + len(data)
    ]
    prologues = generic_prologue_candidates(data)
    frame_targets = [
        target for target in in_executable
        if _has_frame_prologue(data, target - CODE_LOAD_ADDRESS)
    ]
    internal_targets = [
        target for target in in_executable
        if not _has_frame_prologue(data, target - CODE_LOAD_ADDRESS)
        and _inside_candidate_interval(
            len(data), target - CODE_LOAD_ADDRESS, prologues
        )
    ]
    first_call = calls[0][0] if calls else None
    r1_not_explicitly_written = (
        first_call is not None
        and not any(
            _may_write_register(be16(data, pos), ARGUMENT_REGISTER)
            for pos in range(entry, first_call, 2)
        )
    )
    return {
        "candidate_function_interval_bytes": max(0, end - entry),
        "jsr_like_sites": len(calls),
        "jsr_sites_with_nearby_literal_target": len(resolved),
        "unique_literal_targets": len(set(resolved)),
        "unique_targets_inside_main_executable": len(set(in_executable)),
        "unique_targets_with_frame_prologue_signature": len(set(frame_targets)),
        "unique_targets_without_frame_prologue_inside_candidate_interval": len(set(internal_targets)),
        "first_jsr_target_resolved": bool(calls and calls[0][1] is not None),
        "r1_not_explicitly_written_before_first_jsr": r1_not_explicitly_written,
        "all_jsr_literal_targets_resolved": bool(calls) and len(resolved) == len(calls),
    }


def _first_preserved_filename_call(data: bytes) -> tuple[int, int, int] | None:
    name_offsets = _occurrences(data, SET_NAMES[0])
    if len(name_offsets) != 1:
        return None
    refs = _pc_literal_refs(data, CODE_LOAD_ADDRESS + name_offsets[0])
    if len(refs) != 1:
        return None
    ref_pos, _, arg_reg = refs[0]
    for call_pos in range(ref_pos + 2, min(len(data) - 1, ref_pos + 0x40), 2):
        if not _is_jsr(be16(data, call_pos)):
            continue
        if any(
            _may_write_register(be16(data, pos), arg_reg)
            for pos in range(ref_pos + 2, call_pos, 2)
        ):
            continue
        target = _call_target_from_recent_literal(data, call_pos)
        if target is not None:
            return call_pos, arg_reg, target
    return None


def analyze(image: Path) -> dict:
    root = read_root_payloads(image)
    main = root["payloads"].get("0TH2.BIN", b"")
    if not main:
        return {
            "schema_version": 1,
            "stage": "stage88_filename_helper_callchain",
            "analysis": {
                "main_executable_present": False,
                "filename_helper_call_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }
    first_call = _first_preserved_filename_call(main)
    if first_call is None:
        return {
            "schema_version": 1,
            "stage": "stage88_filename_helper_callchain",
            "analysis": {
                "main_executable_present": True,
                "filename_helper_call_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    _, _, helper_target = first_call
    helper_entry = helper_target - CODE_LOAD_ADDRESS
    if not 0 <= helper_entry < len(main):
        return {
            "schema_version": 1,
            "stage": "stage88_filename_helper_callchain",
            "analysis": {
                "main_executable_present": True,
                "filename_helper_call_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    helper_end = _function_end(main, helper_entry)
    helper1 = summarize_function(main, helper_entry, helper_end)
    helper1_calls = _resolve_call_sites(main, helper_entry, helper_end)
    first_nested_target = next(
        (target for _, target in helper1_calls if target is not None), None
    )
    helper2 = {}
    helper3 = {}
    second_nested_target = None
    if first_nested_target is not None:
        helper2_entry = first_nested_target - CODE_LOAD_ADDRESS
        if 0 <= helper2_entry < len(main):
            helper2_end = _function_end(main, helper2_entry)
            helper2 = summarize_function(main, helper2_entry, helper2_end)
            helper2_calls = _resolve_call_sites(main, helper2_entry, helper2_end)
            second_nested_target = next(
                (target for _, target in helper2_calls if target is not None), None
            )
            if second_nested_target is not None:
                helper3_entry = second_nested_target - CODE_LOAD_ADDRESS
                if 0 <= helper3_entry < len(main):
                    helper3_end = _function_end(main, helper3_entry)
                    helper3 = summarize_function(main, helper3_entry, helper3_end)

    return {
        "schema_version": 1,
        "stage": "stage88_filename_helper_callchain",
        "target_file": "0TH2.BIN",
        "analysis": {
            "filename_helper_call_resolved": True,
            "filename_argument_register_preserved_to_helper_call": True,
            "helper_target_inside_main_executable": True,
            "helper_target_has_frame_prologue_signature": _has_frame_prologue(
                main, helper_entry
            ),
            "first_helper": helper1,
            "first_nested_callee": helper2,
            "next_nested_callee": helper3,
            "filename_argument_flow_is_only_a_register_preservation_candidate": True,
            "file_open_or_read_semantics_confirmed": False,
            "full_control_flow_reachability_proven": False,
            "indirect_callee_register_effects_modeled": False,
            "prior_bsr_callee_register_effects_modeled": False,
            "all_alternate_function_entries_excluded": False,
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
