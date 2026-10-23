#!/usr/bin/env python3
"""Stage87: trace SET filename-table references to bounded call contexts.

The original Saturn ISO stays local. The output contains aggregate counts and
booleans only; string offsets, instruction addresses and payload bytes are not
emitted. A nearby indirect call is not automatically a file-loader proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16
from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import (
    LENGTH_SOURCE_GLOBAL,
    _direct_store_sites,
    _may_write_register,
    _resolve_callback,
)
from stage76_length_field_feedback_cfg import _find_routine_prologues
from stage81_callback64_callsite_census import literal_backed_jsr_sites
from stage83_unpaired_callback_context_audit import generic_prologue_candidates
from stage86_set_module_signature_audit import read_root_payloads

SET_NAMES = tuple(f"SET{i:02d}.BIN".encode("ascii") for i in range(8))
WRITER_TARGET_FALLBACK = 0x060085A8
LOW_BASE_HYPOTHESES = (0x06000000, CODE_LOAD_ADDRESS)


def _occurrences(data: bytes, needle: bytes) -> list[int]:
    found = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return found
        found.append(pos)
        start = pos + 1


def _pc_literal_refs(data: bytes, target: int) -> list[tuple[int, int, int]]:
    return [
        (pos, literal[0], literal[2])
        for pos in range(0, len(data) - 5, 2)
        if (literal := movl_literal(data, pos)) is not None
        and literal[1] == target
    ]


def _raw_pointer_summary(data: bytes, target: int) -> dict:
    positions = _occurrences(data, target.to_bytes(4, "big"))
    return {
        "raw_big_endian_words": len(positions),
        "raw_words_aligned_to_longword": sum(pos % 4 == 0 for pos in positions),
    }


def _is_jsr(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x400B


def _call_target_from_recent_literal(
    data: bytes, call_pos: int, lookback_bytes: int = 0x20
) -> int | None:
    opcode = be16(data, call_pos)
    if not _is_jsr(opcode):
        return None
    target_reg = (opcode >> 8) & 0xF
    start = max(0, call_pos - lookback_bytes)
    for load_pos in range(call_pos - 2, start - 1, -2):
        literal = movl_literal(data, load_pos)
        if literal is None or literal[2] != target_reg:
            continue
        if any(
            _may_write_register(be16(data, pos), target_reg)
            for pos in range(load_pos + 2, call_pos, 2)
        ):
            continue
        return literal[1]
    return None


def _first_call_preserving_argument(
    data: bytes, ref_pos: int, argument_reg: int, window_bytes: int = 0x40
) -> dict:
    stop = min(len(data) - 1, ref_pos + window_bytes)
    for call_pos in range(ref_pos + 2, stop, 2):
        if not _is_jsr(be16(data, call_pos)):
            continue
        if any(
            _may_write_register(be16(data, pos), argument_reg)
            for pos in range(ref_pos + 2, call_pos, 2)
        ):
            continue
        target = _call_target_from_recent_literal(data, call_pos)
        target_entry = (
            target - CODE_LOAD_ADDRESS
            if target is not None and CODE_LOAD_ADDRESS <= target < CODE_LOAD_ADDRESS + len(data)
            else None
        )
        prologue = (
            target_entry is not None
            and target_entry + 4 <= len(data)
            and be16(data, target_entry) == 0x2FE6
            and be16(data, target_entry + 2) == 0x4F22
        )
        return {
            "call_found_before_argument_register_is_clobbered": True,
            "call_target_resolved_from_nearby_pc_literal": target is not None,
            "call_target_lies_in_same_loaded_executable": target_entry is not None,
            "call_target_has_simple_frame_prologue": prologue,
            "argument_register_preserved_at_call": True,
        }
    return {
        "call_found_before_argument_register_is_clobbered": False,
        "call_target_resolved_from_nearby_pc_literal": False,
        "call_target_lies_in_same_loaded_executable": False,
        "call_target_has_simple_frame_prologue": False,
        "argument_register_preserved_at_call": False,
    }


def _candidate_function_interval(data: bytes, site: int) -> tuple[int, int] | None:
    prologues = generic_prologue_candidates(data)
    previous = [pos for pos in prologues if pos < site]
    following = [pos for pos in prologues if pos > site]
    if not previous:
        return None
    return max(previous), min(following) if following else len(data)


def summarize_main_filename_table(data: bytes) -> dict:
    name_offsets = {
        name: _occurrences(data, name)
        for name in SET_NAMES[:7]
    }
    all_once = all(len(name_offsets[name]) == 1 for name in SET_NAMES[:7])
    offsets = [name_offsets[name][0] for name in SET_NAMES[:7] if name_offsets[name]]
    contiguous = (
        len(offsets) == 7
        and all(offsets[index + 1] - offsets[index] == len(SET_NAMES[index]) + 1
                for index in range(6))
    )
    base_offset = offsets[0] if offsets else None
    ref_sites = (
        _pc_literal_refs(data, CODE_LOAD_ADDRESS + base_offset)
        if base_offset is not None else []
    )
    later_refs = sum(
        len(_pc_literal_refs(data, CODE_LOAD_ADDRESS + offset))
        for offset in offsets[1:]
    )
    interval = (
        _candidate_function_interval(data, ref_sites[0][0])
        if ref_sites else None
    )
    interval_jsr_count = 0
    interval_jmp_count = 0
    call_summary = {
        "call_found_before_argument_register_is_clobbered": False,
        "call_target_resolved_from_nearby_pc_literal": False,
        "call_target_lies_in_same_loaded_executable": False,
        "call_target_has_simple_frame_prologue": False,
        "argument_register_preserved_at_call": False,
    }
    if interval is not None:
        start, end = interval
        interval_jsr_count = sum(
            _is_jsr(be16(data, pos))
            for pos in range(start, max(start, end - 1), 2)
        )
        interval_jmp_count = sum(
            (be16(data, pos) & 0xF0FF) == 0x402B
            for pos in range(start, max(start, end - 1), 2)
        )
        call_summary = _first_call_preserving_argument(
            data, ref_sites[0][0], ref_sites[0][2]
        )
    return {
        "set00_to_set06_name_occurrences_each_once": all_once,
        "set00_to_set06_names_form_contiguous_ten_byte_table": contiguous,
        "filename_table_entries": len(offsets),
        "pc_literal_refs_to_first_filename": len(ref_sites),
        "pc_literal_refs_to_later_filename_entries": later_refs,
        "table_reference_has_candidate_function_interval": interval is not None,
        "candidate_function_jsr_like_sites": interval_jsr_count,
        "candidate_function_jmp_like_sites": interval_jmp_count,
        **call_summary,
        "main_table_raw_pointer_words_under_zero_base_hypothesis": (
            _raw_pointer_summary(data, 0x06000000 + base_offset)["raw_big_endian_words"]
            if base_offset is not None else 0
        ),
        "main_table_raw_pointer_words_under_code_base_hypothesis": (
            _raw_pointer_summary(data, CODE_LOAD_ADDRESS + base_offset)["raw_big_endian_words"]
            if base_offset is not None else 0
        ),
        "loader_api_identity_confirmed": False,
        "filename_table_runtime_iteration_proven": False,
    }


def summarize_low_set07(data: bytes) -> dict:
    offsets = _occurrences(data, b"SET07.BIN")
    direct_refs = 0
    raw_refs = 0
    if len(offsets) == 1:
        for base in LOW_BASE_HYPOTHESES:
            target = base + offsets[0]
            direct_refs += len(_pc_literal_refs(data, target))
            raw_refs += _raw_pointer_summary(data, target)["raw_big_endian_words"]
    return {
        "set07_name_occurrences": len(offsets),
        "direct_pc_literal_refs_under_candidate_load_bases": direct_refs,
        "raw_pointer_words_under_candidate_load_bases": raw_refs,
        "low_module_load_base_resolved": False,
        "set07_load_callsite_resolved": False,
        "set07_executable_overlay_role_confirmed": False,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    low = payloads.get("TH2.LOW", b"")
    callback_entry, _, callback_chain = _resolve_callback(main) if main else (None, None, False)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_chain and callback_entry is not None else None
    )
    source_stores = set(_direct_store_sites(main, LENGTH_SOURCE_GLOBAL)) if main else set()
    prologues = _find_routine_prologues(main) if main else []
    writer_candidates = [pos for pos in prologues if source_stores and pos < min(source_stores)]
    writer_entry = max(writer_candidates) if writer_candidates else None
    writer_address = (
        CODE_LOAD_ADDRESS + writer_entry if writer_entry is not None else None
    )
    set_call_results = []
    for index in range(8):
        name = f"SET{index:02d}.BIN"
        data = payloads.get(name)
        if data is None:
            continue
        set_call_results.append({
            "file": name,
            "literal_backed_writer_jsr_sites": (
                len(literal_backed_jsr_sites(data, writer_address))
                if writer_address is not None else 0
            ),
            "literal_backed_callback_id64_jsr_sites": (
                len(literal_backed_jsr_sites(data, callback_address))
                if callback_address is not None else 0
            ),
        })
    main_table = summarize_main_filename_table(main) if main else {}
    low_name = summarize_low_set07(low) if low else {}
    return {
        "schema_version": 1,
        "stage": "stage87_set_filename_loader_context",
        "target_files": ["0TH2.BIN", "TH2.LOW", "SET00.BIN–SET07.BIN"],
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "writer_target_resolved": writer_address is not None,
            "main_filename_table": main_table,
            "low_set07_reference": low_name,
            "set_file_direct_calls_to_writer_or_callback": set_call_results,
            "all_set_file_entrypoints_resolved": False,
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
