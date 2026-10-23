#!/usr/bin/env python3
"""Stage83: bounded caller-context census for unpaired callback ID64 calls.

Function intervals are estimated from stack-frame prologue signatures. They
are not a full disassembly, interprocedural CFG, or runtime call graph.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import (
    LENGTH_SOURCE_GLOBAL,
    _direct_store_sites,
    _resolve_callback,
)
from stage76_length_field_feedback_cfg import _find_routine_prologues
from stage81_callback64_callsite_census import literal_backed_jsr_sites
from stage82_low_module_callback_audit import count_field_delay_store_sites

SERVICE_SLOT_A = 0x06000300
SERVICE_SLOT_B = 0x06000310


def generic_prologue_candidates(data: bytes) -> list[int]:
    found = []
    for pos in range(0, len(data) - 0x24, 2):
        if be16(data, pos) != 0x2FE6:
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


def classify_unpaired_callback_contexts(
    data: bytes,
    callback_sites: list[int],
    writer_sites: list[int],
    paired_callback_sites: set[int],
    length_copy_sites: set[int],
    prologues: list[int],
) -> dict:
    unpaired = set(callback_sites) - paired_callback_sites
    writer_before = 0
    writer_after = 0
    no_writer_in_interval = 0
    unknown_interval = 0
    copy_no_writer = 0
    nop_no_writer = 0
    for call in unpaired:
        previous = [pos for pos in prologues if pos < call]
        following = [pos for pos in prologues if pos > call]
        if not previous:
            unknown_interval += 1
            continue
        start = max(previous)
        end = min(following) if following else len(data)
        in_interval = [pos for pos in writer_sites if start <= pos < end]
        earlier = [pos for pos in in_interval if pos < call]
        later = [pos for pos in in_interval if pos > call]
        if earlier:
            writer_before += 1
        elif later:
            writer_after += 1
        else:
            no_writer_in_interval += 1
        if call in length_copy_sites and not in_interval:
            copy_no_writer += 1
        if be16(data, call + 2) == 0x0009 and not in_interval:
            nop_no_writer += 1
    return {
        "unpaired_callback_sites": len(unpaired),
        "unpaired_callback_sites_with_writer_before_in_candidate_function": writer_before,
        "unpaired_callback_sites_with_writer_after_in_candidate_function": writer_after,
        "unpaired_callback_sites_without_writer_in_candidate_function": no_writer_in_interval,
        "unpaired_callback_sites_without_resolved_candidate_function": unknown_interval,
        "length_copy_sites_without_writer_in_candidate_function": copy_no_writer,
        "nop_delay_callback_sites_without_writer_in_candidate_function": nop_no_writer,
        "candidate_function_intervals_prove_control_flow": False,
    }


def summarize_module(
    data: bytes,
    writer_address: int,
    callback_address: int,
    count_address: int,
) -> dict:
    writer_sites = literal_backed_jsr_sites(data, writer_address)
    callback_sites = literal_backed_jsr_sites(data, callback_address)
    writer_set = set(writer_sites)
    paired = {call for call in callback_sites if call - 6 in writer_set}
    copy_sites = count_field_delay_store_sites(
        data, callback_address, count_address
    )
    context = classify_unpaired_callback_contexts(
        data, callback_sites, writer_sites, paired, copy_sites,
        generic_prologue_candidates(data),
    )
    return {
        "literal_backed_writer_jsr_sites": len(writer_sites),
        "literal_backed_callback_id64_jsr_sites": len(callback_sites),
        "writer_then_callback_pairs": len(paired),
        "callback_count_field_delay_store_sites": len(copy_sites),
        **context,
        "caller_context_census_exhaustive": False,
    }


def analyze(image: Path) -> dict:
    main_data = iso_file_payload(image, b"0TH2.BIN")
    low_data = iso_file_payload(image, b"TH2.LOW")
    callback_entry, count_address, callback_chain = _resolve_callback(main_data)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_chain and callback_entry is not None else None
    )
    stores = set(_direct_store_sites(main_data, LENGTH_SOURCE_GLOBAL))
    prologues = _find_routine_prologues(main_data)
    candidates = [pos for pos in prologues if stores and pos < min(stores)]
    writer_entry = max(candidates) if candidates else None
    writer_address = (
        CODE_LOAD_ADDRESS + writer_entry if writer_entry is not None else None
    )
    if callback_address is None or count_address is None or writer_address is None:
        return {
            "schema_version": 1,
            "stage": "stage83_unpaired_callback_context_audit",
            "analysis": {
                "callback_id64_chain_verified": callback_chain,
                "cross_module_targets_resolved": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }
    main = summarize_module(
        main_data, writer_address, callback_address, count_address
    )
    low = summarize_module(
        low_data, writer_address, callback_address, count_address
    )
    return {
        "schema_version": 1,
        "stage": "stage83_unpaired_callback_context_audit",
        "target_files": ["0TH2.BIN", "TH2.LOW"],
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "cross_module_targets_resolved": True,
            "main_executable": main,
            "low_module": low,
            "total_unpaired_callback_sites": (
                main["unpaired_callback_sites"] + low["unpaired_callback_sites"]
            ),
            "total_unpaired_sites_with_writer_before_in_candidate_function": (
                main["unpaired_callback_sites_with_writer_before_in_candidate_function"]
                + low["unpaired_callback_sites_with_writer_before_in_candidate_function"]
            ),
            "total_unpaired_sites_with_writer_after_in_candidate_function": (
                main["unpaired_callback_sites_with_writer_after_in_candidate_function"]
                + low["unpaired_callback_sites_with_writer_after_in_candidate_function"]
            ),
            "total_unpaired_sites_without_writer_in_candidate_function": (
                main["unpaired_callback_sites_without_writer_in_candidate_function"]
                + low["unpaired_callback_sites_without_writer_in_candidate_function"]
            ),
            "source_initialized_before_all_callback_reads_proven": False,
            "global_length_upper_bound_proven": False,
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
