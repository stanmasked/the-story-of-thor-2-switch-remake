#!/usr/bin/env python3
"""Stage81: classify every literal-backed callback-ID64 callsite in 0TH2.BIN.

Outputs aggregate counts only. Literal-backed callsites do not exhaust
computed pointers, table dispatch, or runtime-created callback targets.
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
    _count_length_assignments,
    _direct_store_sites,
    _resolve_callback,
)
from stage76_length_field_feedback_cfg import _find_routine_prologues


def literal_backed_jsr_sites(data: bytes, target_address: int) -> list[int]:
    sites = set()
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None or literal[1] != target_address:
            continue
        register = literal[2]
        if be16(data, pos + 2) == (0x400B | (register << 8)):
            sites.add(pos + 2)
    return sorted(sites)


def classify_callback_calls(
    callback_sites: list[int],
    writer_sites: list[int],
    length_copy_sites: set[int],
    known_global_copy_sites: set[int],
) -> dict:
    writer_set = set(writer_sites)
    paired = {
        call for call in callback_sites
        if call - 6 in writer_set
    }
    copied = set(callback_sites) & length_copy_sites
    known_copy = set(callback_sites) & known_global_copy_sites
    classified = paired | copied
    return {
        "callback_id64_literal_jsr_sites": len(callback_sites),
        "callback_sites_followed_by_writer_predecessor": len(paired),
        "callback_sites_with_length_field_delay_store": len(copied),
        "callback_sites_copying_known_global_source": len(known_copy),
        "callback_sites_not_preceded_by_writer": len(set(callback_sites) - paired),
        "callback_sites_unclassified_by_known_patterns": len(set(callback_sites) - classified),
        "all_detected_callback_sites_match_a_known_pattern": (
            bool(callback_sites) and classified == set(callback_sites)
        ),
        "writer_sites_without_immediate_callback_pair": (
            len(writer_set - {call - 6 for call in paired})
        ),
        "source_global_initialized_before_all_copy_reads_proven": False,
        "literal_reference_census_exhaustive": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    callback_entry, count_address, callback_chain = _resolve_callback(data)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_chain and callback_entry is not None else None
    )
    source_store_sites = set(_direct_store_sites(data, LENGTH_SOURCE_GLOBAL))
    prologues = _find_routine_prologues(data)
    entry_candidates = [
        pos for pos in prologues
        if source_store_sites and pos < min(source_store_sites)
    ]
    writer_entry = max(entry_candidates) if entry_candidates else None
    writer_address = (
        CODE_LOAD_ADDRESS + writer_entry if writer_entry is not None else None
    )

    callback_sites = (
        literal_backed_jsr_sites(data, callback_address)
        if callback_address is not None else []
    )
    writer_sites = (
        literal_backed_jsr_sites(data, writer_address)
        if writer_address is not None else []
    )
    assignments = (
        _count_length_assignments(data, count_address, callback_address)
        if count_address is not None and callback_address is not None else []
    )
    length_copy_sites = {
        item["store_pos"] - 2 for item in assignments
    }
    known_global_copy_sites = {
        item["store_pos"] - 2 for item in assignments
        if item["source_is_known_global"]
    }
    result = classify_callback_calls(
        callback_sites, writer_sites, length_copy_sites,
        known_global_copy_sites,
    )
    return {
        "schema_version": 1,
        "stage": "stage81_callback64_callsite_census",
        "target_file": "0TH2.BIN",
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "writer_entry_resolved": writer_entry is not None,
            "source_field_store_sites_recognized": len(source_store_sites),
            **result,
            "callback_callsite_runtime_execution_confirmed": False,
            "source_field_initialized_before_first_runtime_read_proven": False,
            "global_length_upper_bound_proven": False,
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
