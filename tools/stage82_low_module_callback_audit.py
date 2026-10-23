#!/usr/bin/env python3
"""Stage82: cross-module census of callback ID64 and writer calls.

Scans the main executable and TH2.LOW independently. Only aggregate counts are
emitted; raw pointer occurrences are not proof of table semantics or execution.
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
from stage81_callback64_callsite_census import literal_backed_jsr_sites

SERVICE_SLOT_A = 0x06000300
SERVICE_SLOT_B = 0x06000310


def pc_literal_reference_count(data: bytes, address: int) -> int:
    return sum(
        1 for pos in range(0, len(data) - 5, 2)
        if (literal := movl_literal(data, pos)) is not None
        and literal[1] == address
    )


def count_field_delay_store_sites(
    data: bytes, callback_address: int, count_address: int
) -> set[int]:
    found = set()
    for call_pos in literal_backed_jsr_sites(data, callback_address):
        count_load = movl_literal(data, call_pos - 4)
        callback_load = movl_literal(data, call_pos - 2)
        if (
            count_load is None
            or count_load[1] != count_address
            or callback_load is None
            or callback_load[1] != callback_address
        ):
            continue
        store = be16(data, call_pos + 2)
        if (
            store & 0xF00F == 0x2001
            and ((store >> 8) & 0xF) == count_load[2]
        ):
            found.add(call_pos)
    return found


def summarize_module(
    data: bytes,
    writer_address: int,
    callback_address: int,
    count_address: int,
) -> dict:
    writer_sites = literal_backed_jsr_sites(data, writer_address)
    callback_sites = literal_backed_jsr_sites(data, callback_address)
    writer_set = set(writer_sites)
    paired_callbacks = {
        call for call in callback_sites if call - 6 in writer_set
    }
    paired_writers = {call - 6 for call in paired_callbacks}
    count_stores = count_field_delay_store_sites(
        data, callback_address, count_address
    )
    nop_delays = {
        call for call in callback_sites
        if be16(data, call + 2) == 0x0009
    }
    unpaired_nop = nop_delays - paired_callbacks
    other_delay = {
        call for call in callback_sites
        if call not in nop_delays and call not in count_stores
    }
    classified = paired_callbacks | count_stores | unpaired_nop
    return {
        "literal_backed_writer_jsr_sites": len(writer_sites),
        "literal_backed_callback_id64_jsr_sites": len(callback_sites),
        "writer_then_callback_pairs": len(paired_callbacks),
        "callback_calls_with_count_field_delay_store": len(count_stores),
        "unpaired_callback_calls_with_nop_delay_slot": len(unpaired_nop),
        "callback_calls_with_other_unclassified_delay_slot": len(other_delay),
        "writer_calls_without_immediate_callback_pair": len(
            writer_set - paired_writers
        ),
        "all_literal_backed_callback_sites_fit_observed_patterns": (
            bool(callback_sites) and classified == set(callback_sites)
        ),
        "pc_literal_refs_to_source_global": pc_literal_reference_count(
            data, LENGTH_SOURCE_GLOBAL
        ),
        "pc_literal_refs_to_count_field": pc_literal_reference_count(
            data, count_address
        ),
        "service_slot_a_raw_big_endian_occurrences": data.count(
            SERVICE_SLOT_A.to_bytes(4, "big")
        ),
        "service_slot_b_raw_big_endian_occurrences": data.count(
            SERVICE_SLOT_B.to_bytes(4, "big")
        ),
        "service_slot_a_pc_literal_refs": pc_literal_reference_count(
            data, SERVICE_SLOT_A
        ),
        "service_slot_b_pc_literal_refs": pc_literal_reference_count(
            data, SERVICE_SLOT_B
        ),
        "callback_census_exhaustive": False,
    }


def analyze(image: Path) -> dict:
    main_data = iso_file_payload(image, b"0TH2.BIN")
    low_data = iso_file_payload(image, b"TH2.LOW")
    callback_entry, count_address, callback_chain = _resolve_callback(main_data)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_chain and callback_entry is not None else None
    )
    source_stores = set(_direct_store_sites(main_data, LENGTH_SOURCE_GLOBAL))
    prologues = _find_routine_prologues(main_data)
    entries = [
        pos for pos in prologues
        if source_stores and pos < min(source_stores)
    ]
    writer_entry = max(entries) if entries else None
    writer_address = (
        CODE_LOAD_ADDRESS + writer_entry
        if writer_entry is not None else None
    )
    if callback_address is None or writer_address is None or count_address is None:
        return {
            "schema_version": 1,
            "stage": "stage82_low_module_callback_audit",
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
    assignments = _count_length_assignments(
        main_data, count_address, callback_address
    )
    totals = {
        "total_literal_backed_writer_jsr_sites": (
            main["literal_backed_writer_jsr_sites"]
            + low["literal_backed_writer_jsr_sites"]
        ),
        "total_literal_backed_callback_id64_jsr_sites": (
            main["literal_backed_callback_id64_jsr_sites"]
            + low["literal_backed_callback_id64_jsr_sites"]
        ),
        "total_writer_then_callback_pairs": (
            main["writer_then_callback_pairs"]
            + low["writer_then_callback_pairs"]
        ),
        "total_callback_count_field_delay_store_sites": (
            main["callback_calls_with_count_field_delay_store"]
            + low["callback_calls_with_count_field_delay_store"]
        ),
        "total_unpaired_nop_callback_sites": (
            main["unpaired_callback_calls_with_nop_delay_slot"]
            + low["unpaired_callback_calls_with_nop_delay_slot"]
        ),
        "main_callback_length_assignments_from_known_source_global": sum(
            item["source_is_known_global"] for item in assignments
        ),
        "low_module_pc_literal_refs_to_source_global": low[
            "pc_literal_refs_to_source_global"
        ],
        "all_observed_literal_callback_sites_fit_known_patterns": (
            main["all_literal_backed_callback_sites_fit_observed_patterns"]
            and low["all_literal_backed_callback_sites_fit_observed_patterns"]
        ),
        "source_initialized_before_all_callback_reads_proven": False,
        "computed_or_table_callback_targets_excluded": False,
        "runtime_callback_execution_confirmed": False,
        "runtime_dma_completion_confirmed": False,
        "same_frame_submit_timing_confirmed": False,
        "private_addresses_or_code_offsets_emitted": False,
    }
    return {
        "schema_version": 1,
        "stage": "stage82_low_module_callback_audit",
        "target_files": ["0TH2.BIN", "TH2.LOW"],
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "cross_module_targets_resolved": True,
            "main_executable": main,
            "low_module": low,
            **totals,
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
