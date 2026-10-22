#!/usr/bin/env python3
"""Stage76: audit static reachability evidence and early-HWRAM vector patterns.

The original Saturn image stays private and local. Output contains counts and
booleans only, never RAM addresses, code offsets, instruction words, or payload.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage74_scu_dma_handler_audit import _audit_command_count

COMMAND_COUNT_FIELD = 0x0609651C
UNCLASSIFIED_INCREMENT_ENTRY = 0x0448
SOURCE_ZERO_STORE = 0x4A9A
PRODUCER_ENTRY = 0x45A8
HWRAM_SCAN_START = 0x06000000
HWRAM_SCAN_END = 0x06000400


def _may_write_register(opcode: int, register: int) -> bool:
    group = opcode >> 12
    destination = (opcode >> 8) & 0xF
    return group in (0x3, 0x4, 0x5, 0x6, 0x7, 0x9, 0xD, 0xE) and destination == register


def _literal_refs(data: bytes, value: int) -> list[tuple[int, int]]:
    return [
        (pos, item[2])
        for pos in range(0, len(data) - 5, 2)
        if (item := movl_literal(data, pos)) is not None and item[1] == value
    ]


def audit_increment_candidate(data: bytes) -> dict:
    entry = UNCLASSIFIED_INCREMENT_ENTRY
    signature = (
        len(data) > entry + 0x0E
        and be16(data, entry) == 0x6251
        and be16(data, entry + 2) == 0x7201
        and be16(data, entry + 4) == 0x2521
    )
    return_before_candidate = (
        len(data) > entry
        and be16(data, entry - 4) == 0x000B
        and be16(data, entry - 2) == 0x2432
    )
    direct_branch_sites = []
    for pos in range(0, len(data) - 1, 2):
        branch = branch_destination(pos, be16(data, pos))
        if branch is not None and branch[1] == entry:
            direct_branch_sites.append(pos)
    target_address = CODE_LOAD_ADDRESS + entry
    literal_pointer_refs = _literal_refs(data, target_address)
    raw_pointer = target_address.to_bytes(4, "big")
    raw_pointer_refs = data.count(raw_pointer)
    return {
        "unclassified_increment_signature_verified": signature,
        "return_and_delay_slot_precede_candidate": return_before_candidate,
        "direct_branch_targets_to_candidate": len(direct_branch_sites),
        "literal_pointer_refs_to_candidate": len(literal_pointer_refs),
        "raw_absolute_pointer_occurrences_to_candidate": raw_pointer_refs,
        "candidate_has_static_direct_entry": bool(
            direct_branch_sites or literal_pointer_refs or raw_pointer_refs
        ),
        "candidate_reachability_proven": False,
        "computed_or_runtime_indirect_targets_fully_resolved": False,
    }


def audit_hwrm_vector_cluster(data: bytes) -> dict:
    refs = []
    for pos in range(0, len(data) - 5, 2):
        item = movl_literal(data, pos)
        if item is not None and HWRAM_SCAN_START <= item[1] < HWRAM_SCAN_END:
            refs.append((pos, item[1], item[2]))

    call_sites = set()
    refs_with_call_pattern = 0
    nearby_store_sites = set()
    for pos, _address, pointer_reg in refs:
        matched = False
        for store_pos in range(pos + 2, min(len(data) - 1, pos + 0x10), 2):
            opcode = be16(data, store_pos)
            if (
                opcode & 0xF00F in (0x2000, 0x2001, 0x2002)
                and ((opcode >> 8) & 0xF) == pointer_reg
            ):
                nearby_store_sites.add(store_pos)

        for deref_pos in range(pos + 2, min(len(data) - 1, pos + 0x20), 2):
            opcode = be16(data, deref_pos)
            if opcode & 0xF00F != 0x6002 or ((opcode >> 4) & 0xF) != pointer_reg:
                continue
            destination_reg = (opcode >> 8) & 0xF
            for call_pos in range(deref_pos + 2, min(len(data) - 1, deref_pos + 0x12), 2):
                call_opcode = be16(data, call_pos)
                if (
                    call_opcode & 0xF0FF in (0x400B, 0x402B)
                    and ((call_opcode >> 8) & 0xF) == destination_reg
                ):
                    call_sites.add(call_pos)
                    matched = True
        if matched:
            refs_with_call_pattern += 1

    return {
        "early_hwrm_literal_reference_sites": len(refs),
        "distinct_early_hwrm_addresses": len({address for _, address, _ in refs}),
        "references_followed_by_indirect_call_pattern": refs_with_call_pattern,
        "unique_indirect_call_sites": len(call_sites),
        "nearby_direct_store_sites": len(nearby_store_sites),
        "service_vector_contents_resolved": False,
        "service_vector_initializer_resolved": False,
        "runtime_service_completion_confirmed": False,
    }


def audit_r10_source_path(data: bytes) -> dict:
    zero_init = len(data) > 0x45E0 and be16(data, 0x45E0) == 0xEA00
    explicit_reassignments = sum(
        _may_write_register(be16(data, pos), 10)
        for pos in range(0x45E2, min(len(data), SOURCE_ZERO_STORE), 2)
    )
    direct_bsr_sites = []
    direct_targets = set()
    for pos in range(PRODUCER_ENTRY, min(len(data) - 1, SOURCE_ZERO_STORE), 2):
        branch = branch_destination(pos, be16(data, pos))
        if branch is not None and branch[0] == "BSR":
            direct_bsr_sites.append(pos)
            direct_targets.add(branch[1])
    return {
        "source_register_locally_initialized_to_zero": zero_init,
        "explicit_source_register_reassignments_before_store": explicit_reassignments,
        "direct_helper_call_sites_before_source_store": len(direct_bsr_sites),
        "distinct_direct_helper_targets_before_source_store": len(direct_targets),
        "source_register_preservation_across_all_callees_proven": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    increment = audit_increment_candidate(data)
    vectors = audit_hwrm_vector_cluster(data)
    r10 = audit_r10_source_path(data)
    count_audit = _audit_command_count(data, COMMAND_COUNT_FIELD)
    return {
        "schema_version": 1,
        "stage": "stage76_count_block_reachability_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            **increment,
            **vectors,
            **r10,
            "command_count_increment_sites_recognized": count_audit[
                "command_count_increment_sites_recognized"
            ],
            "command_count_increment_sites_guarded_by_limit": count_audit[
                "command_count_increment_sites_guarded_by_limit"
            ],
            "command_count_increment_sites_after_local_zero_reset": count_audit[
                "command_count_increment_sites_after_local_zero_reset"
            ],
            "command_count_increment_sites_without_guard_or_zero_reset": count_audit[
                "command_count_increment_sites_without_guard_or_zero_reset"
            ],
            "global_count_bound_proven": False,
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
