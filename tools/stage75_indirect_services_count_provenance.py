#!/usr/bin/env python3
"""Stage75: trace service-vector use and command-count assignment provenance.

The original Saturn image stays private and local. Output is aggregate-only:
no game RAM addresses, code offsets, instruction words, or proprietary payload.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage46_vdp1_submit_gate import find_submit_gates
from stage71_callback_dispatch_chain import (
    CODE_LOAD_ADDRESS,
    TARGET_CALLBACK_ID,
    _find_negative_writer_registrations,
)
from stage73_memory_path_audit import audit_helper_transfer
from stage74_scu_dma_handler_audit import (
    _audit_command_count,
    audit_dma_chain,
)

SOURCE_COUNT_FIELD = 0x0609BA7C
COMMAND_COUNT_FIELD = 0x0609651C
SERVICE_ADDRESSES = (0x06000300, 0x06000304, 0x06000310, 0x06000314)
PRODUCER_ENTRY = 0x45A8
INITIALIZER_ENTRY = 0x042E
MARKER_HELPER_ENTRY = 0x044E
SOURCE_ZERO_STORE = 0x4A9A
SOURCE_COPY_STORE = 0x4AB2
MARKER_COPY_SITES = (
    {
        "source_load": 0x1D12, "source_read": 0x1D24,
        "count_pointer": 0x1D26, "marker_pointer": 0x1D28,
        "call": 0x1D2A, "store": 0x1D2C,
        "source_reg": 4, "value_reg": 1, "count_reg": 2,
    },
    {
        "source_load": 0x2380, "source_read": 0x23B8,
        "count_pointer": 0x23BA, "marker_pointer": 0x23BC,
        "call": 0x23BE, "store": 0x23C0,
        "source_reg": 4, "value_reg": 2, "count_reg": 3,
    },
)


def _may_write_register(opcode: int, register: int) -> bool:
    group = opcode >> 12
    destination = (opcode >> 8) & 0xF
    return group in (0x3, 0x4, 0x5, 0x6, 0x7, 0x9, 0xD, 0xE) and destination == register


def _movw_literal(data: bytes, pos: int) -> tuple[int, int, int] | None:
    if pos < 0 or pos & 1 or pos + 2 > len(data):
        return None
    opcode = be16(data, pos)
    if opcode & 0xF000 != 0x9000:
        return None
    register = (opcode >> 8) & 0xF
    literal_pos = ((pos + 4) & ~1) + (opcode & 0xFF) * 2
    if literal_pos + 2 > len(data):
        return None
    return literal_pos, be16(data, literal_pos), register


def _literal_refs(data: bytes, value: int) -> list[tuple[int, int]]:
    return [
        (pos, item[2])
        for pos in range(0, len(data) - 5, 2)
        if (item := movl_literal(data, pos)) is not None and item[1] == value
    ]


def _word_store_to_register(opcode: int, pointer_register: int) -> tuple[bool, int]:
    if opcode & 0xF00F != 0x2001 or ((opcode >> 8) & 0xF) != pointer_register:
        return False, -1
    return True, (opcode >> 4) & 0xF


def _source_field_audit(data: bytes) -> dict:
    refs = _literal_refs(data, SOURCE_COUNT_FIELD)
    writers = []
    for pos, pointer_reg in refs:
        for store_pos in range(pos + 2, min(len(data) - 1, pos + 0x10), 2):
            is_store, source_reg = _word_store_to_register(be16(data, store_pos), pointer_reg)
            if is_store:
                writers.append((pos, store_pos, pointer_reg, source_reg))

    zero_writer = any(
        load_pos == 0x4A96 and store_pos == SOURCE_ZERO_STORE
        and pointer_reg == 2 and source_reg == 10
        for load_pos, store_pos, pointer_reg, source_reg in writers
    )
    zero_local_dataflow = (
        be16(data, 0x45E0) == 0xEA00
        and not any(
            _may_write_register(be16(data, pos), 10)
            for pos in range(0x45E2, SOURCE_ZERO_STORE, 2)
        )
    )
    count_pointer = movl_literal(data, 0x45C4)
    count_copy_writer = any(
        load_pos == 0x4AAC and store_pos == SOURCE_COPY_STORE
        and pointer_reg == 0 and source_reg == 2
        for load_pos, store_pos, pointer_reg, source_reg in writers
    )
    count_copy_dataflow = (
        count_pointer is not None and count_pointer[2] == 13
        and count_pointer[1] == COMMAND_COUNT_FIELD
        and be16(data, 0x4AB0) == 0x62D1
        and be16(data, SOURCE_COPY_STORE) == 0x2021
        and not any(
            _may_write_register(be16(data, pos), 13)
            for pos in range(0x45C6, 0x4AB0, 2)
        )
    )
    return {
        "source_field_literal_reference_sites": len(refs),
        "source_field_direct_word_writer_sites": len(writers),
        "source_field_zero_writer_shape_verified": zero_writer,
        "source_field_zero_local_register_dataflow_verified": zero_local_dataflow,
        "source_field_count_copy_writer_shape_verified": count_copy_writer,
        "source_field_count_copy_from_command_count_verified": count_copy_dataflow,
        "source_field_writer_values_locally_resolved": (
            zero_writer and zero_local_dataflow and count_copy_writer and count_copy_dataflow
        ),
        "source_field_initial_value_present_in_loaded_image": (
            0 <= SOURCE_COUNT_FIELD - CODE_LOAD_ADDRESS < len(data)
        ),
    }


def _marker_copy_audit(data: bytes) -> dict:
    verified = []
    for item in MARKER_COPY_SITES:
        source = movl_literal(data, item["source_load"])
        count_ptr = movl_literal(data, item["count_pointer"])
        marker_ptr = movl_literal(data, item["marker_pointer"])
        source_read = be16(data, item["source_read"])
        store = be16(data, item["store"])
        source_ok = (
            source is not None and source[1] == SOURCE_COUNT_FIELD
            and source[2] == item["source_reg"]
        )
        count_ok = (
            count_ptr is not None and count_ptr[1] == COMMAND_COUNT_FIELD
            and count_ptr[2] == item["count_reg"]
        )
        marker_ok = (
            marker_ptr is not None
            and marker_ptr[1] == CODE_LOAD_ADDRESS + MARKER_HELPER_ENTRY
        )
        read_ok = (
            source_read & 0xF00F == 0x6001
            and ((source_read >> 4) & 0xF) == item["source_reg"]
            and ((source_read >> 8) & 0xF) == item["value_reg"]
        )
        store_ok = (
            store & 0xF00F == 0x2001
            and ((store >> 8) & 0xF) == item["count_reg"]
            and ((store >> 4) & 0xF) == item["value_reg"]
            and be16(data, item["call"]) in (0x410B, 0x430B)
        )
        verified.append(source_ok and count_ok and marker_ok and read_ok and store_ok)
    return {
        "count_assignments_from_source_field_verified": all(verified),
        "count_assignment_copy_sites_verified": sum(verified),
        "count_assignment_sources_are_same_global_field": all(verified),
    }


def _producer_initialization_audit(data: bytes) -> dict:
    init_address = CODE_LOAD_ADDRESS + INITIALIZER_ENTRY
    producer_address = CODE_LOAD_ADDRESS + PRODUCER_ENTRY
    init_refs = _literal_refs(data, init_address)
    producer_refs = _literal_refs(data, producer_address)
    init_calls = [
        pos for pos, reg in init_refs
        if reg == 1 and be16(data, pos + 2) == 0x410B
    ]
    producer_calls = [
        pos for pos, reg in producer_refs
        if reg == 1 and be16(data, pos + 2) == 0x410B
    ]
    init_literal = movl_literal(data, INITIALIZER_ENTRY + 0x06)
    initializer_resets_count = (
        be16(data, INITIALIZER_ENTRY) == 0xE200
        and init_literal is not None and init_literal[2] == 5
        and init_literal[1] == COMMAND_COUNT_FIELD
        and be16(data, INITIALIZER_ENTRY + 0x0A) == 0x2521
    )
    pairs = []
    for producer_pos in producer_calls:
        prior = [pos for pos in init_calls if 0 < producer_pos - pos <= 0x20]
        pairs.append(bool(prior) and initializer_resets_count)
    return {
        "producer_entry_reference_sites": len(producer_refs),
        "initializer_call_sites": len(init_calls),
        "producer_call_sites": len(producer_calls),
        "initializer_resets_command_count": initializer_resets_count,
        "all_static_producer_calls_preceded_by_zero_seed": (
            len(producer_calls) == 2 and len(init_calls) == 2 and all(pairs)
        ),
    }


def _service_entry_audit(data: bytes) -> dict:
    all_refs = []
    refs_by_address = {}
    for address in SERVICE_ADDRESSES:
        refs = _literal_refs(data, address)
        refs_by_address[address] = refs
        all_refs.extend((address, pos, reg) for pos, reg in refs)

    nearby_store_sites = set()
    dereference_calls = 0
    for address, pos, reg in all_refs:
        for store_pos in range(pos + 2, min(len(data) - 1, pos + 0x10), 2):
            is_store, _ = _word_store_to_register(be16(data, store_pos), reg)
            if is_store:
                nearby_store_sites.add(store_pos)
        if address == SERVICE_ADDRESSES[0] and reg == 3:
            dereference_calls += (
                be16(data, pos + 4) == 0x6332 and be16(data, pos + 8) == 0x430B
            )
        elif address == SERVICE_ADDRESSES[2] and reg == 2:
            dereference_calls += (
                be16(data, pos + 4) == 0x6222 and be16(data, pos + 8) == 0x420B
            )
        elif address in (SERVICE_ADDRESSES[1], SERVICE_ADDRESSES[3]) and reg == 1:
            dereference_calls += (
                be16(data, pos + 4) == 0x6112 and be16(data, pos + 8) == 0x410B
            )

    direct_tail_jump = False
    for pos, reg in refs_by_address[SERVICE_ADDRESSES[0]]:
        if reg != 2 or pos + 0x18 + 2 > len(data):
            continue
        if (
            be16(data, pos + 0x0E) == 0x6322
            and be16(data, pos + 0x18) == 0x432B
            and not any(
                _may_write_register(be16(data, q), 3)
                for q in range(pos + 0x10, pos + 0x18, 2)
            )
        ):
            direct_tail_jump = True
            break
    return {
        "service_entry_literal_reference_sites": len(all_refs),
        "service_entry_nearby_direct_store_sites": len(nearby_store_sites),
        "service_entry_dereference_call_patterns_verified": int(dereference_calls),
        "service_vector_tail_jump_through_pointer_verified": direct_tail_jump,
        "service_entry_has_tail_jump_and_indirect_call_use": (
            direct_tail_jump and dereference_calls >= 6
        ),
        "service_entry_runtime_contents_resolved": False,
        "service_entry_initialization_path_resolved": False,
        "runtime_service_completion_confirmed": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    gates = find_submit_gates(data)
    gate = gates[0] if len(gates) == 1 else None
    status_address = gate["status_address"] if gate else None
    registrations, _ = (
        _find_negative_writer_registrations(data, status_address)
        if status_address is not None else ([], 0)
    )
    id64 = [item for item in registrations if item["callback_id"] == TARGET_CALLBACK_ID]
    callback_entry = id64[0]["callback_entry"] if len(id64) == 1 else -1
    callback_helper = movl_literal(data, callback_entry + 0x28) if callback_entry >= 0 else None
    helper_entry = (
        callback_helper[1] - CODE_LOAD_ADDRESS
        if callback_helper is not None and callback_helper[2] == 3
        and CODE_LOAD_ADDRESS <= callback_helper[1] < CODE_LOAD_ADDRESS + len(data)
        else -1
    )
    helper_audit = (
        audit_helper_transfer(data, callback_entry, gate["count_address"])
        if gate is not None and callback_entry >= 0 else {}
    )
    count_address = (
        movl_literal(data, callback_entry + 0x18)[1]
        if callback_entry >= 0 and movl_literal(data, callback_entry + 0x18) is not None
        else COMMAND_COUNT_FIELD
    )
    count_audit = _audit_command_count(data, count_address)
    dma_audit = audit_dma_chain(data, callback_entry, helper_entry)
    source_audit = _source_field_audit(data)
    marker_audit = _marker_copy_audit(data)
    init_audit = _producer_initialization_audit(data)
    service_audit = _service_entry_audit(data)

    source_cycle_locally_resolved = (
        source_audit["source_field_writer_values_locally_resolved"]
        and marker_audit["count_assignments_from_source_field_verified"]
        and init_audit["all_static_producer_calls_preceded_by_zero_seed"]
    )
    unclassified = count_audit["command_count_increment_sites_without_guard_or_zero_reset"]
    return {
        "schema_version": 1,
        "stage": "stage75_indirect_services_count_provenance",
        "target_file": "0TH2.BIN",
        "analysis": {
            "unique_submit_gate_signature": len(gates) == 1,
            "callback_id_64_registration_sites": len(id64),
            "callback_length_formula_verified": bool(
                helper_audit.get("callback_length_formula_is_signed_word_times_32_plus_2", False)
            ),
            **{key: value for key, value in dma_audit.items()},
            **source_audit,
            **marker_audit,
            **init_audit,
            **service_audit,
            "command_count_increment_sites_recognized": count_audit[
                "command_count_increment_sites_recognized"
            ],
            "command_count_increment_sites_guarded_by_limit": count_audit[
                "command_count_increment_sites_guarded_by_limit"
            ],
            "command_count_guard_limits": count_audit["command_count_guard_limits"],
            "command_count_increment_sites_after_local_zero_reset": count_audit[
                "command_count_increment_sites_after_local_zero_reset"
            ],
            "command_count_increment_sites_without_guard_or_zero_reset": unclassified,
            "command_count_unresolved_assignments_after_source_trace": 0 if (
                marker_audit["count_assignments_from_source_field_verified"]
            ) else count_audit["command_count_unresolved_register_assignment_sites"],
            "source_count_assignment_cycle_locally_resolved": source_cycle_locally_resolved,
            "source_field_zero_path_transitive_r10_preservation_proven": False,
            "source_field_writer_values_fully_resolved": False,
            "steady_state_count_bound_508_proven": (
                source_cycle_locally_resolved and unclassified == 0
                and count_audit["command_count_increment_sites_guarded_by_limit"]
                + count_audit["command_count_increment_sites_after_local_zero_reset"]
                == count_audit["command_count_increment_sites_recognized"]
            ),
            "bound_would_hold_if_unclassified_increment_is_unreachable_and_r10_zero_survives_calls": (
                source_cycle_locally_resolved and unclassified == 1
            ),
            "cold_start_count_bound_proven": False,
            "runtime_handler_selection_confirmed": False,
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
