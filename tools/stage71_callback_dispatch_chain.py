#!/usr/bin/env python3
"""Stage71: statically connect callback registration, ID thunk, and status writer.

The original Saturn ISO stays local. Output contains only aggregate booleans and
counts; it never emits executable offsets, global addresses, or instruction bytes.
The scan is deliberately bounded and does not claim runtime invocation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage46_vdp1_submit_gate import find_submit_gates
from stage70_vdp1_status_trigger_audit import scan_status_writes

CODE_LOAD_ADDRESS = 0x06004000
TARGET_CALLBACK_ID = 64
THUNK_ENTRY_COUNT = 256
THUNK_ENTRY_BYTES = 6
CALLBACK_DISPATCHER_SIGNATURE = (
    0x7FF8, 0x6343, 0x4308, 0x2F42, 0x1F31, 0x0356,
)


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _is_code_address(value: int, data: bytes) -> bool:
    return CODE_LOAD_ADDRESS <= value < CODE_LOAD_ADDRESS + len(data)


def _matches_callback_table_dispatcher(data: bytes, entry: int) -> bool:
    if entry < 0 or entry + 32 > len(data):
        return False
    first = movl_literal(data, entry)
    second = movl_literal(data, entry + 4)
    third = movl_literal(data, entry + 8)
    if (
        first is None or first[2] != 0
        or second is None or second[2] != 2
        or third is None or third[2] != 1
    ):
        return False
    if tuple(be16(data, entry + offset) for offset in (2, 6, 10, 12, 14, 16)) != CALLBACK_DISPATCHER_SIGNATURE:
        return False
    # After saving the callback, forward the matching thunk to a runtime-owned
    # registrar pointer. The function pointer at the global slot is dynamic.
    return tuple(be16(data, entry + offset) for offset in (18, 20, 22, 24, 26, 28, 30)) == (
        0x6322, 0x55F1, 0x351C, 0x6552, 0x64F2, 0x432B, 0x7F08,
    )


def _find_negative_writer_registrations(
    data: bytes, status_address: int
) -> tuple[list[dict], int]:
    _, writes = scan_status_writes(data, status_address)
    negative_writes = [
        event for event in writes if event["constant_class"] == "negative"
    ]
    registrations = []
    for position in range(0, len(data) - 8, 2):
        callback_literal = movl_literal(data, position)
        if callback_literal is None or callback_literal[2] != 5:
            continue
        callback_address = callback_literal[1]
        if not _is_code_address(callback_address, data):
            continue
        callback_entry = callback_address - CODE_LOAD_ADDRESS
        if not any(
            callback_entry <= event["pointer_load_position"] < callback_entry + 0x100
            and callback_entry <= event["store_position"] < callback_entry + 0x100
            for event in negative_writes
        ):
            continue

        dispatcher_literal = movl_literal(data, position + 2)
        if dispatcher_literal is None or dispatcher_literal[2] != 2:
            continue
        if be16(data, position + 4) != 0x420B:
            continue
        delay_slot = be16(data, position + 6)
        if delay_slot & 0xFF00 != 0xE400:
            continue
        callback_id = _signed8(delay_slot & 0xFF)
        dispatcher_address = dispatcher_literal[1]
        if not _is_code_address(dispatcher_address, data):
            continue
        dispatcher_entry = dispatcher_address - CODE_LOAD_ADDRESS
        if not _matches_callback_table_dispatcher(data, dispatcher_entry):
            continue

        callback_table_literal = movl_literal(data, dispatcher_entry)
        thunk_table_literal = movl_literal(data, dispatcher_entry + 8)
        if callback_table_literal is None or thunk_table_literal is None:
            continue
        if callback_table_literal[2] != 0 or thunk_table_literal[2] != 1:
            continue
        if (
            be16(data, dispatcher_entry + 6) != 0x6343
            or be16(data, dispatcher_entry + 10) != 0x4308
            or be16(data, dispatcher_entry + 16) != 0x0356
        ):
            continue
        registrations.append({
            "callback_id": callback_id,
            "callback_entry": callback_entry,
            "dispatcher_entry": dispatcher_entry,
            "callback_table_base": callback_table_literal[1],
            "thunk_table_base": thunk_table_literal[1],
            "callback_writer_matches_status": True,
        })
    return registrations, len(negative_writes)


def audit_dispatch_chain(data: bytes, status_address: int | None) -> dict:
    if status_address is None:
        return {
            "negative_status_writer_candidates": 0,
            "negative_status_writer_registration_sites": 0,
            "callback_id_64_registration_sites": 0,
            "callback_id_64_writer_registered": False,
            "callback_registration_stores_by_id_times_four": False,
            "callback_registration_forwards_thunk_to_runtime_registrar": False,
            "wrapper_table_entries_verified": 0,
            "all_wrapper_stubs_verified": False,
            "id64_wrapper_matches_registration_id": False,
            "common_invoker_reads_same_callback_table": False,
            "common_invoker_indirect_call_guarded_for_nonnull": False,
            "static_registration_to_indirect_call_chain_verified": False,
            "runtime_callback_invocation_confirmed": False,
            "causal_link_to_submit_gate_runtime_proven": False,
            "private_addresses_or_code_offsets_emitted": False,
        }

    registrations, negative_count = _find_negative_writer_registrations(
        data, status_address
    )
    id64_regs = [item for item in registrations if item["callback_id"] == TARGET_CALLBACK_ID]
    verified_entries = 0
    all_stubs_verified = False
    id64_wrapper = False
    common_invoker_matches = False
    nonnull_call_guarded = False
    stores_by_id = False
    forwards_thunk = False

    for registration in id64_regs:
        dispatcher = registration["dispatcher_entry"]
        callback_table_base = registration["callback_table_base"]
        thunk_table_base = registration["thunk_table_base"]
        stores_by_id = (
            be16(data, dispatcher + 6) == 0x6343
            and be16(data, dispatcher + 10) == 0x4308
            and be16(data, dispatcher + 16) == 0x0356
        )
        forwards_thunk = (
            be16(data, dispatcher + 18) == 0x6322
            and be16(data, dispatcher + 20) == 0x55F1
            and be16(data, dispatcher + 22) == 0x351C
            and be16(data, dispatcher + 24) == 0x6552
            and be16(data, dispatcher + 26) == 0x64F2
            and be16(data, dispatcher + 28) == 0x432B
            and be16(data, dispatcher + 30) == 0x7F08
        )

        table_offset = thunk_table_base - CODE_LOAD_ADDRESS
        if not (0 <= table_offset and table_offset + THUNK_ENTRY_COUNT * 4 <= len(data)):
            continue
        pointers = [
            int.from_bytes(data[table_offset + i * 4:table_offset + i * 4 + 4], "big")
            for i in range(THUNK_ENTRY_COUNT)
        ]
        first_stub_address = pointers[0]
        common_targets = []
        verified_entries = 0
        for index, pointer in enumerate(pointers):
            expected_id = index if index < 128 else index - 256
            stub_entry = pointer - CODE_LOAD_ADDRESS
            if not (0 <= stub_entry and stub_entry + THUNK_ENTRY_BYTES <= len(data)):
                continue
            branch = branch_destination(stub_entry + 2, be16(data, stub_entry + 2))
            if (
                pointer == first_stub_address + index * THUNK_ENTRY_BYTES
                and be16(data, stub_entry) == (0xE000 | (expected_id & 0xFF))
                and be16(data, stub_entry + 4) == 0x4008
                and branch is not None
                and branch[0] == "BRA"
            ):
                verified_entries += 1
                common_targets.append(branch[1]
            )
        all_stubs_verified = (
            verified_entries == THUNK_ENTRY_COUNT
            and len(common_targets) == THUNK_ENTRY_COUNT
            and len(set(common_targets)) == 1
        )

        if len(pointers) > TARGET_CALLBACK_ID:
            id64_pointer = pointers[TARGET_CALLBACK_ID]
            id64_entry = id64_pointer - CODE_LOAD_ADDRESS
            id64_branch = (
                branch_destination(id64_entry + 2, be16(data, id64_entry + 2))
                if 0 <= id64_entry and id64_entry + 6 <= len(data)
                else None
            )
            id64_wrapper = (
                be16(data, id64_entry) == 0xE040
                and be16(data, id64_entry + 4) == 0x4008
                and id64_branch is not None
                and id64_branch[0] == "BRA"
            )
            if id64_wrapper:
                common_entry = id64_branch[1]
                common_literal = movl_literal(data, common_entry)
                common_invoker_matches = (
                    common_literal is not None
                    and common_literal[1] == callback_table_base
                    and common_literal[2] == 1
                    and be16(data, common_entry + 2) == 0x021E
                )
                nonnull_call_guarded = (
                    common_invoker_matches
                    and be16(data, common_entry + 4) == 0x2228
                    and be16(data, common_entry + 6) & 0xFF00 == 0x8900
                    and branch_destination(
                        common_entry + 6, be16(data, common_entry + 6)
                    ) == ("BT", common_entry + 24)
                    and be16(data, common_entry + 14) == 0x420B
                    and be16(data, common_entry + 16) == 0x0009
                )

    id64_registered = bool(id64_regs)
    complete_chain = (
        id64_registered
        and stores_by_id
        and forwards_thunk
        and all_stubs_verified
        and id64_wrapper
        and common_invoker_matches
        and nonnull_call_guarded
    )
    return {
        "negative_status_writer_candidates": negative_count,
        "negative_status_writer_registration_sites": len(registrations),
        "callback_id_64_registration_sites": len(id64_regs),
        "callback_id_64_writer_registered": id64_registered,
        "callback_registration_stores_by_id_times_four": stores_by_id,
        "callback_registration_forwards_thunk_to_runtime_registrar": forwards_thunk,
        "wrapper_table_entries_verified": verified_entries,
        "all_wrapper_stubs_verified": all_stubs_verified,
        "id64_wrapper_matches_registration_id": id64_wrapper,
        "common_invoker_reads_same_callback_table": common_invoker_matches,
        "common_invoker_indirect_call_guarded_for_nonnull": nonnull_call_guarded,
        "static_registration_to_indirect_call_chain_verified": complete_chain,
        "runtime_callback_invocation_confirmed": False,
        "causal_link_to_submit_gate_runtime_proven": False,
        "private_addresses_or_code_offsets_emitted": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    gates = find_submit_gates(data)
    status_address = gates[0]["status_address"] if len(gates) == 1 else None
    return {
        "schema_version": 1,
        "stage": "stage71_callback_dispatch_chain",
        "target_file": "0TH2.BIN",
        "analysis": {
            "unique_submit_gate_signature": len(gates) == 1,
            **audit_dispatch_chain(data, status_address),
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
