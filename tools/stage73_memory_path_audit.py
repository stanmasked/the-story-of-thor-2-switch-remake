#!/usr/bin/env python3
"""Stage73: trace the callback's helper branch and transfer-state setup.

The original Saturn ISO stays local. Output is aggregate-only and never includes
addresses, offsets, instruction words, or copyrighted payload bytes. Static
control-flow evidence is not a runtime trace.
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
    audit_dispatch_chain,
)
from stage72_status_producer_order import audit_callback_body

VDP1_VRAM_BASE = 0x25C00000
HELPER_RANGE_BOUNDS = (0x20200000, 0x20300000, 0x00200000, 0x00300000)
PRIMARY_VIDEO_WINDOW = (0x25A00000, 0x25FE0000)
ALIAS_VIDEO_WINDOW = (0x05A00000, 0x05FE0000)
TRANSFER_STATE_FLAG = 0x06088514
TRANSFER_DESTINATION_SLOT = 0x0608850C
TRANSFER_LENGTH_SLOT = 0x06088510
TRANSFER_FINAL_FLAG = 0x06088515

HELPER_OPCODES = {
    0x00: 0x2FE6, 0x02: 0x2FD6, 0x04: 0x4F22, 0x06: 0x7FD4,
    0x08: 0xED01, 0x0A: 0xEE00, 0x18: 0x9320, 0x1A: 0x2039,
    0x1C: 0xCBF0, 0x1E: 0x400E, 0x20: 0xD70F, 0x22: 0x3472,
    0x24: 0x8B02, 0x26: 0xD30F, 0x28: 0x3432, 0x2A: 0x8B10,
    0x2C: 0xD30E, 0x2E: 0x3432, 0x30: 0x8B02, 0x32: 0xD30E,
    0x34: 0x3432, 0x36: 0x8B0A, 0x38: 0x3572, 0x3A: 0x8B02,
    0x3C: 0xD209, 0x3E: 0x3522, 0x40: 0x8B05, 0x42: 0xD209,
    0x44: 0x3522, 0x46: 0x8B17, 0x48: 0xD208, 0x4A: 0x3522,
    0x4C: 0x8914, 0x4E: 0xD308, 0x50: 0x23E0, 0x52: 0xD308,
    0x54: 0x430B, 0x56: 0x0009, 0x58: 0xA044, 0x5A: 0x0009,
    0x78: 0x62DC, 0x7A: 0xD323, 0x7C: 0x2320, 0x7E: 0xD323,
    0x80: 0x2342, 0x82: 0xD323, 0x84: 0x2362, 0x86: 0x1F51,
    0x88: 0x1F42, 0x8A: 0x1F63, 0x8C: 0x933A, 0x8E: 0x1F34,
    0x90: 0x54F2, 0x92: 0xD320, 0x94: 0x3432, 0x96: 0x0029,
    0x98: 0xD31F, 0x9A: 0x3432, 0x9C: 0x0129, 0x9E: 0x71FF,
    0xA0: 0x611B, 0xA2: 0x2019, 0xA4: 0x2008, 0xA6: 0x8B0A,
    0xA8: 0xD31C, 0xAA: 0x3432, 0xAC: 0x0029, 0xAE: 0xD31C,
    0xB0: 0x3432, 0xB2: 0x0129, 0xB4: 0x71FF, 0xB6: 0x611B,
    0xB8: 0x2019, 0xBA: 0x2008, 0xBC: 0x8901, 0xBE: 0x1FD5,
    0xC0: 0xE202, 0xC2: 0x1F25, 0xC4: 0xE307, 0xC6: 0x65E3,
    0xC8: 0x64F3, 0xCA: 0x1FE6, 0xCC: 0x1FE7, 0xCE: 0x1FE8,
    0xD0: 0x1F39, 0xD2: 0xE303, 0xD4: 0x1F3A, 0xD8: 0xD312,
    0xDA: 0x430B, 0xDC: 0x7404, 0xDE: 0xD312, 0xE0: 0x430B,
    0xE2: 0x64E3, 0xE4: 0xD311, 0xE6: 0x23D0, 0xE8: 0x60F2,
    0xEA: 0xC90F, 0xEC: 0x4008, 0xEE: 0x4008, 0xF0: 0x0102,
    0xF2: 0x9308, 0xF4: 0x2139, 0xF6: 0x201B, 0xF8: 0x400E,
    0xFA: 0x7F2C, 0xFC: 0x4F26, 0xFE: 0x6DF6, 0x100: 0x000B,
    0x102: 0x6EF6,
}

MEMMOVE_OPCODES = {
    0x00: 0x3450, 0x02: 0x891C, 0x04: 0x3452, 0x06: 0x8D0D,
    0x08: 0xE700, 0x0A: 0x6143, 0x0C: 0x6053, 0x0E: 0x3762,
    0x10: 0x8D15, 0x12: 0x6573, 0x14: 0x6304, 0x16: 0x7501,
    0x18: 0x2130, 0x1A: 0x3562, 0x1C: 0x8FFA, 0x1E: 0x7101,
    0x20: 0xA00D, 0x22: 0x0009, 0x24: 0x6143, 0x26: 0x316C,
    0x28: 0x6053, 0x2A: 0x306C, 0x2C: 0x3762, 0x2E: 0x8D06,
    0x30: 0x6573, 0x32: 0x70FF, 0x34: 0x6300, 0x36: 0x7501,
    0x38: 0x3562, 0x3A: 0x8FFA, 0x3C: 0x2134, 0x3E: 0x000B,
    0x40: 0x0009,
}

FIRST_TARGET_OPCODES = (
    0xE601, 0x5349, 0x2369, 0x3360, 0x8B06, 0x6353, 0x4308, 0x4308,
    0x4300, 0x6242, 0xD021, 0x0326, 0xE602, 0x5349, 0x2369, 0x3360,
    0x8B06, 0x6353, 0x4308, 0x4308, 0x4300, 0x5241, 0xD01C, 0x0326,
    0x6653, 0x5342, 0xD01B, 0x4608, 0x4608, 0x4600, 0x0636, 0x7004,
    0x5343, 0x5244, 0x232B, 0x0636, 0x5346, 0x7008, 0x5245, 0x5147,
    0x4328, 0x4118, 0x232B, 0x231B, 0x5248, 0x232B, 0x000B, 0x0636,
)
SECOND_TARGET_DISPATCHER_OPCODES = {
    0x00: 0x2FE6, 0x02: 0x2FD6, 0x04: 0x2FC6, 0x06: 0x2F86,
    0x08: 0x4F22, 0x0A: 0x7FF8, 0x0C: 0x6D43, 0x0E: 0x0002,
    0x10: 0x4009, 0x12: 0x4009, 0x14: 0xC90F, 0x16: 0x2F02,
    0x18: 0x0002, 0x1A: 0x930D, 0x1C: 0x2039, 0x1E: 0xCBF0,
    0x20: 0x400E, 0x22: 0xA017,
}


def _literal(data: bytes, position: int, register: int, value: int) -> bool:
    item = movl_literal(data, position)
    return item is not None and item[2] == register and item[1] == value


def _words_match(data: bytes, start: int, pattern: dict[int, int]) -> bool:
    return start >= 0 and start + max(pattern) + 2 <= len(data) and all(
        be16(data, start + offset) == opcode
        for offset, opcode in pattern.items()
    )


def _select_helper_path(
    destination: int, source: int, bounds: tuple[int, int, int, int]
) -> int:
    low_alias, high_alias, low_direct, high_direct = bounds
    if destination < low_alias:
        return 0x2C
    if destination < high_alias:
        return 0x4E
    if destination < low_direct:
        return 0x38
    if destination < high_direct:
        return 0x4E
    if source < low_alias:
        if source < low_direct or source >= high_direct:
            return 0x78
        return 0x4E
    if source < high_alias:
        return 0x4E
    if source < low_direct or source >= high_direct:
        return 0x78
    return 0x4E


def _empty_result() -> dict:
    return {
        "callback_count_pointer_matches_submit_pending_count": False,
        "callback_length_field_is_adjacent_to_submit_pending_count": False,
        "callback_length_formula_is_signed_word_times_32_plus_2": False,
        "callback_sequence_contains_no_local_count_bounds_check": False,
        "callback_destination_is_vdp1_vram_base": False,
        "callback_helper_pointer_resolves_into_loaded_code": False,
        "helper_range_dispatch_signature_verified": False,
        "helper_special_path_selected_for_callback_arguments": False,
        "helper_generic_memmove_path_selected_for_callback_arguments": False,
        "special_path_sets_transfer_state_flag": False,
        "special_path_stores_destination_and_byte_length": False,
        "destination_matches_primary_video_memory_window": False,
        "special_path_has_two_call_sites": False,
        "generic_bytewise_overlap_safe_memmove_signature_verified": False,
        "generic_memmove_forward_and_backward_loops_verified": False,
        "generic_memmove_handles_equal_pointers_and_zero_length": False,
        "first_special_target_is_verified_leaf_helper": False,
        "second_special_target_is_verified_dma_dispatcher": False,
        "scu_dma_register_block_literals_verified": False,
        "three_in_image_transfer_handlers_verified": False,
        "special_path_call_return_contract_resolved": False,
        "actual_vdp1_memory_write_proven": False,
        "runtime_callback_invocation_confirmed": False,
        "private_addresses_or_code_offsets_emitted": False,
    }


def audit_helper_transfer(
    data: bytes, callback_entry: int, expected_count_address: int | None
) -> dict:
    result = _empty_result()
    if callback_entry < 0 or callback_entry + 0x2E > len(data):
        return result

    count_pointer = movl_literal(data, callback_entry + 0x1A)
    source_literal = movl_literal(data, callback_entry + 0x20)
    destination_literal = movl_literal(data, callback_entry + 0x24)
    helper_literal = movl_literal(data, callback_entry + 0x28)
    if (
        count_pointer is None or count_pointer[2] != 2
        or source_literal is None or source_literal[2] != 5
        or destination_literal is None or destination_literal[2] != 4
        or helper_literal is None or helper_literal[2] != 3
    ):
        return result

    result["callback_count_pointer_matches_submit_pending_count"] = (
        expected_count_address is not None
        and count_pointer[1] == expected_count_address
        and be16(data, callback_entry + 0x1C) == 0x6621
    )
    result["callback_length_field_is_adjacent_to_submit_pending_count"] = (
        expected_count_address is not None
        and count_pointer[1] + 2 == expected_count_address
        and be16(data, callback_entry + 0x1C) == 0x6621
    )
    result["callback_length_formula_is_signed_word_times_32_plus_2"] = (
        be16(data, callback_entry + 0x1C) == 0x6621
        and be16(data, callback_entry + 0x1E) == 0x4608
        and be16(data, callback_entry + 0x22) == 0x4608
        and be16(data, callback_entry + 0x26) == 0x4600
        and be16(data, callback_entry + 0x2A) == 0x430B
        and be16(data, callback_entry + 0x2C) == 0x7602
    )
    result["callback_sequence_contains_no_local_count_bounds_check"] = (
        result["callback_length_formula_is_signed_word_times_32_plus_2"]
    )
    result["callback_destination_is_vdp1_vram_base"] = (
        destination_literal[1] == VDP1_VRAM_BASE
    )

    helper_address = helper_literal[1]
    if not (CODE_LOAD_ADDRESS <= helper_address < CODE_LOAD_ADDRESS + len(data)):
        return result
    helper_entry = helper_address - CODE_LOAD_ADDRESS
    result["callback_helper_pointer_resolves_into_loaded_code"] = True
    if not _words_match(data, helper_entry, HELPER_OPCODES):
        return result

    bound_loads = (
        (0x20, 7, HELPER_RANGE_BOUNDS[0]),
        (0x26, 3, HELPER_RANGE_BOUNDS[1]),
        (0x2C, 3, HELPER_RANGE_BOUNDS[2]),
        (0x32, 3, HELPER_RANGE_BOUNDS[3]),
        (0x3C, 2, HELPER_RANGE_BOUNDS[1]),
        (0x42, 2, HELPER_RANGE_BOUNDS[2]),
        (0x48, 2, HELPER_RANGE_BOUNDS[3]),
    )
    range_literals_verified = all(
        _literal(data, helper_entry + offset, register, value)
        for offset, register, value in bound_loads
    )
    branch_targets = {
        0x24: 0x2C, 0x2A: 0x4E, 0x30: 0x38, 0x36: 0x4E,
        0x3A: 0x42, 0x40: 0x4E, 0x46: 0x78, 0x4C: 0x78,
    }
    branches_verified = all(
        (branch_destination(
            helper_entry + offset, be16(data, helper_entry + offset)
        ) or (None, None))[1] == helper_entry + target
        for offset, target in branch_targets.items()
    )
    result["helper_range_dispatch_signature_verified"] = (
        range_literals_verified and branches_verified
    )
    if not result["helper_range_dispatch_signature_verified"]:
        return result

    destination = destination_literal[1]
    source = source_literal[1]
    selected_path = _select_helper_path(
        destination, source, HELPER_RANGE_BOUNDS
    )
    result["helper_special_path_selected_for_callback_arguments"] = (
        selected_path == 0x78
    )
    result["helper_generic_memmove_path_selected_for_callback_arguments"] = (
        selected_path == 0x4E
    )
    result["destination_matches_primary_video_memory_window"] = (
        PRIMARY_VIDEO_WINDOW[0] <= destination < PRIMARY_VIDEO_WINDOW[1]
    )

    special_literals = (
        (0x7A, 3, TRANSFER_STATE_FLAG),
        (0x7E, 3, TRANSFER_DESTINATION_SLOT),
        (0x82, 3, TRANSFER_LENGTH_SLOT),
        (0x92, 3, PRIMARY_VIDEO_WINDOW[0]),
        (0x98, 3, PRIMARY_VIDEO_WINDOW[1]),
        (0xA8, 3, ALIAS_VIDEO_WINDOW[0]),
        (0xAE, 3, ALIAS_VIDEO_WINDOW[1]),
        (0xE4, 3, TRANSFER_FINAL_FLAG),
    )
    special_literals_verified = all(
        _literal(data, helper_entry + offset, register, value)
        for offset, register, value in special_literals
    )
    first_target_literal = movl_literal(data, helper_entry + 0xD8)
    second_target_literal = movl_literal(data, helper_entry + 0xDE)
    special_targets_resolved = (
        first_target_literal is not None and first_target_literal[2] == 3
        and second_target_literal is not None and second_target_literal[2] == 3
        and CODE_LOAD_ADDRESS <= first_target_literal[1] < CODE_LOAD_ADDRESS + len(data)
        and CODE_LOAD_ADDRESS <= second_target_literal[1] < CODE_LOAD_ADDRESS + len(data)
    )
    special_stores_and_calls = all(
        be16(data, helper_entry + offset) == opcode
        for offset, opcode in {
            0x78: 0x62DC, 0x7C: 0x2320, 0x80: 0x2342, 0x84: 0x2362,
            0x86: 0x1F51, 0x88: 0x1F42, 0x8A: 0x1F63, 0x8C: 0x933A,
            0x8E: 0x1F34, 0x90: 0x54F2, 0xDA: 0x430B, 0xDC: 0x7404,
            0xE0: 0x430B, 0xE2: 0x64E3, 0xE6: 0x23D0,
        }.items()
    )
    result["special_path_sets_transfer_state_flag"] = (
        special_literals_verified
        and special_stores_and_calls
        and be16(data, helper_entry + 0x08) == 0xED01
    )
    result["special_path_stores_destination_and_byte_length"] = (
        special_literals_verified
        and special_stores_and_calls
        and be16(data, helper_entry + 0x7E) == 0xD323
        and be16(data, helper_entry + 0x80) == 0x2342
        and be16(data, helper_entry + 0x82) == 0xD323
        and be16(data, helper_entry + 0x84) == 0x2362
    )
    result["special_path_has_two_call_sites"] = (
        special_literals_verified
        and special_targets_resolved
        and special_stores_and_calls
        and be16(data, helper_entry + 0xD8) == 0xD312
        and be16(data, helper_entry + 0xDE) == 0xD312
    )

    memmove_literal = movl_literal(data, helper_entry + 0x52)
    if memmove_literal is not None and memmove_literal[2] == 3:
        memmove_address = memmove_literal[1]
        if CODE_LOAD_ADDRESS <= memmove_address < CODE_LOAD_ADDRESS + len(data):
            memmove_entry = memmove_address - CODE_LOAD_ADDRESS
            memmove_match = _words_match(data, memmove_entry, MEMMOVE_OPCODES)
            if memmove_match:
                targets = {
                    0x02: ("BT", 0x3E), 0x06: ("BT/S", 0x24),
                    0x10: ("BT/S", 0x3E), 0x1C: ("BF/S", 0x14),
                    0x20: ("BRA", 0x3E), 0x2E: ("BT/S", 0x3E),
                    0x3A: ("BF/S", 0x32),
                }
                target_match = all(
                    branch_destination(
                        memmove_entry + offset,
                        be16(data, memmove_entry + offset),
                    ) == (kind, memmove_entry + target)
                    for offset, (kind, target) in targets.items()
                )
                result["generic_bytewise_overlap_safe_memmove_signature_verified"] = (
                    target_match
                )
                result["generic_memmove_forward_and_backward_loops_verified"] = (
                    target_match
                    and be16(data, memmove_entry + 0x14) == 0x6304
                    and be16(data, memmove_entry + 0x18) == 0x2130
                    and be16(data, memmove_entry + 0x34) == 0x6300
                    and be16(data, memmove_entry + 0x3C) == 0x2134
                )
                result["generic_memmove_handles_equal_pointers_and_zero_length"] = (
                    target_match
                    and be16(data, memmove_entry + 0x00) == 0x3450
                    and be16(data, memmove_entry + 0x02) == 0x891C
                    and be16(data, memmove_entry + 0x0E) == 0x3762
                    and be16(data, memmove_entry + 0x10) == 0x8D15
                )

    first_target = first_target_literal[1] if special_targets_resolved else -1
    second_target = second_target_literal[1] if special_targets_resolved else -1
    first_entry = first_target - CODE_LOAD_ADDRESS
    second_entry = second_target - CODE_LOAD_ADDRESS
    first_leaf_verified = (
        special_targets_resolved
        and all(be16(data, first_entry + 2 * i) == opcode
                for i, opcode in enumerate(FIRST_TARGET_OPCODES))
        and be16(data, first_entry + 0x5C) == 0x000B
        and be16(data, first_entry + 0x5E) == 0x0636
    )
    second_prologue_verified = (
        special_targets_resolved
        and _words_match(data, second_entry, SECOND_TARGET_DISPATCHER_OPCODES)
    )
    result["first_special_target_is_verified_leaf_helper"] = first_leaf_verified
    result["second_special_target_is_verified_dma_dispatcher"] = False
    result["scu_dma_register_block_literals_verified"] = False
    result["three_in_image_transfer_handlers_verified"] = False

    if second_prologue_verified:
        dma_register_literals = (
            int.from_bytes(data[second_entry + 0x3C:second_entry + 0x40], "big") == 0x25FE0000
            and int.from_bytes(data[second_entry + 0x40:second_entry + 0x44], "big") == 0x25FE0004
            and int.from_bytes(data[second_entry + 0x44:second_entry + 0x48], "big") == 0x25FE0008
            and _literal(data, second_entry + 0xAC, 0, 0x25FE0010)
        )
        handler_literals = []
        for offset in (0x26, 0x2C, 0x32):
            item = movl_literal(data, second_entry + offset)
            handler_literals.append(
                item is not None and item[2] == 12
                and CODE_LOAD_ADDRESS <= item[1] < CODE_LOAD_ADDRESS + len(data)
            )
        handler_offsets = [
            movl_literal(data, second_entry + offset)[1] - CODE_LOAD_ADDRESS
            for offset in (0x26, 0x2C, 0x32)
            if movl_literal(data, second_entry + offset) is not None
            and CODE_LOAD_ADDRESS <= movl_literal(data, second_entry + offset)[1] < CODE_LOAD_ADDRESS + len(data)
        ]
        handler_entries = (
            len(handler_offsets) == 3
            and all(_words_match(data, offset, {0x00: 0x4F22, 0x02: 0x7FF8})
                    for offset in handler_offsets)
        )
        handler_literals = all(handler_literals)
        result["scu_dma_register_block_literals_verified"] = dma_register_literals
        result["three_in_image_transfer_handlers_verified"] = (
            handler_literals and handler_entries
        )
        result["second_special_target_is_verified_dma_dispatcher"] = (
            dma_register_literals and handler_literals and handler_entries
            and be16(data, second_entry + 0xCC) == 0x000B
            and be16(data, second_entry + 0xCE) == 0x6EF6
        )

    result["special_path_call_return_contract_resolved"] = (
        first_leaf_verified
        and result["second_special_target_is_verified_dma_dispatcher"]
    )
    result["actual_vdp1_memory_write_proven"] = False
    result["runtime_callback_invocation_confirmed"] = False
    return result


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    gates = find_submit_gates(data)
    status_address = gates[0]["status_address"] if len(gates) == 1 else None
    registrations, _ = (
        _find_negative_writer_registrations(data, status_address)
        if status_address is not None else ([], 0)
    )
    id64 = [item for item in registrations if item["callback_id"] == TARGET_CALLBACK_ID]
    callback_entry = id64[0]["callback_entry"] if len(id64) == 1 else -1
    callback_status = (
        audit_callback_body(data, callback_entry, status_address)
        if callback_entry >= 0 else {}
    )
    transfer = audit_helper_transfer(
        data, callback_entry,
        gates[0]["count_address"] if len(gates) == 1 else None,
    )
    dispatch = audit_dispatch_chain(data, status_address)
    return {
        "schema_version": 1,
        "stage": "stage73_memory_path_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            "unique_submit_gate_signature": len(gates) == 1,
            "callback_id_64_registration_sites": len(id64),
            "callback_status_handshake_statically_verified": bool(
                callback_status.get("callback_body_handshake_verified", False)
            ),
            "static_callback_dispatch_chain_verified": dispatch[
                "static_registration_to_indirect_call_chain_verified"
            ],
            **transfer,
            "actual_vdp1_memory_write_proven": False,
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
