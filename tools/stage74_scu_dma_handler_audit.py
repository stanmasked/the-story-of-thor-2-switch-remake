#!/usr/bin/env python3
"""Stage74: audit Saturn SCU DMA handler dispatch and command-count producers.

The original ISO remains private and local. JSON output is aggregate-only:
no executable offsets, RAM addresses, instruction words, or game assets.
Static signatures do not prove a runtime DMA completion event.
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
from stage73_memory_path_audit import (
    FIRST_TARGET_OPCODES,
    SECOND_TARGET_DISPATCHER_OPCODES,
    audit_helper_transfer,
)

SCU_D0R = 0x25FE0000
SCU_D0W = 0x25FE0004
SCU_D0C = 0x25FE0008
SCU_D0EN = 0x25FE0010
COMMAND_BUFFER_POINTER = 0x0609650C
COMMAND_COUNT_ADDRESS = 0x0609651C
COMMAND_BUFFER_BASE = 0x06097A70
HANDLER_POINTER_LOADS = (0x26, 0x2C, 0x32)
HANDLER_BRANCHES = ((0x56, 0x26), (0x5A, 0x2C), (0x5E, 0x32))
HANDLER_COMMON = {
    0x00: 0x4F22, 0x02: 0x7FF8, 0x04: 0x0002, 0x06: 0x4009,
    0x08: 0x4009, 0x0A: 0xC90F, 0x0C: 0x2F02, 0x0E: 0x0002,
    0x10: 0x9323, 0x12: 0x2039, 0x14: 0xCBF0, 0x16: 0x400E,
    0x18: 0xD210, 0x1A: 0x1F21, 0x1C: 0x6323, 0x1E: 0xE200,
    0x20: 0x2320, 0x22: 0xD30F, 0x24: 0xD50F, 0x26: 0x6332,
    0x28: 0x6552, 0x2A: 0x430B, 0x2E: 0xD20E, 0x30: 0xD50E,
    0x32: 0x6222, 0x34: 0x6552, 0x36: 0x420B, 0x3A: 0x53F1,
    0x3C: 0xE200, 0x3E: 0x2320, 0x40: 0x60F2, 0x42: 0xC90F,
    0x44: 0x4008, 0x46: 0x4008, 0x48: 0x0302, 0x4A: 0x9206,
    0x4C: 0x2329, 0x4E: 0x203B, 0x50: 0x400E, 0x52: 0x7F08,
    0x54: 0x4F26, 0x56: 0x000B, 0x58: 0x0009,
}
TERMINATOR_OPCODES = {
    0x04: 0x6342, 0x06: 0x2321, 0x08: 0x6342, 0x0A: 0x7304,
    0x0C: 0x000B, 0x0E: 0x2432,
}


def _words_match(data: bytes, start: int, pattern: dict[int, int]) -> bool:
    return start >= 0 and start + max(pattern) + 2 <= len(data) and all(
        be16(data, start + offset) == opcode for offset, opcode in pattern.items()
    )


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


def _may_write_register(opcode: int, register: int) -> bool:
    group = opcode >> 12
    destination = (opcode >> 8) & 0xF
    # Conservative destination-register classification for the SH-2 groups
    # that can write Rn. Stores in groups 0/1/2 are deliberately excluded.
    return group in (0x3, 0x4, 0x5, 0x6, 0x7, 0x9, 0xD, 0xE) and destination == register


def _register_unchanged(
    data: bytes, start: int, end: int, register: int, skip_ranges=()
) -> bool:
    for pos in range(start, end, 2):
        if any(left <= pos < right for left, right in skip_ranges):
            continue
        if _may_write_register(be16(data, pos), register):
            return False
    return True


def _handler_audit(data: bytes, entry: int, index: int) -> dict:
    result = {
        "handler_body_signature_verified": False,
        "handler_argument_tags_verified": False,
        "handler_indirect_service_slots_verified": False,
        "handler_parameter_globals_verified": False,
        "handler_state_byte_cleared_before_and_after_calls": False,
        "handler_direct_scu_register_reference_found": False,
        "handler_runtime_service_targets_resolved": False,
    }
    if entry < 0 or entry + 0x60 > len(data):
        return result
    result["handler_body_signature_verified"] = _words_match(
        data, entry, HANDLER_COMMON
    )
    expected_tag = 0x4B - index
    result["handler_argument_tags_verified"] = (
        be16(data, entry + 0x2C) == 0xE400 + expected_tag
        and be16(data, entry + 0x38) == 0xE400 + expected_tag
    )
    service_a = movl_literal(data, entry + 0x22)
    service_b = movl_literal(data, entry + 0x2E)
    result["handler_indirect_service_slots_verified"] = (
        be16(data, entry + 0x2A) == 0x430B
        and be16(data, entry + 0x36) == 0x420B
        and service_a is not None and service_a[2] == 3
        and service_a[1] == 0x06000300
        and service_b is not None and service_b[2] == 2
        and service_b[1] == 0x06000310
    )
    state = movl_literal(data, entry + 0x18)
    parameter_a = movl_literal(data, entry + 0x24)
    parameter_b = movl_literal(data, entry + 0x30)
    result["handler_parameter_globals_verified"] = (
        state is not None and state[2] == 2 and state[1] == 0x06088668 + index
        and parameter_a is not None and parameter_a[2] == 5
        and parameter_a[1] == 0x06088650 + index * 4
        and parameter_b is not None and parameter_b[2] == 5
        and parameter_b[1] == 0x0608865C + index * 4
    )
    result["handler_state_byte_cleared_before_and_after_calls"] = (
        result["handler_parameter_globals_verified"]
        and be16(data, entry + 0x1A) == 0x1F21
        and be16(data, entry + 0x1C) == 0x6323
        and be16(data, entry + 0x1E) == 0xE200
        and be16(data, entry + 0x20) == 0x2320
        and be16(data, entry + 0x3A) == 0x53F1
        and be16(data, entry + 0x3C) == 0xE200
        and be16(data, entry + 0x3E) == 0x2320
    )
    for offset in (0x18, 0x22, 0x24, 0x2E, 0x30):
        item = movl_literal(data, entry + offset)
        if item is not None and item[1] in (
            SCU_D0R, SCU_D0W, SCU_D0C, SCU_D0EN
        ):
            result["handler_direct_scu_register_reference_found"] = True
    return result


def _count_increment_candidates(data: bytes, count_address: int) -> list[dict]:
    candidates = []
    for store_pos in range(4, len(data) - 1, 2):
        store = be16(data, store_pos)
        if store & 0xF00F != 0x2001:  # MOV.W Rm,@Rn
            continue
        pointer_reg, value_reg = (store >> 8) & 0xF, (store >> 4) & 0xF
        add_pos = store_pos - 2
        load_pos = store_pos - 4
        regular = (
            be16(data, add_pos) & 0xF0FF == 0x7001
            and (be16(data, add_pos) >> 8) & 0xF == value_reg
            and be16(data, load_pos) & 0xF00F == 0x6001
            and (be16(data, load_pos) >> 4) & 0xF == pointer_reg
            and (be16(data, load_pos) >> 8) & 0xF == value_reg
        )
        delay_slot = (
            be16(data, store_pos - 2) == 0x000B
            and be16(data, store_pos - 4) & 0xF0FF == 0x7001
            and (be16(data, store_pos - 4) >> 8) & 0xF == value_reg
            and be16(data, store_pos - 6) & 0xF00F == 0x6001
            and (be16(data, store_pos - 6) >> 4) & 0xF == pointer_reg
            and (be16(data, store_pos - 6) >> 8) & 0xF == value_reg
        )
        if not (regular or delay_slot):
            continue
        pointer_loads = [
            pos for pos in range(max(0, store_pos - 0x50), store_pos - 1, 2)
            if (literal := movl_literal(data, pos)) is not None
            and literal[1] == count_address and literal[2] == pointer_reg
        ]
        if not pointer_loads:
            continue
        guards = []
        for cmp_pos in range(max(0, store_pos - 0x24), store_pos - 4, 2):
            cmp_op = be16(data, cmp_pos)
            if cmp_op & 0xF00F != 0x3003:  # CMP/GE Rm,Rn
                continue
            check_reg, limit_reg = (cmp_op >> 8) & 0xF, (cmp_op >> 4) & 0xF
            checked_load = any(
                (op := be16(data, q)) & 0xF00F == 0x6001
                and (op >> 4) & 0xF == pointer_reg
                and (op >> 8) & 0xF == check_reg
                for q in range(max(0, cmp_pos - 6), cmp_pos, 2)
            )
            if not checked_load:
                continue
            for limit_pos in range(max(0, cmp_pos - 8), cmp_pos, 2):
                literal = _movw_literal(data, limit_pos)
                if literal is None or literal[2] != limit_reg:
                    continue
                for branch_pos in range(cmp_pos + 2, store_pos, 2):
                    branch = branch_destination(branch_pos, be16(data, branch_pos))
                    if branch == ("BT", store_pos + 2):
                        guards.append(literal[1])
        reset = False
        for pointer_pos in pointer_loads:
            for reset_pos in range(pointer_pos + 2, store_pos, 2):
                reset_op = be16(data, reset_pos)
                if reset_op & 0xF00F != 0x2001 or (reset_op >> 8) & 0xF != pointer_reg:
                    continue
                zero_reg = (reset_op >> 4) & 0xF
                # Do not let a reset in one routine justify an increment
                # after an intervening return. Adjacent bytes may be another
                # entry point or an unrelated block (notably near the END helper).
                if any(
                    be16(data, barrier_pos) in (0x000B, 0x002B)
                    for barrier_pos in range(reset_pos + 2, store_pos, 2)
                ):
                    continue
                for zero_pos in range(max(0, pointer_pos - 0x10), reset_pos, 2):
                    zero_op = be16(data, zero_pos)
                    if (
                        zero_op & 0xF0FF == 0xE000
                        and (zero_op >> 8) & 0xF == zero_reg
                        and zero_op & 0xFF == 0
                        and not any(
                            (mid_op := be16(data, mid)) & 0xF0FF == 0xE000
                            and (mid_op >> 8) & 0xF == zero_reg
                            for mid in range(zero_pos + 2, reset_pos, 2)
                        )
                    ):
                        reset = True
        candidates.append({
            "store_pos": store_pos,
            "guards": sorted(set(guards)),
            "reset_before_increment": reset,
            "delay_slot_increment": delay_slot,
        })
    # The same store can be seen from more than one nearby pointer literal.
    by_store = {}
    for candidate in candidates:
        current = by_store.get(candidate["store_pos"])
        if current is None:
            by_store[candidate["store_pos"]] = candidate
        else:
            current["guards"] = sorted(set(current["guards"] + candidate["guards"]))
            current["reset_before_increment"] |= candidate["reset_before_increment"]
    return list(by_store.values())


def _is_zero_reset_store(data: bytes, pointer_reg: int, store_pos: int) -> bool:
    opcode = be16(data, store_pos)
    if opcode & 0xF00F != 0x2001 or (opcode >> 8) & 0xF != pointer_reg:
        return False
    source_reg = (opcode >> 4) & 0xF
    for zero_pos in range(max(0, store_pos - 0x10), store_pos, 2):
        zero_op = be16(data, zero_pos)
        if (
            zero_op & 0xF0FF == 0xE000
            and (zero_op >> 8) & 0xF == source_reg
            and zero_op & 0xFF == 0
            and not any(
                (mid_op := be16(data, mid)) & 0xF0FF == 0xE000
                and (mid_op >> 8) & 0xF == source_reg
                for mid in range(zero_pos + 2, store_pos, 2)
            )
        ):
            return True
    return False


def _audit_command_count(data: bytes, count_address: int) -> dict:
    increments = _count_increment_candidates(data, count_address)
    guarded = [item for item in increments if item["guards"]]
    reset_seeded = [item for item in increments if not item["guards"] and item["reset_before_increment"]]
    unresolved_increments = [
        item for item in increments if not item["guards"] and not item["reset_before_increment"]
    ]
    increment_positions = {item["store_pos"] for item in increments}
    pointer_refs = [
        (pos, literal[2]) for pos in range(0, len(data) - 5, 2)
        if (literal := movl_literal(data, pos)) is not None and literal[1] == count_address
    ]
    assignments = set()
    for pos, pointer_reg in pointer_refs:
        for store_pos in range(pos + 2, min(len(data) - 1, pos + 0x40), 2):
            op = be16(data, store_pos)
            if (
                op & 0xF00F == 0x2001
                and (op >> 8) & 0xF == pointer_reg
                and store_pos not in increment_positions
                and not _is_zero_reset_store(data, pointer_reg, store_pos)
            ):
                assignments.add(store_pos)
    # Stores from a known zero register are resets; the remaining stores have
    # register provenance that this bounded scan cannot fully resolve.
    unresolved_assignments = len(assignments)
    return {
        "command_count_pointer_reference_sites": len(pointer_refs),
        "command_count_increment_sites_recognized": len(increments),
        "command_count_increment_sites_guarded_by_limit": len(guarded),
        "command_count_guard_limits": sorted({
            cap for item in guarded for cap in item["guards"]
        }),
        "command_count_increment_sites_after_local_zero_reset": len(reset_seeded),
        "command_count_increment_sites_without_guard_or_zero_reset": len(unresolved_increments),
        "command_count_unresolved_register_assignment_sites": unresolved_assignments,
        "command_count_global_upper_bound_proven": (
            bool(increments) and not unresolved_increments and unresolved_assignments == 0
        ),
    }


def _audit_terminator(data: bytes, count_formula_verified: bool) -> dict:
    matches = []
    for pos in range(0, len(data) - 0x10, 2):
        pointer = movl_literal(data, pos)
        marker = movl_literal(data, pos + 2)
        if (
            pointer is None or pointer[2] != 4 or pointer[1] != COMMAND_BUFFER_POINTER
            or marker is None or marker[2] != 2 or marker[1] != 0x00008000
            or not _words_match(data, pos, {0x04: 0x6342, **TERMINATOR_OPCODES})
        ):
            continue
        matches.append(pos)
    return {
        "halfword_end_marker_helper_signature_verified": len(matches) == 1,
        "end_marker_is_written_as_16_bit_0x8000": len(matches) == 1,
        "end_marker_pointer_reservation_is_four_bytes": len(matches) == 1,
        "callback_plus_two_matches_marker_payload_bytes": (
            len(matches) == 1 and count_formula_verified
        ),
        "reserved_padding_excluded_from_transfer_length": (
            len(matches) == 1 and count_formula_verified
        ),
    }


def audit_dma_chain(data: bytes, callback_entry: int, helper_entry: int) -> dict:
    result = {
        "helper_call_targets_resolved": False,
        "source_destination_count_register_block_pattern_verified": False,
        "dispatcher_selects_three_in_image_handlers": False,
        "three_handler_bodies_verified": False,
        "three_handler_argument_tags_verified": False,
        "three_handler_indirect_service_slots_verified": False,
        "three_handler_parameter_globals_verified": False,
        "three_handler_state_byte_clear_pattern_verified": False,
        "handlers_write_scu_registers_directly": False,
        "dispatcher_d0en_start_write_verified": False,
        "dispatcher_dma_enable_offset_resolved_to_level0": False,
        "dma_level0_enable_start_value_verified": False,
        "runtime_handler_choice_confirmed": False,
        "runtime_dma_completion_confirmed": False,
    }
    if helper_entry < 0 or helper_entry + 0xE8 > len(data):
        return result
    first = movl_literal(data, helper_entry + 0xD8)
    second = movl_literal(data, helper_entry + 0xDE)
    if (
        first is None or first[2] != 3 or second is None or second[2] != 3
        or not (CODE_LOAD_ADDRESS <= first[1] < CODE_LOAD_ADDRESS + len(data))
        or not (CODE_LOAD_ADDRESS <= second[1] < CODE_LOAD_ADDRESS + len(data))
        or be16(data, helper_entry + 0xDA) != 0x430B
        or be16(data, helper_entry + 0xDC) != 0x7404
        or be16(data, helper_entry + 0xE0) != 0x430B
        or be16(data, helper_entry + 0xE2) != 0x64E3
    ):
        return result
    first_entry = first[1] - CODE_LOAD_ADDRESS
    dispatcher_entry = second[1] - CODE_LOAD_ADDRESS
    result["helper_call_targets_resolved"] = True
    result["source_destination_count_register_block_pattern_verified"] = (
        _words_match(data, first_entry, {
            index * 2: opcode for index, opcode in enumerate(FIRST_TARGET_OPCODES)
        })
        and all(
            (literal := movl_literal(data, first_entry + offset)) is not None
            and literal[2] == 0 and literal[1] == value
            for offset, value in ((0x14, SCU_D0R), (0x2C, SCU_D0W), (0x34, SCU_D0C))
        )
        and be16(data, first_entry + 0x16) == 0x0326
        and be16(data, first_entry + 0x2E) == 0x0326
        and be16(data, first_entry + 0x3C) == 0x0636
    )
    if not _words_match(data, dispatcher_entry, SECOND_TARGET_DISPATCHER_OPCODES):
        return result
    handlers = []
    for load_offset in HANDLER_POINTER_LOADS:
        literal = movl_literal(data, dispatcher_entry + load_offset)
        if (
            literal is None or literal[2] != 12
            or not (CODE_LOAD_ADDRESS <= literal[1] < CODE_LOAD_ADDRESS + len(data))
        ):
            return result
        handlers.append(literal[1] - CODE_LOAD_ADDRESS)
    branches_verified = all(
        branch_destination(dispatcher_entry + branch_offset,
                           be16(data, dispatcher_entry + branch_offset))
        == ("BT", dispatcher_entry + target_offset)
        for branch_offset, target_offset in HANDLER_BRANCHES
    )
    result["dispatcher_selects_three_in_image_handlers"] = branches_verified and len(set(handlers)) == 3
    handler_results = [
        _handler_audit(data, entry, index) for index, entry in enumerate(handlers)
    ]
    result["three_handler_bodies_verified"] = all(
        item["handler_body_signature_verified"] for item in handler_results
    )
    result["three_handler_argument_tags_verified"] = all(
        item["handler_argument_tags_verified"] for item in handler_results
    )
    result["three_handler_indirect_service_slots_verified"] = all(
        item["handler_indirect_service_slots_verified"] for item in handler_results
    )
    result["three_handler_parameter_globals_verified"] = all(
        item["handler_parameter_globals_verified"] for item in handler_results
    )
    result["three_handler_state_byte_clear_pattern_verified"] = all(
        item["handler_state_byte_cleared_before_and_after_calls"] for item in handler_results
    )
    result["handlers_write_scu_registers_directly"] = any(
        item["handler_direct_scu_register_reference_found"] for item in handler_results
    )

    # The dispatcher copies R4 into R13 at entry. The helper's second JSR
    # delay slot sets R4 from R14; R14 is initialized to zero and is not changed
    # by the helper or first target. The dispatcher then scales R13 by 32.
    r14_zero_proven = (
        be16(data, helper_entry + 0x0A) == 0xEE00
        and _register_unchanged(
            data, helper_entry + 0x0C, helper_entry + 0xD8, 14,
            skip_ranges=((helper_entry + 0x5C, helper_entry + 0x78),)
        )
        and _register_unchanged(data, first_entry, first_entry + 0x60, 14)
        and be16(data, helper_entry + 0xE2) == 0x64E3
    )
    dispatcher_scales_r13 = (
        r14_zero_proven
        and be16(data, dispatcher_entry + 0x0C) == 0x6D43
        and _register_unchanged(
            data, dispatcher_entry + 0x0E, dispatcher_entry + 0xA4, 13,
            skip_ranges=((dispatcher_entry + 0x38, dispatcher_entry + 0x54),)
        )
        and be16(data, dispatcher_entry + 0xA4) == 0x4D08
        and be16(data, dispatcher_entry + 0xA6) == 0x4D08
        and be16(data, dispatcher_entry + 0xA8) == 0x4D00
    )
    enable_base = movl_literal(data, dispatcher_entry + 0xAC)
    enable_value = _movw_literal(data, dispatcher_entry + 0xAA)
    result["dispatcher_dma_enable_offset_resolved_to_level0"] = dispatcher_scales_r13
    result["dispatcher_d0en_start_write_verified"] = (
        dispatcher_scales_r13
        and enable_base is not None and enable_base[2] == 0 and enable_base[1] == SCU_D0EN
        and be16(data, dispatcher_entry + 0xAE) == 0x0D36
        and (be16(data, dispatcher_entry + 0xAE) & 0xF00F) == 0x0006
    )
    result["dma_level0_enable_start_value_verified"] = (
        result["dispatcher_d0en_start_write_verified"]
        and enable_value is not None and enable_value[2] == 3 and enable_value[1] == 0x0101
    )
    return result


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
    helper_literal = movl_literal(data, callback_entry + 0x28) if callback_entry >= 0 else None
    helper_entry = (
        helper_literal[1] - CODE_LOAD_ADDRESS
        if helper_literal is not None and helper_literal[2] == 3
        and CODE_LOAD_ADDRESS <= helper_literal[1] < CODE_LOAD_ADDRESS + len(data)
        else -1
    )
    helper_result = (
        audit_helper_transfer(data, callback_entry, gate["count_address"])
        if gate is not None and callback_entry >= 0 else {}
    )
    chain = audit_dma_chain(data, callback_entry, helper_entry)
    count_address = (
        movl_literal(data, callback_entry + 0x18)[1]
        if callback_entry >= 0 and movl_literal(data, callback_entry + 0x18) is not None
        else COMMAND_COUNT_ADDRESS
    )
    count_audit = _audit_command_count(data, count_address)
    terminator = _audit_terminator(
        data, bool(helper_result.get("callback_length_formula_is_signed_word_times_32_plus_2", False))
    )
    return {
        "schema_version": 1,
        "stage": "stage74_scu_dma_handler_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            "unique_submit_gate_signature": len(gates) == 1,
            "callback_id_64_registration_sites": len(id64),
            "callback_length_formula_verified": bool(
                helper_result.get("callback_length_formula_is_signed_word_times_32_plus_2", False)
            ),
            **chain,
            **count_audit,
            **terminator,
            "source_destination_effective_dma_addresses_fully_resolved": False,
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
