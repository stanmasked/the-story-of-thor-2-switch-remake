#!/usr/bin/env python3
"""Stage93: audit the shared loader wrapper and SET07 startup entry.

The original Saturn ISO is read locally. Output is aggregate-only and does not
emit raw addresses, code offsets, instruction bytes, or original payloads.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import (
    _be16,
    _branch,
    _find_main_th2_low_load,
    _find_set07_callsite,
    _find_set_table_loader_targets,
)
from stage92_set07_guard_predicate_audit import _loader_result_summary


def _summarize_loader_wrapper(data: bytes, entry: int, code_load_address: int = CODE_LOAD_ADDRESS) -> dict:
    if entry < 0 or entry + 0x38 > len(data):
        return {"wrapper_signature_found": False}

    helper_a = movl_literal(data, entry + 4)
    helper_b = movl_literal(data, entry + 0x1C)
    error_a = _branch(entry + 0x14, _be16(data, entry + 0x14))
    error_b = _branch(entry + 0x2A, _be16(data, entry + 0x2A))
    success_a = _branch(entry + 0x12, _be16(data, entry + 0x12))
    success_b = _branch(entry + 0x28, _be16(data, entry + 0x28))

    helper_a_valid = (
        helper_a is not None and helper_a[2] == 3
        and code_load_address <= helper_a[1] < code_load_address + len(data)
    )
    helper_b_valid = (
        helper_b is not None and helper_b[2] == 3
        and code_load_address <= helper_b[1] < code_load_address + len(data)
    )
    shared_error_target = bool(
        error_a and error_b and error_a[0] == "BSR" and error_b[0] == "BSR"
        and error_a[1] == error_b[1]
    )
    first_check = (
        _be16(data, entry + 0x0E) == 0x6E03
        and _be16(data, entry + 0x10) == 0x4E11
        and success_a is not None and success_a[0] == "BT"
        and success_a[1] == entry + 0x18
        and shared_error_target and _be16(data, entry + 0x16) == 0xE401
    )
    second_check = (
        _be16(data, entry + 0x24) == 0x6E03
        and _be16(data, entry + 0x26) == 0x4E11
        and success_b is not None and success_b[0] == "BT"
        and success_b[1] == entry + 0x2E
        and shared_error_target and _be16(data, entry + 0x2C) == 0xE402
    )
    wrapper_return = (
        _be16(data, entry + 0x2E) == 0x60E3
        and _be16(data, entry + 0x30) == 0x7F04
        and _be16(data, entry + 0x32) == 0x4F26
        and _be16(data, entry + 0x34) == 0x000B
        and _be16(data, entry + 0x36) == 0x6EF6
    )
    second_args = (
        _be16(data, entry + 0x18) == 0x66F2
        and _be16(data, entry + 0x1A) == 0xE500
        and _be16(data, entry + 0x1E) == 0xE7FF
        and _be16(data, entry + 0x20) == 0x430B
        and _be16(data, entry + 0x22) == 0x64E3
    )
    return {
        "wrapper_signature_found": _be16(data, entry) == 0x2FE6 and _be16(data, entry + 2) == 0x4F22,
        "first_internal_helper_call_found": helper_a_valid and _be16(data, entry + 0x0A) == 0x430B and _be16(data, entry + 0x0C) == 0x0009,
        "second_internal_helper_call_found": helper_b_valid and second_args,
        "both_helpers_have_internal_targets": helper_a_valid and helper_b_valid,
        "first_result_checked_for_nonnegative_value": first_check,
        "first_negative_path_uses_error_code_1": first_check,
        "first_error_path_rejoins_second_helper": first_check and _be16(data, entry + 0x18) == 0x66F2,
        "second_result_checked_for_nonnegative_value": second_check,
        "second_negative_path_uses_error_code_2": second_check,
        "second_error_path_rejoins_return": second_check and wrapper_return,
        "wrapper_returns_second_helper_result": second_check and wrapper_return,
        "error_paths_share_one_helper_target": shared_error_target,
        "wrapper_short_circuits_after_first_negative_result": False if first_check else None,
    }


def _summarize_set07_entry(set07: bytes, buffer_base: int) -> dict:
    if len(set07) < 0x180:
        return {"entry_stub_found": False}
    stack_load = movl_literal(set07, 0)
    startup_load = movl_literal(set07, 0x3A)
    poll_load = movl_literal(set07, 0xF0)
    pre_poll_call_load = movl_literal(set07, 0x144)
    stack_ok = (
        stack_load is not None and stack_load[2] == 0
        and _be16(set07, 2) == 0x6F03
        and buffer_base <= stack_load[1] < buffer_base + len(set07)
    )
    startup_target_ok = (
        startup_load is not None and startup_load[2] == 3
        and buffer_base <= startup_load[1] < buffer_base + len(set07)
        and _be16(set07, 0x3C) == 0x430B and _be16(set07, 0x3E) == 0x0009
    )
    startup_prologue = (
        _be16(set07, 0x84) == 0x2FE6
        and _be16(set07, 0x9A) == 0x4F22
    )
    zero_loop = _branch(0x18, _be16(set07, 0x18))
    copy_loop = _branch(0x30, _be16(set07, 0x30))
    bounded_byte_loops = bool(
        zero_loop and zero_loop[0] == "BF" and zero_loop[1] == 0x0C
        and copy_loop and copy_loop[0] == "BF" and copy_loop[1] == 0x24
    )
    pre_poll_call = (
        pre_poll_call_load is not None and pre_poll_call_load[2] == 3
        and buffer_base <= pre_poll_call_load[1] < buffer_base + len(set07)
        and _be16(set07, 0x14A) == 0x430B and _be16(set07, 0x14C) == 0xE401
    )
    poll_branch = _branch(0x15A, _be16(set07, 0x15A))
    mask_poll = (
        _be16(set07, 0x14E) == 0xEA40
        and _be16(set07, 0x152) == 0x4C0B
        and _be16(set07, 0x154) == 0x0009
        and _be16(set07, 0x156) == 0x600D
        and _be16(set07, 0x158) == 0x20A8
        and poll_branch is not None and poll_branch[0] == "BT"
        and poll_branch[1] == 0x152
    )
    poll_target_inside = bool(
        poll_load is not None and poll_load[2] == 12
        and buffer_base <= poll_load[1] < buffer_base + len(set07)
    )
    return {
        "entry_stub_found": stack_ok and startup_target_ok,
        "entry_stack_pointer_literal_inside_module": stack_ok,
        "entry_calls_internal_startup_routine": startup_target_ok,
        "startup_routine_prologue_found": startup_prologue,
        "startup_has_two_bounded_byte_loops": bounded_byte_loops,
        "startup_calls_internal_helper_before_mask_poll": pre_poll_call,
        "startup_polls_until_return_value_has_mask_0x40": mask_poll,
        "mask_poll_target_is_inside_module": poll_target_inside,
        "callback_registration_confirmed": False,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    low = payloads.get("TH2.LOW", b"")
    set07 = payloads.get("SET07.BIN", b"")
    _, set_targets = _find_set_table_loader_targets(main) if main else ({}, [])
    _, low_targets, low_bases = _find_main_th2_low_load(main) if main else ({}, [], [])
    common_targets = set(set_targets).intersection(low_targets)
    base = low_bases[0] if len(set(low_bases)) == 1 else None
    all_targets = set(set_targets).union(low_targets)
    callsite = _find_set07_callsite(low, base, all_targets) if low and base is not None else None
    if len(common_targets) != 1 or callsite is None:
        return {
            "schema_version": 1,
            "stage": "stage93_loader_wrapper_and_set07_entry_audit",
            "analysis": {
                "shared_loader_target_unique": len(common_targets) == 1,
                "set07_load_entry_callsite_found": callsite is not None,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }
    loader_target = next(iter(common_targets))
    loader_offset = loader_target - CODE_LOAD_ADDRESS
    _, buffer_base = callsite
    wrapper = _summarize_loader_wrapper(main, loader_offset)
    entry = _summarize_set07_entry(set07, buffer_base)
    caller = _loader_result_summary(low, callsite[0], buffer_base)
    return {
        "schema_version": 1,
        "stage": "stage93_loader_wrapper_and_set07_entry_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "shared_loader_target_unique": True,
            "set07_load_entry_callsite_found": True,
            "loader_wrapper": wrapper,
            "set07_entry": entry,
            "caller_checks_loader_result_before_entry": caller.get("loader_result_explicitly_checked_before_entry") is True,
            "caller_invokes_same_destination_buffer_as_entry": caller.get("entry_call_uses_same_destination_buffer", False),
            "runtime_file_load_confirmed": False,
            "runtime_overlay_execution_confirmed": False,
            "runtime_callback_registration_confirmed": False,
            "runtime_dma_completion_confirmed": False,
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
