#!/usr/bin/env python3
"""Stage94: audit the loader error helper's return boundary.

Reads the private Saturn ISO locally and emits aggregate facts only; no raw
addresses, offsets, instruction bytes, or original payloads are emitted.
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
    _find_set_table_loader_targets,
)
from stage92_set07_guard_predicate_audit import _delay_aware_cfg
from stage93_loader_wrapper_and_set07_entry_audit import _summarize_loader_wrapper


def _address_like(value: int) -> bool:
    return 0x00200000 <= value < 0x00300000 or 0x06000000 <= value < 0x06100000


def _summarize_error_helper(data: bytes, entry: int) -> dict:
    if entry < 0 or entry + 0x54 > len(data):
        return {"error_helper_signature_found": False}

    state_a = movl_literal(data, entry)
    first_indirect = movl_literal(data, entry + 8)
    dispatcher_a = movl_literal(data, entry + 0x0E)
    state_b = movl_literal(data, entry + 0x16)
    second_indirect = movl_literal(data, entry + 0x1E)
    dispatcher_b = movl_literal(data, entry + 0x24)
    branch_a = _branch(entry + 6, _be16(data, entry + 6))
    branch_b = _branch(entry + 0x1C, _be16(data, entry + 0x1C))

    signature = (
        state_a is not None and state_a[2] == 2
        and _be16(data, entry + 2) == 0x6020
        and _be16(data, entry + 4) == 0x2008
        and branch_a is not None and branch_a[0] == "BT" and branch_a[1] == entry + 0x0E
        and first_indirect is not None and first_indirect[2] == 0
        and _be16(data, entry + 0x0A) == 0x402B and _be16(data, entry + 0x0C) == 0x0009
        and dispatcher_a is not None and dispatcher_a[2] == 1
        and _be16(data, entry + 0x10) == 0x6312
        and _be16(data, entry + 0x12) == 0x432B and _be16(data, entry + 0x14) == 0x0009
        and state_b is not None and state_b[2] == 2 and state_b[1] == state_a[1]
        and _be16(data, entry + 0x18) == 0x6020
        and _be16(data, entry + 0x1A) == 0x2008
        and branch_b is not None and branch_b[0] == "BT" and branch_b[1] == entry + 0x24
        and second_indirect is not None and second_indirect[2] == 0
        and _be16(data, entry + 0x20) == 0x402B and _be16(data, entry + 0x22) == 0x0009
        and dispatcher_b is not None and dispatcher_b[2] == 1 and dispatcher_b[1] == dispatcher_a[1]
        and _be16(data, entry + 0x26) == 0x6312
        and _be16(data, entry + 0x28) == 0x432B and _be16(data, entry + 0x2A) == 0x0009
    )
    pool_start = entry + 0x2C
    pool_values = [int.from_bytes(data[pos:pos + 4], "big") for pos in range(pool_start, entry + 0x54, 4)]
    pointer_pool = len(pool_values) == 10 and sum(_address_like(v) for v in pool_values) >= 8
    cfg = _delay_aware_cfg(data, entry, pool_start)
    rts_nodes = [pos for pos in cfg["nodes"] if _be16(data, pos) in (0x000B, 0x002B)]
    final_call_returns_to_pool = (
        _be16(data, entry + 0x28) == 0x432B
        and _be16(data, entry + 0x2A) == 0x0009
        and pool_start == entry + 0x2C
        and pointer_pool
    )
    return {
        "error_helper_signature_found": signature,
        "both_conditionals_test_same_global_byte": bool(signature and state_a[1] == state_b[1]),
        "two_optional_indirect_calls_to_distinct_targets_found": bool(signature and first_indirect[1] != second_indirect[1]),
        "both_paths_call_same_indirect_dispatch_slot": bool(signature and dispatcher_a[1] == dispatcher_b[1]),
        "pointer_pool_immediately_follows_final_indirect_call": final_call_returns_to_pool,
        "pointer_pool_candidate_found": pointer_pool,
        "local_rts_or_rte_before_pointer_pool_found": bool(rts_nodes),
        "bounded_cfg_reaches_final_indirect_call": entry + 0x28 in cfg["nodes"],
        "bounded_cfg_instruction_count": len(cfg["nodes"]),
        "bounded_cfg_has_no_local_return": not bool(rts_nodes),
        "helper_appears_nonreturning_by_layout": bool(final_call_returns_to_pool and not rts_nodes),
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    _, set_targets = _find_set_table_loader_targets(main) if main else ({}, [])
    _, low_targets, _ = _find_main_th2_low_load(main) if main else ({}, [], [])
    common = set(set_targets).intersection(low_targets)
    if len(common) != 1:
        return {
            "schema_version": 1,
            "stage": "stage94_error_helper_return_audit",
            "analysis": {"shared_loader_target_unique": False, "private_addresses_or_code_offsets_emitted": False},
        }
    loader_target = next(iter(common))
    loader_entry = loader_target - CODE_LOAD_ADDRESS
    wrapper = _summarize_loader_wrapper(main, loader_entry)
    error_a = _branch(loader_entry + 0x14, _be16(main, loader_entry + 0x14))
    error_b = _branch(loader_entry + 0x2A, _be16(main, loader_entry + 0x2A))
    common_error = bool(error_a and error_b and error_a[0] == "BSR" and error_b[0] == "BSR" and error_a[1] == error_b[1])
    error = _summarize_error_helper(main, error_a[1]) if common_error and error_a[1] is not None else {"error_helper_signature_found": False}
    return {
        "schema_version": 1,
        "stage": "stage94_error_helper_return_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "shared_loader_target_unique": True,
            "both_negative_wrapper_paths_call_same_error_helper": common_error,
            "wrapper_first_error_return_address_targets_second_helper_setup": wrapper.get("first_error_call_return_address_targets_second_helper_setup", False),
            "error_helper": error,
            "negative_status_path_may_not_return_to_wrapper": error.get("helper_appears_nonreturning_by_layout", False),
            "runtime_error_helper_nonreturning_confirmed": False,
            "runtime_file_load_confirmed": False,
            "runtime_overlay_execution_confirmed": False,
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
