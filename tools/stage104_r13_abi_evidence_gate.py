#!/usr/bin/env python3
"""Stage104: gate the conditional R13 claim using sanitized Stage99/103 reports.

This tool consumes aggregate JSON reports only; it never opens the original
ISO or emits private addresses, offsets, instruction bytes, or payloads.
Passing the gate supports a conditional ABI-based static claim, not runtime
proof that the BIOS slot target is SYS_CHGSCUIM.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def evaluate(stage99: dict[str, Any], stage103: dict[str, Any]) -> dict[str, Any]:
    a99 = stage99.get("analysis", {})
    a103 = stage103.get("analysis", {})
    calls = a99.get("pre_store_call_summaries", [])
    direct_callee_preserves = any(
        item.get("role") == "in_image_direct_callee"
        and item.get("r13_preservation_proven") is True
        for item in calls
    )
    first_callee_direct_writes = a99.get("first_callee_direct_r13_write_count")
    first_callee_has_dynamic_call = (
        a99.get("first_callee_has_unresolved_indirect_pointer_call") is True
    )
    first_callee_has_no_direct_r13_writes = first_callee_direct_writes == 0
    wrapper_success_preserves = (
        a99.get("loader_wrapper_normal_success_path_preserves_r13") is True
    )
    seed_one = a99.get("second_writer_source_register_seeded_to_one") is True
    expected_call_count = a99.get("pre_store_call_count") == 3
    writer_is_delay_slot = a99.get("second_writer_is_final_call_delay_slot") is True
    slot_arguments_match = (
        a103.get("documented_sys_chgscuim_argument_shape_compatible") is True
        and a103.get("all_scanned_slot_call_pairs_resolved", 0) >= 1
    )

    conditions = {
        "second_writer_source_seeded_to_one": seed_one,
        "three_pre_store_calls_identified": expected_call_count,
        "writer_is_final_bsr_delay_slot": writer_is_delay_slot,
        "dynamic_slot_call_is_present": first_callee_has_dynamic_call,
        "first_callee_has_no_direct_r13_writes": first_callee_has_no_direct_r13_writes,
        "local_direct_callee_preserves_r13": direct_callee_preserves,
        "loader_wrapper_success_path_preserves_r13": wrapper_success_preserves,
        "slot_argument_shape_compatible_with_sys_chgscuim": slot_arguments_match,
    }
    conditional_claim_supported = all(conditions.values())
    return {
        "schema_version": 1,
        "stage": "stage104_r13_abi_evidence_gate",
        "analysis": {
            "evidence_conditions": conditions,
            "conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi": (
                conditional_claim_supported
            ),
            "default_shc_abi_preserves_r8_to_r14_is_external_assumption": True,
            "specific_bios_implementation_register_preservation_verified": False,
            "runtime_slot_target_confirmed": False,
            "runtime_r13_preservation_confirmed": False,
            "unconditional_r13_one_proven": False,
            "runtime_control_byte_value_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage99_report", type=Path)
    parser.add_argument("stage103_report", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    stage99 = json.loads(args.stage99_report.read_text(encoding="utf-8"))
    stage103 = json.loads(args.stage103_report.read_text(encoding="utf-8"))
    rendered = json.dumps(evaluate(stage99, stage103), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
