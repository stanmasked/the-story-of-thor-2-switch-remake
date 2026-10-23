#!/usr/bin/env python3
"""Stage102: aggregate call-site argument patterns for the unresolved service slot.

The private ISO is read locally. The report is aggregate-only: it never emits
slot values, code offsets, instruction bytes, or original payloads. Similarity
to a public SGL call pattern is corroboration, not target-identity proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage75_indirect_services_count_provenance import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import _be16
from stage100_low_memory_service_slot_provenance import (
    BOOT_CODE_END,
    BOOT_CODE_START,
    BOOT_SYSTEM_AREA_SIZE,
    _discover_service_slot,
    _slot_call_pattern_sites,
)


def _callsite_signature(data: bytes, call_site: int, lookback_instructions: int = 8) -> dict:
    """Classify only coarse argument-register setup and the call delay slot."""
    if call_site < 0 or call_site + 4 > len(data) or call_site & 1:
        return {
            "r4_pc_relative_setup_near_call": False,
            "r4_immediate_setup_near_call": False,
            "r4_setup_near_call": False,
            "r5_zero_in_call_delay_slot": False,
            "r4_immediate_in_call_delay_slot": False,
            "r5_immediate_in_call_delay_slot": False,
            "r4_setup_and_r5_zero_delay_signature": False,
        }

    delay = _be16(data, call_site + 2)
    start = max(0, call_site - lookback_instructions * 2)
    r4_pc_relative = False
    r4_immediate = False
    for pos in range(start, call_site, 2):
        opcode = _be16(data, pos)
        group = opcode >> 12
        destination = (opcode >> 8) & 0xF
        if group in (0x9, 0xD) and destination == 4:
            r4_pc_relative = True
        elif group == 0xE and destination == 4:
            r4_immediate = True

    delay_group = delay >> 12
    delay_destination = (delay >> 8) & 0xF
    r5_zero = delay == 0xE500
    r4_delay_immediate = delay_group == 0xE and delay_destination == 4
    r5_delay_immediate = delay_group == 0xE and delay_destination == 5
    r4_setup = r4_pc_relative or r4_immediate
    return {
        "r4_pc_relative_setup_near_call": r4_pc_relative,
        "r4_immediate_setup_near_call": r4_immediate,
        "r4_setup_near_call": r4_setup,
        "r5_zero_in_call_delay_slot": r5_zero,
        "r4_immediate_in_call_delay_slot": r4_delay_immediate,
        "r5_immediate_in_call_delay_slot": r5_delay_immediate,
        "r4_setup_and_r5_zero_delay_signature": r4_setup and r5_zero,
    }


def _summarize_call_sites(data: bytes, call_sites: list[int]) -> dict:
    signatures = [_callsite_signature(data, pos) for pos in call_sites]
    return {
        "slot_call_pattern_count": len(call_sites),
        "calls_with_r4_pc_relative_setup": sum(
            item["r4_pc_relative_setup_near_call"] for item in signatures
        ),
        "calls_with_r4_immediate_setup": sum(
            item["r4_immediate_setup_near_call"] for item in signatures
        ),
        "calls_with_r4_setup_and_r5_zero_delay": sum(
            item["r4_setup_and_r5_zero_delay_signature"] for item in signatures
        ),
        "calls_with_r5_zero_delay": sum(
            item["r5_zero_in_call_delay_slot"] for item in signatures
        ),
        "calls_with_r4_immediate_in_delay_slot": sum(
            item["r4_immediate_in_call_delay_slot"] for item in signatures
        ),
        "calls_with_r5_immediate_in_delay_slot": sum(
            item["r5_immediate_in_call_delay_slot"] for item in signatures
        ),
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    slot = _discover_service_slot(payloads)
    if slot is None:
        return {
            "schema_version": 1,
            "stage": "stage102_sgl_call_pattern_correlation",
            "analysis": {
                "stage100_service_slot_recovered": False,
                "callsite_signature_audit_performed": False,
                "runtime_target_confirmed": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    module_summaries = []
    for name, data in sorted(payloads.items()):
        refs, calls = _slot_call_pattern_sites(data, slot)
        if not refs and not calls:
            continue
        summary = _summarize_call_sites(data, calls)
        module_summaries.append({
            "module": name,
            "exact_literal_reference_count": refs,
            **summary,
        })

    raw_iso = image.read_bytes()
    boot_area = raw_iso[:BOOT_SYSTEM_AREA_SIZE]
    boot_refs, boot_calls = _slot_call_pattern_sites(
        boot_area, slot, BOOT_CODE_START, BOOT_CODE_END
    )
    root_counts = _summarize_call_sites(b"", []) if not module_summaries else {
        key: sum(item.get(key, 0) for item in module_summaries)
        for key in (
            "slot_call_pattern_count",
            "calls_with_r4_pc_relative_setup",
            "calls_with_r4_immediate_setup",
            "calls_with_r4_setup_and_r5_zero_delay",
            "calls_with_r5_zero_delay",
            "calls_with_r4_immediate_in_delay_slot",
            "calls_with_r5_immediate_in_delay_slot",
        )
    }

    return {
        "schema_version": 1,
        "stage": "stage102_sgl_call_pattern_correlation",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get(
                "full_payloads_scanned", len(payloads)
            ),
            "root_modules_with_slot_references": len(module_summaries),
            "root_exact_literal_reference_count": sum(
                item["exact_literal_reference_count"] for item in module_summaries
            ),
            **root_counts,
            "boot_code_window_literal_reference_count": boot_refs,
            "boot_code_window_slot_call_pattern_count": len(boot_calls),
            "public_sgl_call_shape_correlated": (
                root_counts["calls_with_r4_setup_and_r5_zero_delay"] > 0
            ),
            "public_sgl_shape_is_target_identity_proof": False,
            "runtime_slot_value_resolved": False,
            "runtime_target_confirmed": False,
            "runtime_r13_preservation_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
            "module_summaries": module_summaries,
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
