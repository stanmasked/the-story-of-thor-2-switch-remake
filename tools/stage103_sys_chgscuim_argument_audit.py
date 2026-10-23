#!/usr/bin/env python3
"""Stage103: audit local argument provenance for the shared Saturn service slot.

The original ISO is read locally and never modified. Output contains aggregate
argument-shape counts only, not argument values, RAM addresses, code offsets,
instruction bytes, or original payloads. SYS_CHGSCUIM compatibility is a
static hypothesis, not proof of the runtime function pointer target.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage75_indirect_services_count_provenance import _may_write_register
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import _be16
from stage100_low_memory_service_slot_provenance import (
    BOOT_CODE_END,
    BOOT_CODE_START,
    BOOT_SYSTEM_AREA_SIZE,
    _discover_service_slot,
    _slot_call_pattern_sites,
)

LOOKBACK_BYTES = 0x100
MAX_COPY_DEPTH = 8


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _constant_written_at(
    data: bytes, pos: int, register: int, depth: int = 0
) -> tuple[int | None, str]:
    """Decode a bounded set of constant writes; return None for unknown writes."""
    if pos < 0 or pos + 2 > len(data) or depth > MAX_COPY_DEPTH:
        return None, "unresolved"
    opcode = _be16(data, pos)
    group = opcode >> 12
    destination = (opcode >> 8) & 0xF
    if not _may_write_register(opcode, register) or destination != register:
        return None, "not_a_direct_write"

    if group == 0xE:
        return _signed(opcode & 0xFF, 8), "immediate"
    if group == 0x9:
        literal_pos = ((pos + 4) & ~3) + (opcode & 0xFF) * 2
        if literal_pos + 2 > len(data):
            return None, "unresolved_pc_word"
        return _signed(_be16(data, literal_pos), 16), "pc_relative_word"
    if group == 0xD:
        literal = movl_literal(data, pos)
        if literal is None or literal[2] != register:
            return None, "unresolved_pc_long"
        return _signed(literal[1], 32), "pc_relative_long"
    if group == 0x6 and (opcode & 0xF) == 0x3:
        source_register = (opcode >> 4) & 0xF
        value, _source = _constant_before(
            data, pos, source_register, depth=depth + 1
        )
        return (value, "register_copy") if value is not None else (
            None, "unresolved_register_copy"
        )
    return None, "other_write"


def _constant_before(
    data: bytes,
    pos: int,
    register: int,
    *,
    depth: int = 0,
    lookback_bytes: int = LOOKBACK_BYTES,
) -> tuple[int | None, str]:
    """Find the nearest statically decodable write in a bounded linear window.

    This is local provenance, not a CFG proof: branch-dependent writes and
    register side effects outside the window can leave the value unresolved.
    """
    if depth > MAX_COPY_DEPTH:
        return None, "copy_depth_limit"
    start = max(0, pos - lookback_bytes)
    for candidate in range(pos - 2, start - 1, -2):
        opcode = _be16(data, candidate)
        if not _may_write_register(opcode, register):
            continue
        return _constant_written_at(data, candidate, register, depth=depth)
    return None, "not_found_in_window"


def _constant_at_call(
    data: bytes, call_site: int, register: int
) -> tuple[int | None, str]:
    """Resolve the last local constant source, including a call delay-slot write."""
    if call_site < 0 or call_site + 4 > len(data):
        return None, "invalid_call_site"
    delay_pos = call_site + 2
    delay_opcode = _be16(data, delay_pos)
    if _may_write_register(delay_opcode, register):
        value, source = _constant_written_at(data, delay_pos, register)
        return (value, "delay_" + source) if value is not None else (
            None, "unresolved_delay_write"
        )
    return _constant_before(data, call_site, register)


def _pair_category(r4: int | None, r5: int | None) -> str:
    if r4 is None or r5 is None:
        return "unresolved"
    if r4 < 0 and r5 == 0:
        return "negative_r4_zero_r5"
    if r4 < 0 and 0 < r5 <= 3:
        return "negative_r4_small_nonzero_r5"
    return "other_resolved_pair"


def _summarize_calls(data: bytes, calls: list[int]) -> dict:
    pairs = [
        (
            *_constant_at_call(data, call_site, 4),
            *_constant_at_call(data, call_site, 5),
        )
        for call_site in calls
    ]
    # Pair tuples are (r4_value, r4_source, r5_value, r5_source).
    categories = [
        _pair_category(pair[0], pair[2])
        for pair in pairs
    ]
    return {
        "slot_call_pattern_count": len(calls),
        "argument_pairs_resolved_in_bounded_linear_windows": sum(
            pair[0] is not None and pair[2] is not None for pair in pairs
        ),
        "calls_with_negative_r4_and_zero_r5": categories.count(
            "negative_r4_zero_r5"
        ),
        "calls_with_negative_r4_and_small_nonzero_r5": categories.count(
            "negative_r4_small_nonzero_r5"
        ),
        "calls_with_other_resolved_argument_pair": categories.count(
            "other_resolved_pair"
        ),
        "calls_with_unresolved_argument_pair": categories.count("unresolved"),
        "calls_with_pc_relative_word_r4_and_zero_r5": sum(
            pair[0] is not None
            and pair[1] == "pc_relative_word"
            and pair[2] == 0
            for pair in pairs
        ),
        "calls_with_delay_immediate_r4_and_zero_r5": sum(
            pair[0] is not None
            and pair[1] == "delay_immediate"
            and pair[2] == 0
            for pair in pairs
        ),
        "calls_with_delay_immediate_r4_and_nonzero_r5": sum(
            pair[0] is not None
            and pair[1] == "delay_immediate"
            and pair[2] is not None
            and pair[2] != 0
            for pair in pairs
        ),
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    slot = _discover_service_slot(payloads)
    if slot is None:
        return {
            "schema_version": 1,
            "stage": "stage103_sys_chgscuim_argument_audit",
            "analysis": {
                "stage100_service_slot_recovered": False,
                "argument_provenance_audit_performed": False,
                "runtime_target_confirmed": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    module_summaries = []
    root_pairs = []
    for name, data in sorted(payloads.items()):
        refs, calls = _slot_call_pattern_sites(data, slot)
        if not refs and not calls:
            continue
        summary = _summarize_calls(data, calls)
        module_summaries.append({
            "module": name,
            "exact_literal_reference_count": refs,
            **summary,
        })
        for call_site in calls:
            root_pairs.append((
                *_constant_at_call(data, call_site, 4),
                *_constant_at_call(data, call_site, 5),
            ))

    raw_iso = image.read_bytes()
    boot_area = raw_iso[:BOOT_SYSTEM_AREA_SIZE]
    boot_refs, boot_calls = _slot_call_pattern_sites(
        boot_area, slot, BOOT_CODE_START, BOOT_CODE_END
    )
    boot_summary = _summarize_calls(boot_area, boot_calls)
    all_pairs = root_pairs + [
        (
            *_constant_at_call(boot_area, call_site, 4),
            *_constant_at_call(boot_area, call_site, 5),
        )
        for call_site in boot_calls
    ]
    all_categories = [
        _pair_category(pair[0], pair[2])
        for pair in all_pairs
    ]
    resolved_pairs = sum(
        pair[0] is not None and pair[2] is not None for pair in all_pairs
    )
    mask_shape_pairs = sum(
        category in ("negative_r4_zero_r5", "negative_r4_small_nonzero_r5")
        for category in all_categories
    )

    return {
        "schema_version": 1,
        "stage": "stage103_sys_chgscuim_argument_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get(
                "full_payloads_scanned", len(payloads)
            ),
            "root_modules_with_slot_references": len(module_summaries),
            "root_exact_literal_reference_count": sum(
                item["exact_literal_reference_count"] for item in module_summaries
            ),
            "root_slot_call_pattern_count": len(root_pairs),
            "root_argument_pairs_resolved": sum(
                pair[0] is not None and pair[2] is not None for pair in root_pairs
            ),
            "root_calls_with_negative_r4_and_zero_r5": sum(
                item["calls_with_negative_r4_and_zero_r5"]
                for item in module_summaries
            ),
            "root_calls_with_negative_r4_and_small_nonzero_r5": sum(
                item["calls_with_negative_r4_and_small_nonzero_r5"]
                for item in module_summaries
            ),
            "root_calls_with_pc_relative_word_r4_and_zero_r5": sum(
                item["calls_with_pc_relative_word_r4_and_zero_r5"]
                for item in module_summaries
            ),
            "boot_code_window_literal_reference_count": boot_refs,
            "boot_code_window_slot_call_pattern_count": len(boot_calls),
            "boot_code_window_argument_pairs_resolved": boot_summary[
                "argument_pairs_resolved_in_bounded_linear_windows"
            ],
            "all_scanned_slot_call_pairs_resolved": resolved_pairs,
            "all_scanned_pairs_with_negative_r4_mask_shape_and_small_r5": mask_shape_pairs,
            "documented_sys_chgscuim_argument_shape_compatible": (
                len(all_pairs) > 0 and resolved_pairs == len(all_pairs)
                and mask_shape_pairs == len(all_pairs)
            ),
            "argument_values_are_cfg_proven_on_all_paths": False,
            "slot_initializer_in_disc_proven": False,
            "runtime_slot_value_resolved": False,
            "runtime_target_identified_as_sys_chgscuim": False,
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
