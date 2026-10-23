#!/usr/bin/env python3
"""Stage96: widen the cross-module alias census for the dispatch-slot writer.

Reads the private Saturn ISO locally. Output contains aggregate counts and
root-module-level counts only, never raw addresses, offsets, instruction bytes,
or original payloads. Candidates are static bounded scans, not proof of runtime
initialization or complete alias coverage.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage79_expanded_store_alias_audit import scan_store_aliases
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import _generic_prologues
from stage95_dispatch_slot_cross_module_audit import DISPATCH_SLOT

# Include likely pointer bases within this distance of the target slot. This
# allows bounded ADD/displacement aliases to resolve to the exact target.
POINTER_RADIUS = 0x80
SCAN_WINDOW_INSTRUCTIONS = 128


def _raw_occurrence_summary(data: bytes, value: int) -> dict:
    needle = value.to_bytes(4, "big")
    positions = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1
    literal_pool_words = {
        literal[0]
        for pos in range(0, len(data) - 5, 2)
        if (literal := movl_literal(data, pos)) is not None
    }
    return {
        "raw_big_endian_occurrence_count": len(positions),
        "halfword_aligned_occurrence_count": sum(pos % 2 == 0 for pos in positions),
        "longword_aligned_occurrence_count": sum(pos % 4 == 0 for pos in positions),
        "occurrences_matching_pc_literal_pool_words": sum(pos in literal_pool_words for pos in positions),
    }


def _summarize_payload(name: str, data: bytes) -> dict:
    aliases = scan_store_aliases(
        data,
        target=DISPATCH_SLOT,
        radius=POINTER_RADIUS,
        window=SCAN_WINDOW_INSTRUCTIONS,
    )
    exact_refs = 0
    exact_regs = Counter()
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == DISPATCH_SLOT:
            exact_refs += 1
            exact_regs[str(literal[2])] += 1
    return {
        "module": name,
        "size_bytes": len(data),
        "generic_stack_prologue_candidate_count": len(_generic_prologues(data)),
        "exact_dispatch_slot_pc_literal_reference_count": exact_refs,
        "exact_dispatch_slot_literal_register_counts": dict(sorted(exact_regs.items())),
        "raw_dispatch_slot_occurrences": _raw_occurrence_summary(data, DISPATCH_SLOT),
        "nearby_pointer_literal_load_sites_scanned": aliases["nearby_pc_literal_pointer_load_sites"],
        "bounded_exact_target_store_candidate_count": aliases["exact_target_store_candidates"],
        "bounded_store_candidates_by_mode": aliases["store_candidates_by_mode"],
        "store_candidates_using_alias_or_pointer_arithmetic": aliases["store_candidates_requiring_pointer_arithmetic_or_alias"],
        "unresolved_indexed_store_candidate_count": aliases["unresolved_indexed_store_candidates"],
        "all_store_writers_resolved": aliases["all_store_writers_resolved"],
        "runtime_initialization_order_proven": aliases["runtime_initialization_order_proven"],
    }


def summarize_payloads(payloads: dict[str, bytes]) -> dict:
    per_module = {
        name: _summarize_payload(name, data)
        for name, data in sorted(payloads.items())
    }
    totals = Counter()
    modes = Counter()
    modules_with_candidates = 0
    modules_with_unresolved_indexed = 0
    for item in per_module.values():
        totals["exact_refs"] += item["exact_dispatch_slot_pc_literal_reference_count"]
        totals["nearby_loads"] += item["nearby_pointer_literal_load_sites_scanned"]
        totals["store_candidates"] += item["bounded_exact_target_store_candidate_count"]
        totals["alias_candidates"] += item["store_candidates_using_alias_or_pointer_arithmetic"]
        totals["unresolved_indexed"] += item["unresolved_indexed_store_candidate_count"]
        modes.update(item["bounded_store_candidates_by_mode"])
        if item["bounded_exact_target_store_candidate_count"]:
            modules_with_candidates += 1
        if item["unresolved_indexed_store_candidate_count"]:
            modules_with_unresolved_indexed += 1
    return {
        "root_modules_scanned": len(per_module),
        "modules_with_generic_stack_prologue_candidates": sum(
            item["generic_stack_prologue_candidate_count"] > 0 for item in per_module.values()
        ),
        "exact_dispatch_slot_pc_literal_reference_count": totals["exact_refs"],
        "nearby_pointer_literal_load_sites_scanned": totals["nearby_loads"],
        "bounded_exact_target_store_candidate_count": totals["store_candidates"],
        "modules_with_bounded_store_candidates": modules_with_candidates,
        "bounded_store_candidates_by_mode": dict(sorted(modes.items())),
        "store_candidates_using_alias_or_pointer_arithmetic": totals["alias_candidates"],
        "unresolved_indexed_store_candidate_count": totals["unresolved_indexed"],
        "modules_with_unresolved_indexed_store_candidates": modules_with_unresolved_indexed,
        "pointer_radius_bytes": POINTER_RADIUS,
        "scan_window_instructions_after_literal_load": SCAN_WINDOW_INSTRUCTIONS,
        "store_candidates_by_root_module": {
            name: item["bounded_exact_target_store_candidate_count"]
            for name, item in per_module.items()
            if item["bounded_exact_target_store_candidate_count"]
        },
        "unresolved_indexed_candidates_by_root_module": {
            name: item["unresolved_indexed_store_candidate_count"]
            for name, item in per_module.items()
            if item["unresolved_indexed_store_candidate_count"]
        },
        "all_store_writers_resolved": False,
        "arbitrary_dynamic_aliases_or_unscanned_large_files_excluded": False,
        "runtime_initialization_order_proven": False,
        "per_module": per_module,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    summary = summarize_payloads(root["payloads"])
    return {
        "schema_version": 1,
        "stage": "stage96_dispatch_slot_writer_alias_census",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get("full_payloads_scanned", len(root["payloads"])),
            "large_files_skipped_from_code_scan": root.get("large_files_skipped_from_code_scan", 0),
            **summary,
            "runtime_dispatch_target_confirmed": False,
            "runtime_callback_invocation_confirmed": False,
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
