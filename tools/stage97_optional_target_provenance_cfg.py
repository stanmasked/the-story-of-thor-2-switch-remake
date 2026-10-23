#!/usr/bin/env python3
"""Stage97: audit optional error-helper target references with bounded CFG reachability.

Reads a private Saturn ISO locally. Output contains aggregate/module counts only:
no raw RAM addresses, file offsets, instruction bytes, or original payloads.
A literal-pattern match is only a candidate until its instruction site is reachable
from a recognized function prologue in the bounded delay-aware CFG.
"""
from __future__ import annotations

import argparse
import json
from bisect import bisect_right
from collections import Counter
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import (
    _be16,
    _branch,
    _find_main_th2_low_load,
    _generic_prologues,
)
from stage92_set07_guard_predicate_audit import _delay_aware_cfg
from stage95_dispatch_slot_cross_module_audit import OPTIONAL_TARGETS

MAX_FUNCTION_WINDOW = 0x400
MAX_USE_SCAN_INSTRUCTIONS = 12


def _literal_target_sites(data: bytes, target: int) -> list[tuple[int, int]]:
    """Return PC-relative literal-load candidate sites and destination registers."""
    sites = []
    for pos in range(0, len(data) - 1, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == target:
            sites.append((pos, literal[2]))
    return sites


def _function_window(
    data_size: int, site: int, prologues: list[int], max_window: int = MAX_FUNCTION_WINDOW
) -> tuple[int, int] | None:
    index = bisect_right(prologues, site) - 1
    if index < 0:
        return None
    start = prologues[index]
    if site - start >= max_window:
        return None
    end = min(data_size, start + max_window)
    if index + 1 < len(prologues):
        end = min(end, prologues[index + 1])
    if not start <= site < end:
        return None
    return start, end


def _target_use_after_literal(
    data: bytes, site: int, target_register: int, end: int,
    max_instructions: int = MAX_USE_SCAN_INSTRUCTIONS,
) -> str | None:
    """Recognize a conservative immediate indirect call/tail jump through the loaded target."""
    known_registers = {target_register}
    stop = min(end, site + 2 + max_instructions * 2)
    pos = site + 2
    while pos + 2 <= stop:
        opcode = _be16(data, pos)
        branch = _branch(pos, opcode)

        if branch is not None and branch[0] in ("JSR", "JMP"):
            used_register = (opcode >> 8) & 0xF
            if used_register in known_registers:
                return "indirect_call" if branch[0] == "JSR" else "indirect_tail_jump"
            return None
        if branch is not None:
            return None

        # MOV Rm,Rn preserves the target value and can transfer it to another register.
        if opcode & 0xF00F == 0x6003:
            destination = (opcode >> 8) & 0xF
            source = (opcode >> 4) & 0xF
            if source in known_registers:
                known_registers.add(destination)
            elif destination in known_registers:
                known_registers.remove(destination)
            pos += 2
            continue

        # NOP is the only other instruction treated as transparent. Unknown
        # instructions stop the scan rather than risk assuming register liveness.
        if opcode == 0x0009:
            pos += 2
            continue
        return None
    return None


def _summarize_target_sites(
    payloads: dict[str, bytes], target: int
) -> dict:
    per_module: dict[str, dict] = {}
    totals = Counter()
    modules_with_reachable_calls = 0
    call_modes = Counter()

    for name, data in sorted(payloads.items()):
        prologues = _generic_prologues(data)
        sites = _literal_target_sites(data, target)
        cfg_cache: dict[tuple[int, int], dict] = {}
        module = Counter()
        reachable_call_sites: set[tuple[int, str]] = set()

        for site, register in sites:
            module["raw_literal_reference_candidate_count"] += 1
            window = _function_window(len(data), site, prologues)
            if window is None:
                module["reference_sites_without_prologue_window"] += 1
                continue
            module["reference_sites_in_prologue_windows"] += 1
            if window not in cfg_cache:
                cfg_cache[window] = _delay_aware_cfg(data, window[0], window[1])
            cfg = cfg_cache[window]
            state_nodes = cfg["state_nodes"]
            at_site = [state for state in state_nodes if state[0] == site]
            normal_state_reachable = (site, None) in state_nodes

            if normal_state_reachable:
                module["reachable_reference_sites"] += 1
                use = _target_use_after_literal(data, site, register, window[1])
                if use is not None:
                    module[f"reachable_{use}_candidate_count"] += 1
                    reachable_call_sites.add((site, use))
            elif at_site:
                module["reference_sites_reachable_only_as_delay_slots"] += 1
            else:
                module["reference_sites_in_window_but_unreachable"] += 1

        module["reachable_indirect_use_candidate_count"] = len(reachable_call_sites)
        module["generic_stack_prologue_candidate_count"] = len(prologues)
        per_module[name] = dict(module)
        totals.update(module)
        if reachable_call_sites:
            modules_with_reachable_calls += 1
            call_modes.update(use for _, use in reachable_call_sites)

    return {
        "raw_literal_reference_candidate_count": totals["raw_literal_reference_candidate_count"],
        "modules_with_raw_literal_reference_candidates": sum(
            item["raw_literal_reference_candidate_count"] > 0 for item in per_module.values()
        ),
        "reference_sites_in_prologue_windows": totals["reference_sites_in_prologue_windows"],
        "reachable_reference_sites": totals["reachable_reference_sites"],
        "reference_sites_reachable_only_as_delay_slots": totals["reference_sites_reachable_only_as_delay_slots"],
        "reference_sites_in_window_but_unreachable": totals["reference_sites_in_window_but_unreachable"],
        "reference_sites_without_prologue_window": totals["reference_sites_without_prologue_window"],
        "reachable_indirect_use_candidate_count": totals["reachable_indirect_use_candidate_count"],
        "modules_with_reachable_indirect_use_candidates": modules_with_reachable_calls,
        "reachable_indirect_use_candidates_by_mode": dict(sorted(call_modes.items())),
        "raw_candidates_by_root_module": {
            name: item["raw_literal_reference_candidate_count"]
            for name, item in per_module.items()
            if item["raw_literal_reference_candidate_count"]
        },
        "reachable_candidates_by_root_module": {
            name: item["reachable_reference_sites"]
            for name, item in per_module.items()
            if item["reachable_reference_sites"]
        },
        "indirect_use_candidates_by_root_module": {
            name: item["reachable_indirect_use_candidate_count"]
            for name, item in per_module.items()
            if item["reachable_indirect_use_candidate_count"]
        },
        "per_module": per_module,
        "runtime_target_invocation_confirmed": False,
    }


def _summarize_th2_low_mapping(
    main: bytes, low: bytes, targets: tuple[int, ...] = OPTIONAL_TARGETS
) -> dict:
    load_summary, _load_targets, bases = _find_main_th2_low_load(main) if main else ({}, [], [])
    distinct_bases = sorted(set(bases))
    unique_base = distinct_bases[0] if len(distinct_bases) == 1 else None
    low_prologues = set(_generic_prologues(low))
    target_results = {}

    for index, target in enumerate(targets, 1):
        mapped = False
        aligned = False
        exact_prologue = False
        prologue_like = False
        if unique_base is not None:
            offset = target - unique_base
            mapped = 0 <= offset < len(low)
            aligned = mapped and offset % 2 == 0
            exact_prologue = aligned and offset in low_prologues
            prologue_like = bool(
                aligned and offset + 0x10 <= len(low)
                and _be16(low, offset) == 0x2FE6
                and any(_be16(low, offset + delta) == 0x4F22 for delta in range(2, 0x10, 2))
            )
        target_results[str(index)] = {
            "maps_inside_th2_low_under_unique_load_base": mapped,
            "mapped_offset_is_halfword_aligned": aligned,
            "mapped_offset_matches_generic_prologue": exact_prologue,
            "mapped_offset_matches_legacy_prologue_shape": prologue_like,
        }

    return {
        "th2_low_load_destination_candidate_count": len(bases),
        "th2_low_load_destination_distinct_candidate_count": len(distinct_bases),
        "th2_low_load_destination_unique_candidate_available": unique_base is not None,
        "th2_low_name_occurrence_count": load_summary.get("th2_low_name_occurrences", 0),
        "th2_low_literal_backed_load_call_candidate_count": load_summary.get("literal_backed_load_call_candidates", 0),
        "th2_low_destination_argument_candidate_count": load_summary.get("load_destination_argument_candidates", 0),
        "generic_stack_prologue_candidate_count_in_th2_low": len(low_prologues),
        "optional_targets": target_results,
        "mapping_is_runtime_address_space_proof": False,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    low = payloads.get("TH2.LOW", b"")
    mapping = _summarize_th2_low_mapping(main, low)
    target_summaries = {
        str(index): _summarize_target_sites(payloads, target)
        for index, target in enumerate(OPTIONAL_TARGETS, 1)
    }
    return {
        "schema_version": 1,
        "stage": "stage97_optional_target_provenance_cfg",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get("full_payloads_scanned", len(payloads)),
            "large_files_skipped_from_code_scan": root.get("large_files_skipped_from_code_scan", 0),
            "th2_low_mapping_consistency": mapping,
            "optional_target_reference_audits": target_summaries,
            "reference_reachability_is_bounded_static_evidence": True,
            "optional_target_semantics_proven": False,
            "runtime_loader_error_behavior_confirmed": False,
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
