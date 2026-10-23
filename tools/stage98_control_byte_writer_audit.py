#!/usr/bin/env python3
"""Stage98: trace static writers to the loader error-helper control byte.

The private Saturn ISO is read locally. Output is aggregate-only: no RAM
addresses, file offsets, instruction bytes, or original payloads are emitted.
Store candidates must be reached from a bounded caller-derived CFG anchor;
a delay-slot store is reported separately from a normal instruction site.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import _may_write_register
from stage79_expanded_store_alias_audit import (
    _is_control_transfer,
    _signed8,
    _store_shape,
)
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import (
    _be16,
    _branch,
    _generic_prologues,
)
from stage92_set07_guard_predicate_audit import _delay_aware_cfg
from stage97_optional_target_provenance_cfg import _find_error_helper_entry_window

MAX_FUNCTION_WINDOW = 0x400
MAX_STORE_SCAN_INSTRUCTIONS = 128
POINTER_RADIUS = 16


def _scan_store_sites_from_literal(
    data: bytes,
    start: int,
    literal_value: int,
    pointer_reg: int,
    target: int,
    radius: int = POINTER_RADIUS,
    window: int = MAX_STORE_SCAN_INSTRUCTIONS,
) -> tuple[dict[int, dict], set[int]]:
    """Bounded pointer-alias scan; returns exact effective-address store candidates."""
    regs: dict[int, int] = {pointer_reg: literal_value}
    adjusted: dict[int, bool] = {pointer_reg: literal_value != target}
    stores: dict[int, dict] = {}
    unresolved_indexed: set[int] = set()
    stop = min(len(data) - 1, start + window * 2)

    def inspect_store(pos: int, opcode: int) -> None:
        shape = _store_shape(opcode)
        if shape is None:
            return
        mode, base_reg, width, displacement, indexed = shape
        if base_reg not in regs:
            return
        base_value = regs[base_reg]
        if indexed:
            if 0 in regs:
                effective = base_value + regs[0]
            else:
                if abs(base_value - target) <= radius:
                    unresolved_indexed.add(pos)
                return
        else:
            effective = base_value + displacement
        if effective == target:
            stores[pos] = {
                "mode": mode,
                "width": width,
                "base_register": base_reg,
                "source_register": (opcode >> 4) & 0xF,
                "pointer_adjusted": adjusted.get(base_reg, False) or base_value != literal_value,
            }
        if mode == "predecrement":
            regs[base_reg] = base_value - width
            adjusted[base_reg] = True

    pos = start + 2
    while pos < stop:
        opcode = _be16(data, pos)
        inspect_store(pos, opcode)

        literal = movl_literal(data, pos)
        if literal is not None:
            regs[literal[2]] = literal[1]
            adjusted[literal[2]] = literal[2] != pointer_reg or literal[1] != target
            pos += 2
            continue

        if opcode >> 12 == 0x7:
            reg = (opcode >> 8) & 0xF
            if reg in regs:
                regs[reg] = (regs[reg] + _signed8(opcode & 0xFF)) & 0xFFFFFFFF
                adjusted[reg] = True
            pos += 2
            continue

        if opcode >> 12 == 0x6 and opcode & 0xF == 0x3:
            destination = (opcode >> 8) & 0xF
            source = (opcode >> 4) & 0xF
            if source in regs:
                regs[destination] = regs[source]
                adjusted[destination] = (
                    adjusted.get(source, False)
                    or destination != pointer_reg
                    or regs[source] != target
                )
            elif destination in regs:
                del regs[destination]
                adjusted.pop(destination, None)
            pos += 2
            continue

        if _is_control_transfer(opcode):
            delay_pos = pos + 2
            if delay_pos + 2 <= len(data):
                inspect_store(delay_pos, _be16(data, delay_pos))
            break

        for register in tuple(regs):
            if _may_write_register(opcode, register):
                regs.pop(register, None)
                adjusted.pop(register, None)
        pos += 2

    return stores, unresolved_indexed


def _scan_control_byte_writers(
    payloads: dict[str, bytes], target: int
) -> dict[str, dict]:
    per_module: dict[str, dict] = {}
    for name, data in sorted(payloads.items()):
        literal_sites = []
        store_sites: dict[int, dict] = {}
        unresolved: set[int] = set()
        for pos in range(0, len(data) - 5, 2):
            literal = movl_literal(data, pos)
            if literal is None or abs(literal[1] - target) > POINTER_RADIUS:
                continue
            literal_sites.append((pos, literal[1], literal[2]))
            found, unknown = _scan_store_sites_from_literal(
                data, pos, literal[1], literal[2], target
            )
            for store_pos, detail in found.items():
                previous = store_sites.get(store_pos)
                if previous is None:
                    store_sites[store_pos] = detail
                elif previous != detail:
                    previous["pointer_provenance_ambiguous"] = True
            unresolved.update(unknown)
        exact_refs = sum(
            1 for pos in range(0, len(data) - 5, 2)
            if (literal := movl_literal(data, pos)) is not None and literal[1] == target
        )
        if literal_sites or store_sites or unresolved or exact_refs:
            per_module[name] = {
                "exact_control_byte_literal_reference_count": exact_refs,
                "nearby_pointer_literal_load_candidate_count": len(literal_sites),
                "exact_effective_address_store_candidate_count": len(store_sites),
                "unresolved_indexed_store_candidate_count": len(unresolved),
                "store_sites": store_sites,
            }
    return per_module


def _caller_entry_anchors(data: bytes) -> list[tuple[int, int, int]]:
    """Find literal-backed JSRs whose target is inside the same loaded main payload."""
    prologues = _generic_prologues(data)
    anchors = set()
    code_end = CODE_LOAD_ADDRESS + len(data)
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None or not CODE_LOAD_ADDRESS <= literal[1] < code_end:
            continue
        call_pos = pos + 2
        opcode = _be16(data, call_pos)
        if (opcode & 0xF0FF) != 0x400B or ((opcode >> 8) & 0xF) != literal[2]:
            continue
        entry = literal[1] - CODE_LOAD_ADDRESS
        end = min(len(data), entry + MAX_FUNCTION_WINDOW)
        next_prologue = next((p for p in prologues if p > entry), None)
        if next_prologue is not None:
            end = min(end, next_prologue)
        if entry < end:
            anchors.add((pos, entry, end))
    return sorted(anchors)


def _source_register_seed_summary(
    data: bytes, entry: int, site: int, source_register: int
) -> dict:
    seed_value = None
    seed_seen = False
    explicit_overwrite = False
    calls_before_store = 0
    non_call_control_transfers_before_store = 0
    for pos in range(entry, site, 2):
        opcode = _be16(data, pos)
        destination = (opcode >> 8) & 0xF

        if opcode >> 12 == 0xE and destination == source_register:
            seed_value = _signed8(opcode & 0xFF)
            seed_seen = True
            explicit_overwrite = False
            continue

        branch = _branch(pos, opcode)
        if branch is not None:
            if pos + 2 < site:
                if branch[0] in ("BSR", "JSR", "BSRF"):
                    calls_before_store += 1
                else:
                    non_call_control_transfers_before_store += 1
            continue

        if seed_seen and _may_write_register(opcode, source_register):
            explicit_overwrite = True

    return {
        "source_register": f"R{source_register}",
        "last_immediate_seed_found": seed_seen,
        "last_immediate_seed_value": seed_value if seed_seen else None,
        "explicit_caller_local_overwrite_after_seed": explicit_overwrite,
        "lexical_call_sites_before_store": calls_before_store,
        "non_call_control_transfers_before_store": non_call_control_transfers_before_store,
        "source_value_proven_at_store": bool(
            seed_seen and not explicit_overwrite and calls_before_store == 0
            and non_call_control_transfers_before_store == 0
        ),
        "interprocedural_register_preservation_proven": False,
    }


def _site_reachability(
    data: bytes, sites: set[int]
) -> tuple[dict[int, dict], int]:
    anchors = _caller_entry_anchors(data)
    found: dict[int, dict] = {}
    analyzed_anchor_count = 0
    for _call_pos, entry, end in anchors:
        relevant = {site for site in sites if entry <= site < end}
        if not relevant:
            continue
        cfg = _delay_aware_cfg(data, entry, end)
        reachable_here = {}
        for site in relevant:
            states = cfg["state_nodes"]
            normal = (site, None) in states
            delay_only = any(pc == site and pending is not None for pc, pending in states)
            if normal or delay_only:
                reachable_here[site] = {
                    "normal_instruction_reachable": normal,
                    "reachable_as_delay_slot": delay_only,
                    "entry": entry,
                    "end": end,
                }
        if reachable_here:
            analyzed_anchor_count += 1
            for site, detail in reachable_here.items():
                previous = found.get(site)
                if previous is None:
                    found[site] = detail
                else:
                    previous["normal_instruction_reachable"] |= detail["normal_instruction_reachable"]
                    previous["reachable_as_delay_slot"] |= detail["reachable_as_delay_slot"]
                    previous["entry_anchor_count"] += 1
                found[site].setdefault("entry_anchor_count", 1)
    return found, analyzed_anchor_count


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    entry_window = _find_error_helper_entry_window(main)
    if entry_window is None:
        return {
            "schema_version": 1,
            "stage": "stage98_control_byte_writer_audit",
            "analysis": {
                "error_helper_entry_anchor_found": False,
                "control_byte_writer_analysis_completed": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    helper_entry = entry_window[0]
    state_literal = movl_literal(main, helper_entry)
    if state_literal is None or state_literal[2] != 2:
        return {
            "schema_version": 1,
            "stage": "stage98_control_byte_writer_audit",
            "analysis": {
                "error_helper_entry_anchor_found": True,
                "control_byte_pointer_extraction_confirmed": False,
                "control_byte_writer_analysis_completed": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    state_address = state_literal[1]
    per_module = _scan_control_byte_writers(payloads, state_address)
    main_sites = per_module.get("0TH2.BIN", {}).get("store_sites", {})
    site_reachability, reachable_anchor_count = _site_reachability(
        main, set(main_sites)
    )

    mode_counts = Counter()
    width_counts = Counter()
    source_counts = Counter()
    reachable_sites = []
    delay_only_count = 0
    normal_count = 0
    for site, detail in sorted(main_sites.items()):
        mode_counts[detail["mode"]] += 1
        width_counts[str(detail["width"])] += 1
        source_counts[f"R{detail['source_register']}"] += 1
        reach = site_reachability.get(site, {})
        if reach:
            is_delay = reach["reachable_as_delay_slot"]
            is_normal = reach["normal_instruction_reachable"]
            delay_only_count += bool(is_delay and not is_normal)
            normal_count += bool(is_normal)
            entry = reach["entry"]
            source = _source_register_seed_summary(
                main, entry, site, detail["source_register"]
            )
            reachable_sites.append({
                "store_mode": detail["mode"],
                "store_width_bytes": detail["width"],
                "source_register": f"R{detail['source_register']}",
                "reachable_from_literal_backed_caller_entry": True,
                "normal_instruction_reachable": is_normal,
                "reachable_as_delay_slot": is_delay,
                **source,
            })

    exact_refs = sum(item["exact_control_byte_literal_reference_count"] for item in per_module.values())
    all_stores = sum(item["exact_effective_address_store_candidate_count"] for item in per_module.values())
    reachable_store_count = len(reachable_sites)
    return {
        "schema_version": 1,
        "stage": "stage98_control_byte_writer_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get("full_payloads_scanned", len(payloads)),
            "large_files_skipped_from_code_scan": root.get("large_files_skipped_from_code_scan", 0),
            "error_helper_entry_anchor_found": True,
            "control_byte_pointer_extraction_confirmed": True,
            "exact_control_byte_literal_reference_count": exact_refs,
            "modules_with_exact_control_byte_references": sum(
                item["exact_control_byte_literal_reference_count"] > 0
                for item in per_module.values()
            ),
            "exact_effective_address_store_candidate_count": all_stores,
            "modules_with_exact_store_candidates": sum(
                item["exact_effective_address_store_candidate_count"] > 0
                for item in per_module.values()
            ),
            "main_payload_literal_backed_caller_entry_anchor_count_reaching_writers": reachable_anchor_count,
            "main_payload_reachable_store_candidate_count": reachable_store_count,
            "main_payload_store_candidates_reachable_only_as_delay_slots": delay_only_count,
            "main_payload_store_candidates_reachable_as_normal_instructions": normal_count,
            "reachable_store_modes": dict(sorted(mode_counts.items())),
            "reachable_store_widths_bytes": dict(sorted(width_counts.items())),
            "reachable_store_source_registers": dict(sorted(source_counts.items())),
            "reachable_writer_site_summaries": reachable_sites,
            "writer_candidate_counts_by_root_module": {
                name: item["exact_effective_address_store_candidate_count"]
                for name, item in per_module.items()
                if item["exact_effective_address_store_candidate_count"]
            },
            "non_main_module_exact_store_candidates": sum(
                item["exact_effective_address_store_candidate_count"]
                for name, item in per_module.items() if name != "0TH2.BIN"
            ),
            "control_byte_initialization_semantics_proven": False,
            "interprocedural_source_register_preservation_proven": False,
            "runtime_control_byte_value_confirmed": False,
            "runtime_error_branch_selection_confirmed": False,
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
