#!/usr/bin/env python3
"""Stage100: trace the unresolved low-memory service slot across disc payloads.

The ISO is read locally. The JSON report is aggregate-only and never emits
runtime addresses, file offsets, instruction bytes, or original payloads.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import _may_write_register
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import _be16, _branch
from stage92_set07_guard_predicate_audit import _delay_aware_cfg
from stage97_optional_target_provenance_cfg import _find_error_helper_entry_window
from stage98_control_byte_writer_audit import (
    _scan_control_byte_writers,
    _site_reachability,
    _source_register_seed_summary,
    _scan_store_sites_from_literal,
)
from stage99_callee_register_preservation_audit import (
    _function_end,
    _pre_store_calls,
    _reachable_calls_and_tail_exits,
)


BOOT_CODE_START = 0x200
BOOT_CODE_END = 0x1000
BOOT_SYSTEM_AREA_SIZE = 0x8000


def _slot_call_pattern_sites(
    data: bytes, slot_address: int, start: int = 0, end: int | None = None
) -> tuple[int, list[int]]:
    """Count literal references and calls through the loaded pointer in that slot.

    The pattern is MOV.L PC,Rn -> MOV.L @Rn,Rm -> JSR @Rm. Instructions that
    prepare arguments may appear between the dereference and JSR, provided
    they do not overwrite the resolved target register.
    """
    if end is None:
        end = len(data)
    exact_refs = 0
    call_sites = []
    for pos in range(start, max(start, end - 5), 2):
        literal = movl_literal(data, pos)
        if literal is None or literal[1] != slot_address:
            continue
        exact_refs += 1
        address_register = literal[2]
        target_register = None
        scan_end = min(end - 1, pos + 0x20)
        for cursor in range(pos + 2, scan_end, 2):
            opcode = _be16(data, cursor)
            branch = _branch(cursor, opcode)
            if branch is not None:
                if (
                    target_register is not None
                    and branch[0] == "JSR"
                    and ((opcode >> 8) & 0xF) == target_register
                ):
                    call_sites.append(cursor)
                break
            if target_register is None:
                # MOV.L @Rn,Rm
                if (
                    opcode & 0xF00F == 0x6002
                    and ((opcode >> 4) & 0xF) == address_register
                ):
                    target_register = (opcode >> 8) & 0xF
                    continue
                if _may_write_register(opcode, address_register):
                    break
                continue

            # After the slot has been dereferenced, allow argument setup but
            # stop if the loaded target register is overwritten.
            if _may_write_register(opcode, target_register):
                break
            if cursor + 2 >= end:
                break
            next_opcode = _be16(data, cursor + 2)
            next_branch = _branch(cursor + 2, next_opcode)
            if (
                next_branch is not None
                and next_branch[0] == "JSR"
                and ((next_opcode >> 8) & 0xF) == target_register
            ):
                call_sites.append(cursor + 2)
                break
    return exact_refs, call_sites


def _bounded_store_candidates(
    data: bytes, slot_address: int, start: int, end: int
) -> int:
    sites = set()
    for pos in range(start, max(start, end - 5), 2):
        literal = movl_literal(data, pos)
        if literal is None or abs(literal[1] - slot_address) > 16:
            continue
        stores, _unresolved = _scan_store_sites_from_literal(
            data, pos, literal[1], literal[2], slot_address
        )
        sites.update(stores)
    return len(sites)


def _discover_service_slot(payloads: dict[str, bytes]) -> int | None:
    main = payloads.get("0TH2.BIN", b"")
    helper_window = _find_error_helper_entry_window(main)
    if helper_window is None:
        return None
    state_literal = movl_literal(main, helper_window[0])
    if state_literal is None or state_literal[2] != 2:
        return None
    per_module = _scan_control_byte_writers(payloads, state_literal[1])
    main_sites = per_module.get("0TH2.BIN", {}).get("store_sites", {})
    r13_sites = [
        site for site, detail in main_sites.items()
        if detail.get("source_register") == 13 and detail.get("width") == 1
    ]
    reachable, _ = _site_reachability(main, set(r13_sites))
    sites = [site for site in r13_sites if site in reachable]
    if len(sites) != 1:
        return None
    site = sites[0]
    entry = reachable[site]["entry"]
    end = reachable[site]["end"]
    _source_register_seed_summary(main, entry, site, 13)
    calls = _pre_store_calls(main, entry, end, site)
    if not calls or calls[0]["target_kind"] != "literal":
        return None
    target = calls[0]["target_value"]
    if target is None or not CODE_LOAD_ADDRESS <= target < CODE_LOAD_ADDRESS + len(main):
        return None
    callee_entry = target - CODE_LOAD_ADDRESS
    callee_end = _function_end(main, callee_entry)
    cfg = _delay_aware_cfg(main, callee_entry, callee_end)
    slots = {
        resolved["value"]
        for _pos, _kind, resolved in _reachable_calls_and_tail_exits(
            main, callee_entry, callee_end, cfg
        )
        if resolved["kind"] == "pointer_slot" and resolved["value"] is not None
    }
    return next(iter(slots)) if len(slots) == 1 else None


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    slot_address = _discover_service_slot(payloads)
    if slot_address is None:
        return {
            "schema_version": 1,
            "stage": "stage100_low_memory_service_slot_provenance",
            "analysis": {
                "stage99_unresolved_service_slot_recovered": False,
                "slot_value_resolved_from_disc": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    per_module = _scan_control_byte_writers(payloads, slot_address)
    root_exact_refs = sum(
        item["exact_control_byte_literal_reference_count"]
        for item in per_module.values()
    )
    root_store_candidates = sum(
        item["exact_effective_address_store_candidate_count"]
        for item in per_module.values()
    )
    modules_with_refs = sum(
        item["exact_control_byte_literal_reference_count"] > 0
        for item in per_module.values()
    )
    root_call_sites = 0
    main_exact_refs = 0
    set07_exact_refs = 0
    for name, data in payloads.items():
        refs, calls = _slot_call_pattern_sites(data, slot_address)
        root_call_sites += len(calls)
        if name == "0TH2.BIN":
            main_exact_refs = refs
        elif name == "SET07.BIN":
            set07_exact_refs = refs

    raw_iso = image.read_bytes()
    boot_area = raw_iso[:BOOT_SYSTEM_AREA_SIZE]
    boot_refs, boot_calls = _slot_call_pattern_sites(
        boot_area, slot_address, BOOT_CODE_START, BOOT_CODE_END
    )
    boot_store_candidates = _bounded_store_candidates(
        boot_area, slot_address, BOOT_CODE_START, BOOT_CODE_END
    )

    return {
        "schema_version": 1,
        "stage": "stage100_low_memory_service_slot_provenance",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get("full_payloads_scanned", len(payloads)),
            "large_files_skipped_from_code_scan": root.get("large_files_skipped_from_code_scan", 0),
            "stage99_unresolved_service_slot_recovered": True,
            "root_payload_exact_literal_reference_count": root_exact_refs,
            "root_modules_with_exact_literal_references": modules_with_refs,
            "main_payload_exact_literal_reference_count": main_exact_refs,
            "set07_payload_exact_literal_reference_count": set07_exact_refs,
            "root_payload_slot_call_pattern_count": root_call_sites,
            "boot_system_area_exact_literal_reference_count": boot_refs,
            "boot_system_area_slot_call_pattern_count": len(boot_calls),
            "bounded_root_payload_store_candidate_count": root_store_candidates,
            "bounded_boot_system_area_store_candidate_count": boot_store_candidates,
            "slot_initialization_found_in_scanned_disc_code": bool(
                root_store_candidates or boot_store_candidates
            ),
            "slot_value_resolved_from_disc": False,
            "slot_runtime_target_confirmed": False,
            "standard_sh2_abi_expectation_is_not_runtime_proof": True,
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
