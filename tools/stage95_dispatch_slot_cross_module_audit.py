#!/usr/bin/env python3
"""Stage95: census the shared indirect-dispatch slot across root modules.

Reads the private Saturn ISO locally. Output contains aggregate counts and
module-level counts only, never raw addresses, offsets, instruction bytes, or
original payloads.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage91_set07_overlay_entry_guard_audit import _be16, _branch

DISPATCH_SLOT = 0x0600026C
OPTIONAL_TARGETS = (0x002E20F8, 0x002E227C)


def _is_direct_store_through_register(op: int, reg: int) -> bool:
    if (op & 0xF00F) in (0x2000, 0x2001, 0x2002) and ((op >> 8) & 0xF) == reg:
        return True
    if (op & 0xF00F) == 0x0006 and ((op >> 8) & 0xF) == reg:
        return True
    if (op & 0xF000) == 0x1000 and ((op >> 8) & 0xF) == reg and (op & 0xF) == 0:
        return True
    return False


def _slot_references(data: bytes, slot: int) -> list[tuple[int, int]]:
    refs = []
    for pos in range(0, len(data) - 1, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == slot:
            refs.append((pos, literal[2]))
    return refs


def _dispatch_call_after_ref(data: bytes, pos: int, base_reg: int) -> bool:
    if pos + 4 > len(data):
        return False
    load = _be16(data, pos + 2)
    if (load & 0xF00F) != 0x6002 or ((load >> 4) & 0xF) != base_reg:
        return False
    target_reg = (load >> 8) & 0xF
    for q in range(pos + 4, min(pos + 22, len(data) - 1), 2):
        op = _be16(data, q)
        if (op & 0xF00F) == 0x400B and ((op >> 8) & 0xF) == target_reg:
            return True
        branch = _branch(q, op)
        if branch is not None:
            return False
    return False


def _store_candidate_after_ref(data: bytes, pos: int, base_reg: int) -> bool:
    for q in range(pos + 2, min(pos + 16, len(data) - 1), 2):
        op = _be16(data, q)
        if _is_direct_store_through_register(op, base_reg):
            return True
        # A read through the pointer or any call/branch ends this short local window.
        if (op & 0xF00F) == 0x6002 and ((op >> 4) & 0xF) == base_reg:
            return False
        branch = _branch(q, op)
        if branch is not None:
            return False
    return False


def _summarize_payloads(payloads: dict[str, bytes]) -> dict:
    ref_counts = {}
    call_counts = {}
    store_candidate_counts = {}
    target_ref_counts = {str(i + 1): 0 for i in range(len(OPTIONAL_TARGETS))}
    target_modules = {str(i + 1): set() for i in range(len(OPTIONAL_TARGETS))}

    for name, data in payloads.items():
        refs = []
        module_targets = set()
        for pos in range(0, len(data) - 1, 2):
            literal = movl_literal(data, pos)
            if literal is None:
                continue
            if literal[1] == DISPATCH_SLOT:
                refs.append((pos, literal[2]))
            for idx, target in enumerate(OPTIONAL_TARGETS, 1):
                if literal[1] == target:
                    target_ref_counts[str(idx)] += 1
                    module_targets.add(str(idx))
        for key in module_targets:
            target_modules[key].add(name)
        ref_counts[name] = len(refs)
        call_counts[name] = sum(_dispatch_call_after_ref(data, pos, reg) for pos, reg in refs)
        store_candidate_counts[name] = sum(_store_candidate_after_ref(data, pos, reg) for pos, reg in refs)

    modules_with_refs = sum(count > 0 for count in ref_counts.values())
    modules_with_calls = sum(count > 0 for count in call_counts.values())
    total_refs = sum(ref_counts.values())
    total_calls = sum(call_counts.values())
    total_store_candidates = sum(store_candidate_counts.values())
    return {
        "dispatcher_slot_literal_reference_candidates": total_refs,
        "modules_with_dispatcher_slot_references": modules_with_refs,
        "recognized_indirect_dispatch_call_sites": total_calls,
        "modules_with_recognized_dispatch_calls": modules_with_calls,
        "reference_candidates_by_root_module": ref_counts,
        "recognized_calls_by_root_module": call_counts,
        "bounded_store_through_slot_candidates": total_store_candidates,
        "store_candidates_by_root_module": store_candidate_counts,
        "optional_indirect_target_literal_reference_counts": target_ref_counts,
        "optional_indirect_target_module_counts": {key: len(value) for key, value in target_modules.items()},
        "dispatcher_slot_initialization_source_resolved": False,
        "callback_registration_proven_by_slot_census": False,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    summary = _summarize_payloads(root["payloads"])
    return {
        "schema_version": 1,
        "stage": "stage95_dispatch_slot_cross_module_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            **summary,
            "runtime_callback_invocation_confirmed": False,
            "runtime_dispatch_target_confirmed": False,
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
