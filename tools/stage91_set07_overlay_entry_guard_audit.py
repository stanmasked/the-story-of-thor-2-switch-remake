#!/usr/bin/env python3
"""Stage91: audit the guarded SET07 load-and-entry path without runtime claims.

The private ISO is read locally. Output contains aggregate counts and booleans,
never raw addresses, offsets, instruction bytes, or original payloads.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads

SET_NAMES = tuple(f"SET{i:02d}.BIN".encode("ascii") for i in range(7))
NEARBY_RESOURCE_NAMES = (b"ED.BIN", b"CHR.BIN", b"CPK0.BIN", b"CPK1.BIN", b"CPK2.BIN")
INDEX10_PATTERN = {
    2: 0x6343,
    4: 0x4408,
    6: 0x343C,
    10: 0x4400,
    12: 0x644E,
    14: 0x430B,
    16: 0x341C,
}


def _be16(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos:pos + 2], "big")


def _all_occurrences(data: bytes, needle: bytes) -> list[int]:
    found = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return found
        found.append(pos)
        start = pos + 1


def _literal_references_to(data: bytes, target: int) -> list[tuple[int, int]]:
    refs = []
    for pos in range(0, len(data) - 1, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == target:
            refs.append((pos, literal[2]))
    return refs


def _find_set_table_loader_targets(data: bytes) -> tuple[dict, list[int]]:
    table_start = None
    for start in _all_occurrences(data, SET_NAMES[0]):
        if all(
            data[start + i * 10:start + i * 10 + len(name) + 1] == name + b"\x00"
            for i, name in enumerate(SET_NAMES)
        ):
            table_start = start
            break
    if table_start is None:
        return {"contiguous_set_table_found": False, "set_table_loader_candidates": 0}, []
    refs = [
        (pos, reg)
        for pos, reg in _literal_references_to(data, CODE_LOAD_ADDRESS + table_start)
        if reg == 1
    ]
    targets = []
    for pos, _ in refs:
        if pos + 18 > len(data):
            continue
        if any(_be16(data, pos + delta) != expected for delta, expected in INDEX10_PATTERN.items()):
            continue
        call_load = movl_literal(data, pos + 8)
        if call_load is not None and call_load[2] == 3:
            targets.append(call_load[1])
    return {
        "contiguous_set_table_found": True,
        "set_table_loader_candidates": len(targets),
    }, targets


def _find_main_th2_low_load(data: bytes) -> tuple[dict, list[int], list[int]]:
    occurrences = _all_occurrences(data, b"TH2.LOW")
    targets = []
    bases = []
    for string_pos in occurrences:
        for pos, reg in _literal_references_to(data, CODE_LOAD_ADDRESS + string_pos):
            if reg != 4 or pos + 8 > len(data):
                continue
            callee = movl_literal(data, pos + 2)
            if (
                callee is None
                or callee[2] != 3
                or _be16(data, pos + 4) != 0x430B
                or _be16(data, pos + 6) != 0x0009
            ):
                continue
            targets.append(callee[1])
            destination = movl_literal(data, pos - 2)
            if destination is not None and destination[2] == 5:
                bases.append(destination[1])
    return {
        "th2_low_name_occurrences": len(occurrences),
        "literal_backed_load_call_candidates": len(targets),
        "load_destination_argument_candidates": len(bases),
        "unique_load_destination_candidate_available": len(set(bases)) == 1,
    }, targets, bases


def _branch(pos: int, op: int) -> tuple[str, int | None, bool] | None:
    top = op >> 12
    if top in (0xA, 0xB):
        disp = op & 0xFFF
        if disp & 0x800:
            disp -= 0x1000
        return ("BRA" if top == 0xA else "BSR", pos + 4 + disp * 2, True)
    if top == 0x8:
        sub = (op >> 8) & 0xF
        if sub in (0x9, 0xB, 0xD, 0xF):
            disp = op & 0xFF
            if disp & 0x80:
                disp -= 0x100
            names = {0x9: "BT", 0xB: "BF", 0xD: "BT/S", 0xF: "BF/S"}
            return names[sub], pos + 4 + disp * 2, sub in (0xD, 0xF)
    if op & 0xF00F in (0x400B, 0x400A):
        return ("JSR" if op & 0xF == 0xB else "JMP", None, True)
    if op in (0x000B, 0x002B):
        return ("RTS" if op == 0x000B else "RTE", None, True)
    if op & 0xF0FF in (0x0003, 0x0023):
        return ("BSRF" if op & 0xF0FF == 0x0003 else "BRAF", None, True)
    return None


def _generic_prologues(data: bytes) -> list[int]:
    found = []
    for pos in range(0, len(data) - 0x24, 2):
        if _be16(data, pos) != 0x2FE6:
            continue
        words = [_be16(data, pos + offset) for offset in range(2, 0x24, 2)]
        try:
            r13 = words.index(0x2FD6)
            r12 = words.index(0x2FC6)
            pr = words.index(0x4F22)
        except ValueError:
            continue
        if r13 < r12 < pr and pr <= 0x10:
            found.append(pos)
    return found


def _walk_cfg(data: bytes, start: int, end: int) -> set[int]:
    seen = set()
    todo = [start]
    while todo:
        pos = todo.pop()
        if pos in seen or pos < start or pos >= end or pos & 1:
            continue
        seen.add(pos)
        op = _be16(data, pos)
        branch = _branch(pos, op)
        successors = []
        if branch is None:
            successors.append(pos + 2)
        else:
            kind, target, _delayed = branch
            if kind == "BRA":
                if target is not None:
                    successors.append(target)
            elif kind == "BSR":
                successors.append(pos + 4)
            elif kind in ("BT", "BF"):
                if target is not None:
                    successors.append(target)
                successors.append(pos + 2)
            elif kind in ("BT/S", "BF/S"):
                if target is not None:
                    successors.append(target)
                successors.append(pos + 4)
            elif kind == "JSR":
                successors.append(pos + 4)
            elif kind == "BSRF":
                successors.append(pos + 2)
        todo.extend(successors)
    return seen


def _find_set07_callsite(data: bytes, load_base: int, loader_targets: set[int]) -> tuple[int, int] | None:
    for string_pos in _all_occurrences(data, b"SET07.BIN"):
        for pos, reg in _literal_references_to(data, load_base + string_pos):
            if reg != 4 or pos + 14 > len(data):
                continue
            loader = movl_literal(data, pos + 2)
            destination = movl_literal(data, pos - 2)
            entry = movl_literal(data, pos + 8)
            if (
                loader is not None and loader[2] == 2 and loader[1] in loader_targets
                and destination is not None and destination[2] == 5
                and _be16(data, pos + 4) == 0x420B
                and _be16(data, pos + 6) == 0x0009
                and entry is not None and entry[2] == 3 and entry[1] == destination[1]
                and _be16(data, pos + 10) == 0x430B
                and _be16(data, pos + 12) == 0x0009
            ):
                return pos, destination[1]
    return None


def _gate_summary(data: bytes, name_pos: int, continuation: int) -> dict:
    lower = max(0, name_pos - 0x200)
    branch_count = 0
    tst_mask_gate = False
    for pos in range(lower, name_pos, 2):
        op = _be16(data, pos)
        branch = _branch(pos, op)
        if branch and branch[0] in ("BT", "BF", "BT/S", "BF/S") and branch[1] == continuation:
            branch_count += 1
            if op & 0xFF00 == 0x8D00 and pos >= 2 and _be16(data, pos - 2) == 0xC860:
                tst_mask_gate = True
    three_guard_signature = False
    for start in range(lower, max(lower, name_pos - 18), 2):
        words = [_be16(data, start + delta) for delta in (0, 2, 6, 8, 12, 14)]
        if words != [0x6031, 0x8860, 0x6053, 0x8806, 0x604F, 0x880F]:
            continue
        branches = [
            _branch(start + offset, _be16(data, start + offset))
            for offset in (4, 10, 16)
        ]
        if all(branch and branch[0] == "BF" and branch[1] == continuation for branch in branches):
            three_guard_signature = True
            break
    return {
        "conditional_skip_branches_to_post_entry_path": branch_count,
        "three_value_guard_signature_found": three_guard_signature,
        "tst_mask_skip_guard_found": tst_mask_gate,
        "entry_call_has_preceding_conditions": branch_count > 0,
    }


def _entry_stub_summary(set07: bytes, buffer_base: int) -> tuple[bool, int]:
    stack_literal = movl_literal(set07, 0) if set07 else None
    stub_sets_stack = (
        stack_literal is not None and stack_literal[2] == 0
        and len(set07) >= 4 and _be16(set07, 2) == 0x6F03
        and buffer_base <= stack_literal[1] < buffer_base + len(set07)
    )
    internal_literal_refs = sum(
        1 for pos in range(0, min(len(set07), 0x100) - 1, 2)
        if (literal := movl_literal(set07, pos)) is not None
        and buffer_base <= literal[1] < buffer_base + len(set07)
    )
    return stub_sets_stack, internal_literal_refs


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    low = payloads.get("TH2.LOW", b"")
    set07 = payloads.get("SET07.BIN", b"")
    table_summary, table_targets = _find_set_table_loader_targets(main) if main else ({}, [])
    main_low_summary, low_targets, low_bases = _find_main_th2_low_load(main) if main else ({}, [], [])
    base = low_bases[0] if len(set(low_bases)) == 1 else None
    loader_targets = set(table_targets).union(low_targets)
    same_main_loader = bool(set(table_targets).intersection(low_targets))
    callsite = _find_set07_callsite(low, base, loader_targets) if low and base is not None else None
    if callsite is None:
        return {
            "schema_version": 1,
            "stage": "stage91_set07_overlay_entry_guard_audit",
            "analysis": {
                "main_set_table_loader": table_summary,
                "main_th2_low_load": main_low_summary,
                "same_loader_target_used_for_th2_low_and_set_table": same_main_loader,
                "set07_loader_and_entry_callsite_found": False,
                "runtime_overlay_execution_confirmed": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }
    name_pos, buffer_base = callsite
    entry_call_pos = name_pos + 10
    prologues = _generic_prologues(low)
    previous = [pos for pos in prologues if pos < name_pos]
    following = [pos for pos in prologues if pos > entry_call_pos]
    function_start = max(previous) if previous else 0
    function_end = min(following) if following else len(low)
    reachable = _walk_cfg(low, function_start, function_end)
    stub_sets_stack, internal_literal_refs = _entry_stub_summary(set07, buffer_base)
    gates = _gate_summary(low, name_pos, entry_call_pos + 4)
    set07_positions = _all_occurrences(low, b"SET07.BIN")
    self_ref = bool(
        base is not None and set07_positions
        and _literal_references_to(low, base + set07_positions[0])
    )
    return {
        "schema_version": 1,
        "stage": "stage91_set07_overlay_entry_guard_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "main_set_table_loader": table_summary,
            "main_th2_low_load": main_low_summary,
            "same_loader_target_used_for_th2_low_and_set_table": same_main_loader,
            "candidate_th2_low_base_consistent_with_set07_literal_reference": self_ref,
            "set07_loader_and_entry_callsite_found": True,
            "candidate_function_cfg_reaches_loader_call": name_pos in reachable,
            "candidate_function_cfg_reaches_entry_call": entry_call_pos in reachable,
            "candidate_function_reachable_instruction_count": len(reachable),
            "entry_stub_sets_stack_from_internal_literal": stub_sets_stack,
            "entry_stub_internal_pointer_literal_refs": internal_literal_refs,
            **gates,
            "runtime_overlay_execution_confirmed": False,
            "runtime_callback_execution_confirmed": False,
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
