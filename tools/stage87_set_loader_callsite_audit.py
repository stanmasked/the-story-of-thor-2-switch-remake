#!/usr/bin/env python3
"""Stage87: trace SET filename-table references and bound loader-callsite evidence.

The original ISO stays local. Output contains aggregate counts and booleans only;
it never emits file offsets, RAM addresses, instruction bytes, or game payloads.
A literal-backed filename-table consumer is static evidence, not runtime proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage85_disc_slot_writer_census import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads

SET_TABLE_NAMES = tuple(f"SET{index:02d}.BIN".encode("ascii") for index in range(7))
LOW_NEARBY_RESOURCE_NAMES = (
    b"ED.BIN", b"CHR.BIN", b"CPK0.BIN", b"CPK1.BIN", b"CPK2.BIN",
)
# This signature is the observed index*10 calculation and indirect-call sequence
# following the literal-backed SET00.BIN pointer in 0TH2.BIN.
_INDEX10_CALL_PATTERN = {
    2: 0x6343,   # MOV R4,R3
    4: 0x4408,   # SHLL2 R4
    6: 0x343C,   # ADD R3,R4
    10: 0x4400,  # SHLL R4 -> index * 10
    12: 0x644E,  # EXTU.W R4,R4
    14: 0x430B,  # JSR @R3
    16: 0x341C,  # delay slot: ADD R1,R4 (filename-table base + index*10)
}


def _all_occurrences(data: bytes, needle: bytes) -> list[int]:
    found: list[int] = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return found
        found.append(pos)
        start = pos + 1


def find_contiguous_set_table(data: bytes) -> int | None:
    """Return the SET00.BIN start only when SET00..SET06 are packed at 10-byte strides."""
    for start in _all_occurrences(data, SET_TABLE_NAMES[0]):
        if all(
            data[start + index * 10:start + index * 10 + len(name) + 1]
            == name + b"\x00"
            for index, name in enumerate(SET_TABLE_NAMES)
        ):
            return start
    return None


def _literal_references_to(data: bytes, target_address: int) -> list[tuple[int, int]]:
    references = []
    for pos in range(0, len(data) - 1, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == target_address:
            references.append((pos, literal[2]))
    return references


def _matches_index10_indirect_call(data: bytes, pos: int) -> tuple[bool, bool]:
    """Match the local filename-pointer calculation; return (match, target-in-image)."""
    if pos < 0 or pos + 18 > len(data):
        return False, False
    for delta, expected in _INDEX10_CALL_PATTERN.items():
        if int.from_bytes(data[pos + delta:pos + delta + 2], "big") != expected:
            return False, False
    call_load = movl_literal(data, pos + 8)
    if call_load is None or call_load[2] != 3:
        return False, False
    target = call_load[1]
    target_in_image = CODE_LOAD_ADDRESS <= target < CODE_LOAD_ADDRESS + len(data)
    return True, target_in_image


def _find_set_table_loader_targets(data: bytes) -> tuple[dict, list[int]]:
    table_start = find_contiguous_set_table(data)
    if table_start is None:
        summary = {
            "set00_to_set06_contiguous_name_table": False,
            "set_name_count_in_table": 0,
            "literal_backed_table_reference_count": 0,
            "index10_filename_argument_call_candidates": 0,
            "candidate_call_targets_inside_main_image": 0,
            "resource_loader_candidate_found": False,
            "runtime_file_load_confirmed": False,
        }
        return summary, []

    table_address = CODE_LOAD_ADDRESS + table_start
    refs = [(pos, reg) for pos, reg in _literal_references_to(data, table_address) if reg == 1]
    matched = 0
    internal_targets = 0
    targets = []
    for pos, _ in refs:
        pattern, internal = _matches_index10_indirect_call(data, pos)
        if pattern:
            matched += 1
            internal_targets += int(internal)
            call_load = movl_literal(data, pos + 8)
            if call_load is not None and call_load[2] == 3:
                targets.append(call_load[1])
    summary = {
        "set00_to_set06_contiguous_name_table": True,
        "set_name_count_in_table": len(SET_TABLE_NAMES),
        "literal_backed_table_reference_count": len(refs),
        "index10_filename_argument_call_candidates": matched,
        "candidate_call_targets_inside_main_image": internal_targets,
        "resource_loader_candidate_found": matched > 0,
        "runtime_file_load_confirmed": False,
    }
    return summary, targets


def summarize_main_set_loader(data: bytes) -> dict:
    return _find_set_table_loader_targets(data)[0]


def _find_main_name_loader_targets(data: bytes, name: bytes) -> tuple[dict, list[int], list[int]]:
    occurrences = _all_occurrences(data, name)
    targets = []
    destination_candidates = []
    internal_targets = 0
    for string_pos in occurrences:
        address = CODE_LOAD_ADDRESS + string_pos
        for pos, reg in _literal_references_to(data, address):
            if reg != 4 or pos + 8 > len(data):
                continue
            # Observed generic filename-load call: R4=name pointer, R3=callee,
            # JSR @R3 and NOP delay slot.
            callee_load = movl_literal(data, pos + 2)
            if (
                callee_load is None
                or callee_load[2] != 3
                or int.from_bytes(data[pos + 4:pos + 6], "big") != 0x430B
                or int.from_bytes(data[pos + 6:pos + 8], "big") != 0x0009
            ):
                continue
            targets.append(callee_load[1])
            internal_targets += int(
                CODE_LOAD_ADDRESS <= callee_load[1] < CODE_LOAD_ADDRESS + len(data)
            )
            # The preceding literal load places a second argument in R5. Treat
            # it as a destination candidate only; the callee's full semantics
            # still need independent verification.
            destination_load = movl_literal(data, pos - 2)
            if destination_load is not None and destination_load[2] == 5:
                destination_candidates.append(destination_load[1])
    summary = {
        "filename_occurrences": len(occurrences),
        "literal_backed_filename_load_call_candidates": len(targets),
        "candidate_call_targets_inside_main_image": internal_targets,
        "load_destination_argument_candidates": len(destination_candidates),
        "unique_load_destination_candidate_available": len(set(destination_candidates)) == 1,
        "runtime_file_load_confirmed": False,
    }
    return summary, targets, destination_candidates


def summarize_main_th2_low_load(data: bytes) -> dict:
    return _find_main_name_loader_targets(data, b"TH2.LOW")[0]


def summarize_low_set07(
    data: bytes,
    candidate_load_base: int | None = None,
    known_loader_targets: set[int] | None = None,
) -> dict:
    set07 = _all_occurrences(data, b"SET07.BIN")
    if not set07:
        return {
            "set07_name_occurrences": 0,
            "nearby_resource_filename_kinds": 0,
            "nearby_resource_filename_cluster_found": False,
            "candidate_load_base_available": candidate_load_base is not None,
            "set07_literal_backed_xref_count": 0,
            "candidate_base_self_reference_consistent": False,
            "set07_loader_call_candidates": 0,
            "set07_call_target_matches_main_loader": False,
            "set07_destination_argument_candidates": 0,
            "set07_loader_call_candidate_found": False,
            "direct_code_xref_status": "name_not_found",
            "overlay_execution_confirmed": False,
        }
    start = set07[0]
    # This is only a local data-cluster heuristic, not a proof of a string table.
    window_start = max(0, start - 0x2000)
    window_end = min(len(data), start + len(b"SET07.BIN") + 0x2000)
    window = data[window_start:window_end]
    nearby = sum(1 for name in LOW_NEARBY_RESOURCE_NAMES if name in window)
    xrefs = (
        _literal_references_to(data, candidate_load_base + start)
        if candidate_load_base is not None else []
    )
    referenced_resource_kinds = 0
    if candidate_load_base is not None:
        for name in (b"SET07.BIN",) + LOW_NEARBY_RESOURCE_NAMES:
            for pos in _all_occurrences(data, name):
                if _literal_references_to(data, candidate_load_base + pos):
                    referenced_resource_kinds += 1
                    break

    known_loader_targets = known_loader_targets or set()
    loader_calls = 0
    matching_loader_calls = 0
    destination_candidates = []
    for pos, reg in xrefs:
        if reg != 4 or pos + 8 > len(data):
            continue
        callee_load = movl_literal(data, pos + 2)
        if (
            callee_load is None
            or callee_load[2] != 2
            or int.from_bytes(data[pos + 4:pos + 6], "big") != 0x420B
            or int.from_bytes(data[pos + 6:pos + 8], "big") != 0x0009
        ):
            continue
        loader_calls += 1
        matching_loader_calls += int(callee_load[1] in known_loader_targets)
        destination_load = movl_literal(data, pos - 2)
        if destination_load is not None and destination_load[2] == 5:
            destination_candidates.append(destination_load[1])

    consistent = candidate_load_base is not None and bool(xrefs)
    return {
        "set07_name_occurrences": len(set07),
        "nearby_resource_filename_kinds": nearby,
        "nearby_resource_filename_cluster_found": nearby == len(LOW_NEARBY_RESOURCE_NAMES),
        "candidate_load_base_available": candidate_load_base is not None,
        "set07_literal_backed_xref_count": len(xrefs),
        "candidate_base_literal_backed_resource_name_kinds": referenced_resource_kinds,
        "candidate_base_self_reference_consistent": consistent,
        "set07_loader_call_candidates": loader_calls,
        "set07_call_target_matches_main_loader": matching_loader_calls > 0,
        "set07_destination_argument_candidates": len(destination_candidates),
        "set07_loader_call_candidate_found": matching_loader_calls > 0,
        "direct_code_xref_status": (
            "literal_backed_loader_call_matches_main_target"
            if matching_loader_calls else
            "literal_backed_reference_matches_candidate_load_base"
            if consistent else
            "unresolved_without_candidate_load_base"
            if candidate_load_base is None else
            "no_literal_backed_reference_at_candidate_load_base"
        ),
        "overlay_execution_confirmed": False,
    }

def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    low = payloads.get("TH2.LOW", b"")
    main_summary, set_targets = _find_set_table_loader_targets(main) if main else (
        {
            "set00_to_set06_contiguous_name_table": False,
            "set_name_count_in_table": 0,
            "literal_backed_table_reference_count": 0,
            "index10_filename_argument_call_candidates": 0,
            "candidate_call_targets_inside_main_image": 0,
            "resource_loader_candidate_found": False,
            "runtime_file_load_confirmed": False,
        },
        [],
    )
    low_load_summary, low_load_targets, destination_candidates = _find_main_name_loader_targets(main, b"TH2.LOW") if main else (
        {
            "filename_occurrences": 0,
            "literal_backed_filename_load_call_candidates": 0,
            "candidate_call_targets_inside_main_image": 0,
            "load_destination_argument_candidates": 0,
            "unique_load_destination_candidate_available": False,
            "runtime_file_load_confirmed": False,
        },
        [],
        [],
    )
    candidate_load_base = (
        destination_candidates[0] if len(set(destination_candidates)) == 1 else None
    )
    known_loader_targets = set(set_targets).union(low_load_targets)
    low_summary = summarize_low_set07(low, candidate_load_base, known_loader_targets)
    common_loader = bool(set(set_targets).intersection(low_load_targets))
    return {
        "schema_version": 1,
        "stage": "stage87_set_loader_callsite_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "main_executable_available": bool(main),
            "low_module_available": bool(low),
            "main_set_loader": main_summary,
            "main_th2_low_load": low_load_summary,
            "same_loader_target_used_for_th2_low_and_set_table": common_loader,
            "loader_target_comparison_possible": bool(set_targets and low_load_targets),
            "low_set07_loader": low_summary,
            "set07_runtime_role_confirmed": False,
            "runtime_pointer_registration_proven": False,
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
