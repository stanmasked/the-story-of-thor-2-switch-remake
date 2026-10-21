#!/usr/bin/env python3
"""Stage37: distinguish signed function-table index from earlier type guards.

This deliberately does NOT claim to have located the runtime writer of
R14+126. Static candidate store pairs can operate on unrelated objects or
non-executable regions. Original Saturn data remains private.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import CODE_LOAD_BASE
from stage36_dispatch_index_audit import _pointer_table, match_indexed_dispatch

TYPE_FIELD = 30
INDEX_FIELD = 126
GATE_SCAN_BACK = 200
STORE_IMMEDIATE = 0xE07E  # MOV #126,R0


def zero_type_guard(data: bytes, start: int) -> bool:
    """MOV.B [R14+30] -> R2, TST R2,R2, BT; no index checked."""
    if start < 0 or start & 1 or start + 8 > len(data):
        return False
    return (
        tuple(be16(data, start + 2*i) for i in range(3))
        == (0xE01E, 0x02EC, 0x2228)
        and be16(data, start+6) & 0xFF00 == 0x8900
    )


def type_switch_1_to_6(data: bytes, start: int) -> bool:
    """Match explicit comparisons of type byte against 1,2,3,4,5,6.

    This is a lexical pattern, not proof of all control-flow destinations.
    """
    if start < 0 or start & 1 or start + 30 > len(data):
        return False
    if tuple(be16(data, start + i*2) for i in range(3)) != (
            0xE01E, 0x00EC, 0x8801):
        return False
    if be16(data, start+6) & 0xFF00 != 0x8D00:
        return False
    # There is a BT/S delay slot instruction before the remaining cases.
    cases = ((10, 2), (14, 3), (18, 4), (22, 5), (26, 6))
    return all(
        be16(data, start+offset) == 0x8800 | number
        and be16(data, start+offset+2) & 0xFF00 == 0x8900
        for offset, number in cases
    )


def indexed_word_store_pairs(data: bytes, base_register: int) -> list[int]:
    """Raw two-word MOV #126,R0; MOV.W Rm,@(R0,Rbase) candidates.

    Only opcode syntax is checked. The two instructions may be unreachable
    or Rbase may point to a different object than in a dispatch routine.
    """
    if not 0 <= base_register <= 15:
        raise ValueError("invalid SH-2 base register")
    opcode_masked = base_register << 8 | 0x0005
    return [
        p for p in range(0, len(data)-3, 2)
        if be16(data, p) == STORE_IMMEDIATE
        and be16(data, p+2) & 0xFF0F == opcode_masked
    ]


def dispatch_locations(data: bytes) -> list[dict]:
    table = _pointer_table(data)
    if table is None:
        return []
    anchors = (
        ("table_start", CODE_LOAD_BASE + table["table_start"]),
        ("selected_cell", CODE_LOAD_BASE + table["entry_cell"]),
    )
    matches = []
    for name, address in anchors:
        for position in range(12, len(data)-12, 2):
            match = match_indexed_dispatch(data, position, address)
            if match:
                matches.append({"anchor": name, "literal_pos": position,
                                "index_register": match["index_register"]})
    return matches


def inspect_local_guards(data: bytes) -> dict:
    matches = dispatch_locations(data)
    details = []
    for match in matches:
        p = match["literal_pos"]
        floor = max(0, p-GATE_SCAN_BACK)
        candidate_starts = range(floor, max(floor, p-18), 2)
        zero_guards = [q for q in candidate_starts if zero_type_guard(data, q)]
        switches = [q for q in candidate_starts if type_switch_1_to_6(data, q)]
        start = min(zero_guards + switches) if zero_guards or switches else p-10
        direct_stores = [
            q for q in indexed_word_store_pairs(data[start:p+12], 14)
        ]
        details.append({
            "anchor": match["anchor"],
            "zero_guards": len(zero_guards),
            "type_switches": len(switches),
            "direct_store_pairs_in_prefix": len(direct_stores),
        })
    return {
        "linked_signed_word_dispatches": len(details),
        "zero_tests_of_separate_type_byte_R14_plus_30": sum(
            item["zero_guards"] for item in details),
        "comparisons_of_type_byte_against_1_through_6": sum(
            item["type_switches"] for item in details),
        "dispatch_paths_with_type_byte_tests": sum(
            bool(item["zero_guards"] or item["type_switches"])
            for item in details),
        "dispatch_paths_with_direct_index_store_pairs_in_observed_prefix": sum(
            bool(item["direct_store_pairs_in_prefix"]) for item in details),
        "candidate_direct_word_store_pairs_R14_plus_126":
            len(indexed_word_store_pairs(data, 14)),
        "candidate_direct_word_store_pairs_R4_plus_126":
            len(indexed_word_store_pairs(data, 4)),
        "type_byte_field_offset": TYPE_FIELD if details else None,
        "index_word_field_offset": INDEX_FIELD if details else None,
        "type_guard_is_index_bounds_guard": False,
        "index_writer_identity_verified": False,
        "interpretation": (
            "The dispatching routines test a byte at R14+30 before they "
            "load the signed table index at R14+126. One zero test appears "
            "on the base-table path; the selected-cell path has both a "
            "zero test and a 1..6 type switch. The type comparisons do not "
            "establish bounds for the separate signed table index."
        ) if details else "No linked dispatch context verified.",
        "limitations": [
            "Candidate store pairs are a raw executable-word census, not known "
            "runtime writes to the same object.",
            "A syntactic absence of an immediate store is not a global "
            "proof that the index is unchanged or safely bounded.",
            "Control-flow paths, caller register aliases and earlier guards "
            "are not exhaustively reconstructed.",
            "No emulator trace, VDP1 command output or decoded sprite is available.",
            "No original code bytes, file positions or private assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1, "stage": "stage37_index_writer_type_guard",
        "target_file": "0TH2.BIN",
        "analysis": inspect_local_guards(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
