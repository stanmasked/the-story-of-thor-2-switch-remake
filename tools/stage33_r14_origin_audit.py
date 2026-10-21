#!/usr/bin/env python3
"""Stage33: classify local R14/R4 origins at verified Stage32 call sites.

Conservative *lexical* provenance: an earlier MOV R4,R14 does not establish
dynamic reachability, callee preservation, or object type equivalence.
The original Saturn executable is processed locally; no proprietary bytes or
actual program positions are emitted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage32_field_consumer_callers import (
    matched_consumer_entries, direct_call_sites, indirect_call_sites,
)

PUSH_R14 = 0x2FE6
COPY_ENTRY_R4_TO_R14 = 0x6E43
RESTORE_R14 = 0x6EF6
SAVE_PR = 0x4F22
ALLOCATE_WORD = 0x7FFC
WRITE_R4_AT_SP = 0x2F42
DELAY_R14_TO_R4 = 0x64E3
DELAY_R5_TWO = 0xE502


def r14_direct_write(opcode: int) -> bool:
    """Recognize selected explicit writes to R14, not all SH-2 instructions."""
    dest = (opcode >> 8) & 0xF
    if opcode == RESTORE_R14:
        return True
    if opcode & 0xF00F in (0x6003, 0x6006) and dest == 14:
        return True
    if opcode & 0xF000 in (0x7000, 0x9000, 0xD000, 0xE000) and dest == 14:
        return True
    return False


def preceding_r14_save(data: bytes, call: int, max_back: int = 256) -> dict | None:
    """Match the *nearest* R4->R14 assignment with its own PUSH R14.

    Never silently fall back to a prior function when the closest save/copy
    is incomplete. A special existing-R4 wrapper is a hard entry boundary.
    """
    if call < 2 or call > len(data) or call & 1:
        return None
    if (call >= 8
            and be16(data, call - 8) == SAVE_PR
            and be16(data, call - 4) == ALLOCATE_WORD
            and be16(data, call - 2) == WRITE_R4_AT_SP):
        return None
    low = max(0, call - max_back)
    for pos in range(call - 2, low - 1, -2):
        opcode = be16(data, pos)
        if opcode == COPY_ENTRY_R4_TO_R14:
            pushes = [
                start for start in range(max(low, pos - 12), pos, 2)
                if be16(data, start) == PUSH_R14
            ]
            if not pushes:
                return None
            begin = pushes[-1]
            writes = sum(
                r14_direct_write(be16(data, p))
                or be16(data, p) == PUSH_R14
                for p in range(pos + 2, call, 2)
            )
            return {"prologue": begin, "initialization": pos,
                    "intervening_recognized_r14_writes": writes}
        if opcode == PUSH_R14:
            # A new prologue cannot borrow an older copy from another routine.
            return None
    return None

def wrapper_uses_incoming_r4(data: bytes, literal_load: int, call: int) -> bool:
    """Special wrapper does not assign to R4 before an indirect JSR.

    It saves R4 to reserved stack space and sets R5=2 in JSR delay slot.
    This is a narrow exact pattern; incoming R4's *caller* origin is unknown.
    """
    if literal_load < 2 or call != literal_load + 6 or call + 4 > len(data):
        return False
    if (be16(data, literal_load - 2) != SAVE_PR
            or be16(data, literal_load + 2) != ALLOCATE_WORD
            or be16(data, literal_load + 4) != WRITE_R4_AT_SP
            or be16(data, call + 2) != DELAY_R5_TWO):
        return False
    instruction = be16(data, literal_load)
    reg = (instruction >> 8) & 15
    return (instruction & 0xF000 == 0xD000
            and be16(data, call) == 0x400B | reg << 8)


def summarize_origins(data: bytes) -> dict:
    entries = matched_consumer_entries(data)
    candidates = []
    for entry in entries:
        for direct in direct_call_sites(data, entry["entry"]):
            candidates.append({"kind": "bsr", "call": direct["position"],
                               "r14_passed": direct["delay_r14_to_r4"]})
        for indirect in indirect_call_sites(data, entry["entry"]):
            candidates.append({
                "kind": "jsr", "call": indirect["jsr_pos"],
                "r14_passed": indirect["delay_r14_to_r4"],
                "wrapper": wrapper_uses_incoming_r4(
                    data, indirect["load_pos"], indirect["jsr_pos"]),
                "r5_two": indirect["delay_r5_two"],
            })

    passed = [c for c in candidates if c["r14_passed"]]
    origins = [preceding_r14_save(data, c["call"]) for c in passed]
    clean = [x for x in origins if x is not None
             and x["intervening_recognized_r14_writes"] == 0]
    competing = [x for x in origins if x is not None
                 and x["intervening_recognized_r14_writes"] > 0]
    wrappers = [c for c in candidates if c.get("wrapper")]
    return {
        "stage32_caller_sites_examined": len(candidates),
        "calls_passing_r14_as_r4_in_delay_slot": len(passed),
        "r14_callers_with_local_push_and_input_r4_copy": sum(
            x is not None for x in origins),
        "r14_callers_without_local_copy_in_bounded_window": sum(
            x is None for x in origins),
        "local_copies_without_recognized_intervening_r14_writes": len(clean),
        "local_copies_with_competing_lexical_r14_writes": len(competing),
        "indirect_wrappers_saving_existing_r4_and_setting_r5_two": len(wrappers),
        "wrapper_r4_source": "incoming_R4_untraced" if wrappers else None,
        "interpretation": (
            "Most R14 arguments have a preceding input-R4-to-R14 prologue. "
            "Some contain competing lexical R14 restores on possibly separate "
            "control-flow paths; these cannot establish R14 at the call. "
            "The exceptional indirect wrapper stores its incoming R4 at SP "
            "and sets R5 to 2, without a preceding R4 assignment in that "
            "verified short sequence."
        ),
        "limitations": [
            "A lexical R14 copy is not proof of the executed path or callee preservation.",
            "R14 restore opcodes in alternate branches may be unreachable at a caller.",
            "Indirect function calls between the prologue and call could alter registers.",
            "One direct caller has no nearby verified R14 origin; the wrapper's R4 "
            "is only traced to its own entry, not the outer caller.",
            "No alias equality between producer and consumers, VDP1 destination, "
            "or resource container correspondence has been proved.",
            "No executable offsets, source game bytes or copyrighted assets are output.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage33_r14_caller_provenance",
        "target_file": "0TH2.BIN",
        "analysis": summarize_origins(iso_file_payload(image)),
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
        print(rendered)


if __name__ == "__main__":
    main()
