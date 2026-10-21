#!/usr/bin/env python3
"""Stage31: bounded SH-2 entry/flag audit for prepared-field consumers.

The original Saturn ISO is processed privately. Reports aggregate metadata
only; lexical prologue matches do not prove runtime pointer identity.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage30_field_consumer_audit import find_consumer_groups, is_branch

PUSH_R14 = 0x2FE6
WORD_FROM_R4_PLUS_16 = 0x8548  # MOV.W @(8,R4),R0, displacement unit=2
EXPECTED_SAVED = ((14, 13, 12, 11, 9), (14, 13, 12, 11, 10, 9, 8))


def branch_destination(pos: int, opcode: int) -> int | None:
    if pos < 0 or pos & 1:
        return None
    if opcode & 0xF000 == 0xA000:
        displacement = opcode & 0xFFF
        if displacement & 0x800:
            displacement -= 0x1000
    elif opcode & 0xFF00 in (0x8900, 0x8B00):
        displacement = opcode & 0xFF
        if displacement & 0x80:
            displacement -= 0x100
    else:
        return None
    return pos + 4 + displacement * 2


def known_direct_r4_assignment(opcode: int) -> bool:
    """Subset of R4 writes only; false cannot prove R4 is unchanged."""
    n = (opcode >> 8) & 15
    if opcode & 0xF000 in (0x7000, 0x9000, 0xD000, 0xE000) and n == 4:
        return True
    return opcode & 0xF00F == 0x6003 and n == 4


def _saved_registers(data: bytes, entry: int, first_read: int) -> tuple[int, ...]:
    return tuple(
        (be16(data, pos) >> 4) & 15
        for pos in range(entry, min(first_read, entry + 24), 2)
        if be16(data, pos) & 0xFF0F == 0x2F06
    )


def candidate_prologue(data: bytes, first_read: int, max_back: int = 180) -> dict | None:
    """Choose nearest known R14-saving entry within a bounded window."""
    if first_read < 2 or first_read > len(data) or first_read & 1:
        return None
    for pos in range(first_read - 2, max(-2, first_read - max_back - 2), -2):
        if be16(data, pos) == PUSH_R14:
            regs = _saved_registers(data, pos, first_read)
            if regs in EXPECTED_SAVED:
                return {"entry": pos, "saved_registers": regs}
    return None


def field16_before_group(data: bytes, entry: int, first_read: int) -> bool:
    return any(be16(data, pos) == WORD_FROM_R4_PLUS_16
               for pos in range(max(entry, first_read - 12), first_read, 2))


def gate_flag_plus_7(data: bytes, entry: int, first_read: int) -> bool:
    """Bit 0 clear -> BT skips BRA and proceeds toward +31..+34 reads."""
    for pos in range(entry, first_read - 10, 2):
        if [be16(data, pos + i * 2) for i in range(3)] != [0x8447, 0xC801, 0x8901]:
            continue
        bra_pos = pos + 6
        bra = be16(data, bra_pos)
        if (bra & 0xF000 == 0xA000
                and branch_destination(pos + 4, 0x8901) == pos + 10
                and branch_destination(bra_pos, bra) > first_read
                and be16(data, pos + 8) == 0x6053):
            return True
    return False


def flag_plus_6_test(data: bytes, entry: int, first_read: int) -> bool:
    """Only a preliminary bit-2 test, not a proven entire-path gate."""
    for pos in range(entry, first_read - 6, 2):
        if be16(data, pos) == 0x8446 and be16(data, pos + 2) == 0xC804:
            branch = be16(data, pos + 4)
            if branch & 0xFF00 == 0x8B00 and branch_destination(pos + 4, branch) is not None:
                return True
    return False


def inspect_consumer_entries(data: bytes) -> list[dict]:
    entries = []
    for group in find_consumer_groups(data):
        start = group["reads"][0]["instruction_position"]
        prologue = candidate_prologue(data, start)
        if prologue is None or not field16_before_group(data, prologue["entry"], start):
            continue
        entry = prologue["entry"]
        branches = sum(is_branch(be16(data, p)) for p in range(entry, start, 2))
        writes = sum(known_direct_r4_assignment(be16(data, p))
                     for p in range(entry, start, 2))
        entries.append({
            "start": start,
            "saved_count": len(prologue["saved_registers"]),
            "branch_count": branches,
            "r4_writes_recognized": writes,
            "gate_plus_7": gate_flag_plus_7(data, entry, start),
            "test_plus_6": flag_plus_6_test(data, entry, start),
            "extended": len(group["reads"]) == 6,
        })
    return entries


def summarize_entry_guards(data: bytes) -> dict:
    groups = find_consumer_groups(data)
    entries = inspect_consumer_entries(data)
    return {
        "stage30_consumer_groups": len(groups),
        "consumers_with_matched_prologue_and_r4_word16_read": len(entries),
        "saved_register_counts_by_consumer": [e["saved_count"] for e in entries],
        "pre_read_branch_counts": [e["branch_count"] for e in entries],
        "consumers_with_confirmed_r4_plus_7_bit0_clear_gate": sum(e["gate_plus_7"] for e in entries),
        "consumers_with_preliminary_r4_plus_6_bit2_test": sum(e["test_plus_6"] for e in entries),
        "consumers_with_no_recognized_branch_before_fields": sum(
            not e["branch_count"] for e in entries),
        "consumers_with_recognized_direct_r4_assignment_in_prefix": sum(
            bool(e["r4_writes_recognized"]) for e in entries),
        "extended_reader_has_straight_line_prefix": any(
            e["extended"] and not e["branch_count"] for e in entries),
        "shared_additional_word_field": "R4+16" if entries else None,
        "interpretation": (
            "Three candidate reader procedures share an additional word load "
            "from R4+16. One is gated by bit0 of R4+7 being clear; another "
            "tests bit2 of R4+6 earlier. The full seven-byte reader has no "
            "recognized branch between its prologue and field reads."
        ) if entries else "No matched consumer-entry signatures.",
        "limitations": [
            "Opcode classifiers for R4 assignments and control flow are incomplete.",
            "Recognized prologues do not prove callers pass an identical object type.",
            "Only the R4+7 bit0 gate has a verified local reader-entry meaning.",
            "No confirmed data flow into VDP1 descriptors or resources P0-P3.",
            "No original executable positions, raw bytes or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version": 1, "stage": "stage31_consumer_entry_guards",
            "target_file": "0TH2.BIN",
            "analysis": summarize_entry_guards(iso_file_payload(image))}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    result = json.dumps(analyze(args.image), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
