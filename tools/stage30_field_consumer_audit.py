#!/usr/bin/env python3
"""Stage30: bounded SH-2 consumer audit for candidate structure fields.

The original game image stays private. Only aggregate metadata and semantic
in-memory field offsets are emitted, never binary positions or game assets.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload

FOUR_BYTE_FIELDS = (31, 32, 33, 34)
ALL_FIELDS = (31, 32, 33, 34, 35, 36)
SCAN_WINDOW = 96


def is_branch(opcode: int) -> bool:
    return (opcode & 0xF000 in (0xA000, 0xB000)
            or opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00)
            or opcode & 0xF0FF in (0x400B, 0x402B)
            or opcode in (0x000B, 0x002B))


def field_read(data: bytes, position: int):
    """Recognize MOV #displacement,R0 + MOV.B/W @(R0,R4),Rn."""
    if position < 0 or position & 1 or position + 4 > len(data):
        return None
    op, following = be16(data, position), be16(data, position + 2)
    field = op & 0xFF
    if op & 0xFF00 != 0xE000 or field not in ALL_FIELDS:
        return None
    width = {0x004C: 1, 0x004D: 2}.get(following & 0xF0FF)
    if width is None:
        return None
    return {"field": field, "width": width, "dest": (following >> 8) & 15,
            "instruction_position": position}


def find_consumer_groups(data: bytes) -> list[dict]:
    """Find ordered branch-free four-field reads, with optional +35/+36.

    Lexical SH-2 candidates are not proof of the same runtime pointer identity
    or that the identified sequences actually execute in gameplay.
    """
    found = []
    for start in range(0, len(data) - 4, 2):
        first = field_read(data, start)
        if first is None or first["field"] != 31 or first["width"] != 1:
            continue
        fields = [first]
        for pos in range(start + 4, min(len(data) - 3, start + SCAN_WINDOW), 2):
            if is_branch(be16(data, pos)):
                break
            read = field_read(data, pos)
            if read is not None and read["field"] == fields[-1]["field"] + 1:
                if read["field"] == 36 and read["width"] != 2:
                    continue
                if read["field"] < 36 and read["width"] != 1:
                    continue
                fields.append(read)
                if len(fields) == 6:
                    break
        if len(fields) < 4:
            continue
        first_four = fields[:4]
        adds_r5_to_all_four = all(any(
            be16(data, read["instruction_position"] + delta)
            == (0x300C | (read["dest"] << 8) | (5 << 4))
            for delta in (4, 6)
            if read["instruction_position"] + delta + 2 <= len(data))
            for read in first_four)
        r6_to_r0_then_stack_words = all(
            read["dest"] == 0
            and be16(data, read["instruction_position"] + 4) == 0x306C
            and be16(data, read["instruction_position"] + 6) & 0xFFF0 == 0x81F0
            for read in first_four)
        found.append({"reads": fields, "adds_r5_to_all_four": adds_r5_to_all_four,
                      "r6_to_r0_then_stack_words": r6_to_r0_then_stack_words})
    return found


def summarize_consumers(data: bytes) -> dict:
    groups = find_consumer_groups(data)
    extended = [g for g in groups if len(g["reads"]) == 6
                and g["reads"][4]["field"] == 35
                and g["reads"][5]["field"] == 36]
    return {
        "candidate_four_field_consumer_groups": len(groups),
        "groups_reading_all_seven_bytes": len(extended),
        "common_read_fields": list(FOUR_BYTE_FIELDS) if groups else [],
        "extended_reader_fields": [31, 32, 33, 34, 35, 36, 37] if extended else [],
        "extended_final_field_width_bytes": 2 if extended else None,
        "groups_adding_r5_to_all_four_results": sum(g["adds_r5_to_all_four"] for g in groups),
        "groups_adding_r6_and_storing_four_stack_words":
            sum(g["r6_to_r0_then_stack_words"] for g in groups),
        "interpretation": (
            "Three independent lexical read sequences use R4-relative byte fields "
            "+31..+34; one extends to +35 and a word at +36..+37. "
            "The R5 and R6 arithmetic variants demonstrate use of the fields, "
            "but not runtime structure identity or direct VDP1 command emission."
        ) if groups else "No supported four-field read patterns found.",
        "limitations": [
            "Fields are relative to an in-memory pointer, not ISO positions.",
            "No control-flow reachability or pointer alias/type identity is established.",
            "A bounded lexical opcode scan is not a complete SH-2 disassembler.",
            "Linkage to VDP1 command output, sprite decoding and P0-P3 is unproven.",
            "No original executable bytes or game assets are exported.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version": 1, "stage": "stage30_field_consumers",
            "target_file": "0TH2.BIN",
            "analysis": summarize_consumers(iso_file_payload(image))}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    result = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
