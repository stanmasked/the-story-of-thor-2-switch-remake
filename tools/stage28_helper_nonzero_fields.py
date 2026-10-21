#!/usr/bin/env python3
"""Stage28: verify the nonzero helper data path and conditional normalization.

Reads the private Sega Saturn ISO locally, emitting only aggregate structure
metadata. This is static SH-2 control-flow evidence, not graphics decoding.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage25_r4_provenance_probe import find_input_preservation_paths
from stage27_helper_zero_clear import check_zero_arm

NORMAL_PATH = {
    0x68: 0x63F2,  # MOV.L @R15,R3
    0x6A: 0x606E,  # EXTS.B R6,R0
    0x6C: 0x8803,  # CMP/EQ #3,R0
    0x70: 0x343C,  # ADD R3,R4 (BT/S delay slot)
    0x72: 0xE01F,  # non-3: first byte -> +31
    0x74: 0x6344,
    0x76: 0x0E34,
    0x78: 0x6344,
    0x7C: 0xE020,  # BRA delay slot: select +32
    0x7E: 0xE020,  # type 3: first byte -> +32
    0x80: 0x6344,
    0x82: 0x633B,
    0x84: 0x0E34,
    0x86: 0xE01F,  # type 3: second byte -> +31
    0x88: 0x6344,
    0x8A: 0x633B,
    0x8C: 0x0E34,
    0x8E: 0xE021,  # +33
    0x92: 0x6344,
    0x94: 0x0E34,
    0x96: 0xE022,  # +34
    0x98: 0x6344,
    0x9A: 0x0E34,
    0x9C: 0x6344,
    0x9E: 0xE023,  # +35
    0xA0: 0x4300,  # SHLL R3, doubles byte
    0xA2: 0x0E34,
    0xA4: 0x6240,
    0xA6: 0xE024,  # +36
    0xA8: 0x4200,  # SHLL R2, doubles last source byte
    0xAA: 0x0E25,  # word store to +36..+37
    0xAE: 0xE058,  # first sentinel at +88
    0xB0: 0x0CED,
    0xB2: 0x3C20,
    0xB6: 0x65C3,
    0xB8: 0xE01F,
    0xBC: 0x04EC,  # delay slot: read field +31
    0xBE: 0xE11F,
    0xC0: 0x31EC,
    0xC2: 0x65C3,
    0xC4: 0x2100,
    0xC6: 0xE020,
    0xCA: 0x04EC,  # delay slot: read field +32
    0xCC: 0xE120,
    0xCE: 0x31EC,
    0xD0: 0x2100,
    0xD2: 0xE05A,  # second sentinel at +90
    0xD6: 0x0CED,
    0xD8: 0x3C20,
    0xDC: 0x65C3,
    0xDE: 0xE021,
    0xE2: 0x04EC,
    0xE4: 0xE121,
    0xE6: 0x31EC,
    0xE8: 0x2100,
    0xEA: 0x65C3,
    0xEC: 0xE022,
    0xF0: 0x04EC,
    0xF2: 0xE122,
    0xF4: 0x31EC,
    0xF6: 0x65C3,
    0xF8: 0x2100,
    0xFA: 0xE023,
    0xFE: 0x04EC,
    0x100: 0xE123,
    0x102: 0x31EC,
    0x104: 0x2100,
    0x106: 0x65C3,
    0x108: 0xE024,
    0x10C: 0x04ED,  # last call reads word from +36
    0x10E: 0xE124,
    0x110: 0x31EC,
    0x112: 0x2101,  # last output is word
}
CALL_OFFSETS = (0xBA, 0xC8, 0xE0, 0xEE, 0xFC, 0x10A)


def pc_relative_movw_literal(data: bytes, position: int) -> tuple[int, int] | None:
    """MOV.W @(disp,PC),Rn uses instruction PC+4, without alignment."""
    if position < 0 or position & 1 or position + 2 > len(data):
        return None
    instruction = be16(data, position)
    if instruction & 0xF000 != 0x9000:
        return None
    slot = position + 4 + (instruction & 0xFF) * 2
    if slot + 2 > len(data):
        return None
    return slot, be16(data, slot)


def branch_destination(position: int, instruction: int) -> int | None:
    """SH-2 conditional 8-bit or BRA 12-bit signed PC-relative target."""
    if position < 0 or position & 1:
        return None
    if instruction & 0xF000 == 0xA000:
        displacement = instruction & 0xFFF
        if displacement & 0x800:
            displacement -= 0x1000
    elif instruction & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00):
        displacement = instruction & 0xFF
        if displacement & 0x80:
            displacement -= 0x100
    else:
        return None
    return position + 4 + displacement * 2


def verify_nonzero_fields(data: bytes, entry: int) -> dict | None:
    """Validate both byte-order paths, doubled fields and sentinel gates."""
    if entry < 0 or entry & 1 or entry + 0x1D0 > len(data):
        return None
    if check_zero_arm(data, entry) is None:
        return None
    if any(be16(data, entry + delta) != opcode
           for delta, opcode in NORMAL_PATH.items()):
        return None

    checks = (
        (0x6E, 0x8D00, 0x7E),  # BT/S if EXTS.B R6 == 3, ADD in delay slot
        (0x7A, 0xA000, 0x8C),  # non-3 skips special byte ordering
        (0xB4, 0x8900, 0xD2),  # gate first two conversion calls
        (0xDA, 0x8900, 0x114),  # gate remaining four conversion calls
    )
    for relative, opcode_class, destination in checks:
        opcode = be16(data, entry + relative)
        mask = 0xF000 if opcode_class == 0xA000 else 0xFF00
        if (opcode & mask != opcode_class
                or branch_destination(entry + relative, opcode) != entry + destination):
            return None

    if any(be16(data, entry + relative) != 0x4D0B for relative in CALL_OFFSETS):
        return None  # six JSR @R13, all with independently checked delay slots

    first = pc_relative_movw_literal(data, entry + 0xAC)
    second = pc_relative_movw_literal(data, entry + 0xD4)
    if (first is None or second is None
            or first[0] != second[0] or first[1] != 256):
        return None
    if be16(data, entry + 0xAC) & 0xFF00 != 0x9200:
        return None
    if be16(data, entry + 0xD4) & 0xFF00 != 0x9200:
        return None

    return {
        "type_three_first_two_fields": [32, 31],
        "other_types_first_two_fields": [31, 32],
        "direct_source_field_byte_writes": [31, 32, 33, 34, 35],
        "last_source_word_field": [36, 37],
        "scaled_fields": [35, 36],
        "conversion_call_counts_by_group": [2, 4],
        "gate_input_word_offsets": [88, 90],
        "gate_sentinel": 256,
        "all_conversion_calls_use_R13": True,
    }


def summarize_nonzero_fields(data: bytes) -> dict:
    helper_entries = {p.get("target", p.get("helper_target"))
                      for p in find_input_preservation_paths(data)}
    valid = [m for entry in helper_entries
             if (m := verify_nonzero_fields(data, entry)) is not None]
    return {
        "stage25_helper_targets_examined": len(helper_entries),
        "complete_nonzero_field_processing_matches": len(valid),
        "first_two_field_write_order_for_type_three":
            valid[0]["type_three_first_two_fields"] if valid else [],
        "first_two_field_write_order_for_other_types":
            valid[0]["other_types_first_two_fields"] if valid else [],
        "conditionally_processed_field_groups": [
            {"fields": [31, 32], "source_word_offset": 88, "sentinel": 256,
             "conversion_jsr_sites": 2},
            {"fields": [33, 34, 35, 36], "source_word_offset": 90,
             "sentinel": 256, "conversion_jsr_sites": 4},
        ] if valid else [],
        "source_byte_before_shift_doubled_for_field_35": bool(valid),
        "source_byte_before_shift_doubled_for_word_36_37": bool(valid),
        "all_conversion_call_sites_use_same_register_R13": bool(valid),
        "interpretation": (
            "The nonzero helper path copies source bytes to fields +31..+34, "
            "switches the order of +31/+32 when the signed type byte is 3, "
            "and shifts source values left for byte +35 and word +36..+37. "
            "Two separate 16-bit fields at +88 and +90 are compared with "
            "sentinel 256 to skip conversion groups (2 or 4 indirect calls)."
        ) if valid else "No complete nonzero helper signature was verified.",
        "limitations": [
            "Fields are relative to the input structure, not to the ISO file.",
            "Conversion-call semantics and the identity of the nested source data are unknown.",
            "The source pointer uses an additional runtime offset from the stack.",
            "Branch consistency is checked statically, not through a Saturn emulator.",
            "No source binary offsets, executable bytes or copyrighted assets are exported.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage28_helper_nonzero_fields",
        "target_file": "0TH2.BIN",
        "analysis": summarize_nonzero_fields(iso_file_payload(image)),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    rendered = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
