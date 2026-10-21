#!/usr/bin/env python3
"""Stage26: inspect R4 clobber and return-register contract of the VDP1 helper.

Uses only narrow, independently verifiable SH-2 opcode predicates. Reports
aggregate evidence without original program offsets, instruction bytes or
other copyrighted game assets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage25_r4_provenance_probe import find_input_preservation_paths

# Stack saves, R4->R14, PC-relative word literal and R4 nested-pointer load.
ENTRY_PREFIX = (
    0x2FE6,  # MOV.L R14,@-R15
    0x6E43,  # MOV R4,R14
    None,    # MOV.W @(disp,PC),R0
    0x2FD6,  # MOV.L R13,@-R15
    0x2FC6,  # MOV.L R12,@-R15
    0x4F22,  # STS.L PR,@-R15
    0x7FFC,  # ADD #-4,R15
    0x04EE,  # MOV.L @(R0,R14),R4
    0x2448,  # TST R4,R4
    None,    # BT to zero-value handling
)

RETURN_SUFFIX = (
    0x7F04,  # ADD #4,R15
    0x4F26,  # LDS.L @R15+,PR
    0x6CF6,  # MOV.L @R15+,R12
    0x6DF6,  # MOV.L @R15+,R13
    0x000B,  # RTS
    0x6EF6,  # MOV.L @R15+,R14 -- RTS delay slot
)
EXPECTED_FIELD_DISPLACEMENT = 160


def movw_pc_literal_position(pos: int, opcode: int, data_size: int) -> int | None:
    """SH-2 MOV.W @(disp,PC),Rn points to PC+4+disp*2."""
    if pos < 0 or pos & 1 or opcode & 0xF000 != 0x9000:
        return None
    target = pos + 4 + (opcode & 0xFF) * 2
    return target if target + 2 <= data_size else None


def bt_branch_target(pos: int, opcode: int) -> int | None:
    if pos < 0 or pos & 1 or opcode & 0xFF00 != 0x8900:
        return None
    displacement = opcode & 0xFF
    if displacement & 0x80:
        displacement -= 0x100
    return pos + 4 + displacement * 2


def match_entry(data: bytes, entry: int) -> dict | None:
    """Strict prologue, unconditional R4 write and zero-pointer branch."""
    if entry < 0 or entry & 1 or entry + len(ENTRY_PREFIX) * 2 > len(data):
        return None
    if any(expected is not None and be16(data, entry + i * 2) != expected
           for i, expected in enumerate(ENTRY_PREFIX)):
        return None
    literal_load_pos = entry + 4
    load_word = be16(data, literal_load_pos)
    if load_word & 0xFF00 != 0x9000:  # must load the R0 offset
        return None
    literal_pos = movw_pc_literal_position(literal_load_pos, load_word, len(data))
    if literal_pos is None or be16(data, literal_pos) != EXPECTED_FIELD_DISPLACEMENT:
        return None
    guard_pos = entry + 18
    zero_path = bt_branch_target(guard_pos, be16(data, guard_pos))
    if zero_path is None or not (entry + 20 <= zero_path < min(entry + 144, len(data))):
        return None
    return {
        "entry": entry,
        "zero_path": zero_path,
        "zero_path_sets_r4_zero": be16(data, zero_path) == 0xE400,
        "first_r4_write_precedes_first_conditional_branch": True,
    }


def find_return_sequences(data: bytes, entry: int, max_span: int = 512) -> list[int]:
    """Match balanced epilogue including the SH-2 RTS delay-slot restore."""
    start = entry + len(ENTRY_PREFIX) * 2
    end = min(len(data) - len(RETURN_SUFFIX) * 2, entry + max_span)
    return [
        pos for pos in range(start, end + 1, 2)
        if all(be16(data, pos + 2 * i) == opcode
               for i, opcode in enumerate(RETURN_SUFFIX))
    ]


def inspect_helper(data: bytes, entry: int) -> dict | None:
    matched = match_entry(data, entry)
    if matched is None:
        return None
    returns = find_return_sequences(data, entry)
    if not returns:
        return None
    matched["epilogues"] = returns
    return matched


def summarize_helper_registers(data: bytes) -> dict:
    paths = find_input_preservation_paths(data)
    helpers = {
        path["target"]: inspect_helper(data, path["target"])
        for path in paths
    }
    valid = [helper for helper in helpers.values() if helper is not None]
    return {
        "stage25_helper_calls_examined": len({path["call"] for path in paths}),
        "helpers_with_complete_entry_and_return_signature": len(valid),
        "helpers_loading_r4_from_input_nested_pointer": len(valid),
        "nested_pointer_field_offset_bytes": EXPECTED_FIELD_DISPLACEMENT if valid else None,
        "helpers_testing_nested_pointer_for_zero": len(valid),
        "helpers_with_explicit_zero_case_r4_assignment": sum(
            helper["zero_path_sets_r4_zero"] for helper in valid
        ),
        "helpers_with_unconditional_r4_write_before_first_branch": sum(
            helper["first_r4_write_precedes_first_conditional_branch"] for helper in valid
        ),
        "matched_epilogues_restoring_r12_r13_r14_and_pr": sum(
            len(helper["epilogues"]) for helper in valid
        ),
        "r4_restored_by_matched_epilogue": False if valid else None,
        "interpretation": (
            "The helper copies its input R4 to callee-saved R14, loads a "
            "32-bit nested pointer from memory[R14+160] into R4 before its "
            "first conditional branch and tests it against zero. The "
            "identified return sequence restores PR and R12/R13/R14, not R4. "
            "Therefore callers must not assume that R4 still contains the "
            "original pointer after this helper returns."
        ) if valid else "The strict helper signature was not verified.",
        "limitations": [
            "The identity and runtime contents of the nested pointer are unknown.",
            "A register overwrite is confirmed, not that the numeric value differs on every execution.",
            "The matched epilogue is not a whole-program proof that there are no other returns.",
            "Other nested calls may also change R4, and real execution paths were not traced.",
            "No program offsets, original machine-code bytes, textures, palettes or audio are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage26_vdp1_helper_r4_nested_pointer",
        "target_file": "0TH2.BIN",
        "analysis": summarize_helper_registers(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
