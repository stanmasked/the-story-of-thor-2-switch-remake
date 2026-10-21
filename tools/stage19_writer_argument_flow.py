#!/usr/bin/env python3
"""Stage19: trace the count argument through a guarded SH-2 VDP1 descriptor write.

Reports aggregate evidence only; no offsets, source bytes, or game assets.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import (
    be16, find_guarded_writer_blocks, conditional_branch_target, iso_file_payload,
)

CMP_EQ_IMM_ONE_R0 = 0x8801
BF_S_OPCODE = 0x8F00
EXTU_W_R5_R4 = 0x645D
MOV_R4_R2 = 0x6243
SHLR_R2 = 0x4221
MOV_W_R2_AT_R3 = 0x2321


def clobbers_count_register(opcode: int) -> bool:
    """Conservatively reject common SH-2 R2 writes in the count calculation."""
    top = opcode & 0xF000
    n = (opcode >> 8) & 0xF
    if top in (0x6000, 0x7000, 0x9000, 0xD000, 0xE000) and n == 2:
        return True
    if top == 0x4000 and n == 2 and opcode != SHLR_R2:
        return True
    return False


def producer_argument_patterns(data: bytes) -> list[dict]:
    result = []
    for block in find_guarded_writer_blocks(data):
        start, end = block["start"], block["exit"]
        if start < 6:
            continue
        cmp_one = be16(data, start - 6) == CMP_EQ_IMM_ONE_R0
        branch = be16(data, start - 4)
        skips = (
            branch & 0xFF00 == BF_S_OPCODE
            and conditional_branch_target(start - 4, branch) == end
        )
        extu_delay_slot = be16(data, start - 2) == EXTU_W_R5_R4
        section = [be16(data, offset) for offset in range(start + 10, end - 6, 2)]
        count_ready = False
        for first, word in enumerate(section):
            if word != MOV_R4_R2:
                continue
            for last in range(first + 1, len(section)):
                if section[last] != MOV_W_R2_AT_R3:
                    continue
                window = section[first + 1:last]
                if (
                    window.count(SHLR_R2) == 3
                    and not any(clobbers_count_register(item) for item in window)
                ):
                    count_ready = True
                    break
            if count_ready:
                break
        result.append({
            "cmp_equal_one": cmp_one,
            "conditional_skip_on_not_equal": skips,
            "extu_w_r5_to_r4_in_delay_slot": extu_delay_slot,
            "r4_to_r2_three_right_shifts_then_store": count_ready,
            "complete": cmp_one and skips and extu_delay_slot and count_ready,
        })
    return result


def summarize_argument_flow(data: bytes) -> dict:
    matches = producer_argument_patterns(data)
    complete = sum(item["complete"] for item in matches)
    return {
        "writer_blocks_examined": len(matches),
        "blocks_with_cmp_equal_one_and_common_exit": sum(
            item["cmp_equal_one"] and item["conditional_skip_on_not_equal"]
            for item in matches
        ),
        "blocks_with_zero_extension_in_bf_s_delay_slot": sum(
            item["extu_w_r5_to_r4_in_delay_slot"] for item in matches
        ),
        "blocks_with_three_right_shifts_before_count_store": sum(
            item["r4_to_r2_three_right_shifts_then_store"] for item in matches
        ),
        "complete_argument_flow_matches": complete,
        "provisional_count_formula": "(R5 & 0xFFFF) >> 3" if complete else None,
        "provisional_count_mathematical_range": [0, 8191] if complete else None,
        "writer_enabled_condition": "R0 == 1 and count < 512" if complete else None,
        "interpretation": (
            "The pre-guard CMP/EQ #1,R0 and BF/S skip the descriptor stores "
            "unless R0 equals one. The BF/S delay slot executes EXTU.W R5,R4. "
            "Inside the writer, MOV R4,R2 followed by three SHLR R2 operations "
            "and a word store yields (R5 & 0xFFFF) >> 3. This arithmetic range "
            "is not an observed range of runtime input values."
        ),
        "limitations": [
            "This is a bounded opcode-pattern probe, not complete SH-2 dataflow.",
            "Actual runtime R5 values and parent function entry are unknown.",
            "Relationship between descriptor count and uploader budget remains unproven.",
            "No original offsets, source bytes, textures, or audio are exported.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage19_vdp1_writer_argument_flow",
        "target_file": "0TH2.BIN",
        "analysis": summarize_argument_flow(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(analyze(args.image), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
