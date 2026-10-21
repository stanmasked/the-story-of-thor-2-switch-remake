#!/usr/bin/env python3
"""Stage27: bounded audit of the nested-pointer helper's safe zero/clear arm.

Metadata-only output; original Saturn program offsets, binary bytes and game
assets are intentionally not exported.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage25_r4_provenance_probe import find_input_preservation_paths

# MOV #0,R4; MOV #31..35,R0; MOV.B R4,@(R0,R14); MOV #36,R0;
# BRA epilogue; delay slot MOV.W R4,@(R0,R14).
ZERO_ARM = (
    0xE400, 0xE01F, 0x0E44, 0xE020, 0x0E44, 0xE021, 0x0E44,
    0xE022, 0x0E44, 0xE023, 0x0E44, 0xE024, None, 0x0E45,
)
EPILOGUE = (0x7F04, 0x4F26, 0x6CF6, 0x6DF6, 0x000B, 0x6EF6)


def branch_target(pos: int, opcode: int) -> int | None:
    """BT/BF 8-bit signed, BRA 12-bit signed, using SH-2 PC+4."""
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


def check_zero_arm(data: bytes, entry: int) -> dict | None:
    """Verify three paths leading to zero arm, and delayed final word store."""
    if entry < 0 or entry & 1 or entry + 0x12A > len(data):
        return None
    if not (be16(data, entry) == 0x2FE6
            and be16(data, entry + 2) == 0x6E43
            and be16(data, entry + 14) == 0x04EE
            and be16(data, entry + 16) == 0x2448):
        return None
    zero = entry + 0x2E
    if any(be16(data, zero + i * 2) != w for i, w in enumerate(ZERO_ARM)
           if w is not None):
        return None
    null_branch = be16(data, entry + 0x12)
    secondary_branch = be16(data, entry + 0x1C)
    bf = be16(data, entry + 0x2C)
    if not (null_branch & 0xFF00 == 0x8900
            and secondary_branch & 0xFF00 == 0x8900
            and bf & 0xFF00 == 0x8B00):
        return None
    if not (branch_target(entry + 0x12, null_branch) == zero
            and branch_target(entry + 0x1C, secondary_branch) == zero
            and be16(data, entry + 0x2A) == 0x2008
            and branch_target(entry + 0x2C, bf) == entry + 0x68):
        return None
    bra_pos = zero + 24
    epilogue = branch_target(bra_pos, be16(data, bra_pos))
    if epilogue is None or epilogue < zero + len(ZERO_ARM) * 2:
        return None
    if epilogue + 2 * len(EPILOGUE) > len(data):
        return None
    if any(be16(data, epilogue + 2 * i) != word
           for i, word in enumerate(EPILOGUE)):
        return None
    return {
        "writes_zero_bytes_at_offsets": (31, 32, 33, 34, 35, 36, 37),
        "direct_null_branch": True,
        "secondary_bt_branch": True,
        "zero_field_fallthrough": True,
        "bra_delay_word_store": True,
    }


def summarize_helper_zero_clear(data: bytes) -> dict:
    paths = find_input_preservation_paths(data)
    entries = {path["target"] for path in paths}
    valid = [m for entry in entries if (m := check_zero_arm(data, entry)) is not None]
    return {
        "stage25_helper_targets_examined": len(entries),
        "helpers_with_complete_zero_clear_and_return_arm": len(valid),
        "first_condition": "nested_pointer_in_R4_is_zero" if valid else None,
        "secondary_condition": "alternate_BT_to_clear_arm" if valid else None,
        "third_condition": "zero_second_field_after_TST_R0_R0" if valid else None,
        "cleared_input_structure_byte_offsets":
            list(valid[0]["writes_zero_bytes_at_offsets"]) if valid else [],
        "clear_operations": {"byte_stores": 5, "word_stores": 1} if valid else None,
        "final_word_store_in_BRA_delay_slot": bool(valid),
        "return_restores": ["PR", "R12", "R13", "R14"] if valid else [],
        "interpretation": (
            "The helper's null or rejected-data path clears 7 bytes at offsets "
            "31..37 of the original input structure retained in R14. The last "
            "two bytes are cleared by MOV.W in the BRA delay slot before "
            "the shared return."
        ) if valid else "No fully verified helper zero-clear signature.",
        "limitations": [
            "A narrow static signature is not a complete control-flow graph.",
            "The alternate BT and zero-field cases are identified structurally; "
            "game semantics are unknown.",
            "The modified bytes are data-structure fields, not proven texture data.",
            "No live Saturn emulator trace or nested pointer contents were captured.",
            "No proprietary code bytes, file positions, or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1, "stage": "stage27_helper_zero_clear",
        "target_file": "0TH2.BIN",
        "analysis": summarize_helper_zero_clear(iso_file_payload(image)),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    rendered = json.dumps(analyze(args.image), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
