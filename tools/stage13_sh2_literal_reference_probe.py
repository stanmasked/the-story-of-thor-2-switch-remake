#!/usr/bin/env python3
"""Stage13: resolve SH-2 MOV.L PC-relative literal references to hardware constants.

This scans instruction-shaped 16-bit words but is not a complete disassembler.
It reports counts only and never exports instruction offsets or source bytes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage03_index_tables import MAX_PROBE_BYTES

HARDWARE_ADDRESSES = {
    "VDP1_VRAM_BASE": 0x25C00000,
    "VDP1_FRAMEBUFFER_BASE": 0x25C80000,
    "VDP1_REGISTER_BASE": 0x25D00000,
    "VDP1_FBCR": 0x25D00002,
    "VDP1_PTMR": 0x25D00004,
    "VDP1_EWDR": 0x25D00006,
    "VDP1_EWLR": 0x25D00008,
    "VDP1_EWRR": 0x25D0000A,
    "VDP1_ENDR": 0x25D0000C,
    "VDP1_EDSR": 0x25D00010,
    "VDP1_LOPR": 0x25D00012,
    "VDP1_COPR": 0x25D00014,
    "VDP1_MODR": 0x25D00016,
    "VDP2_VRAM_BASE": 0x25E00000,
    "VDP2_CRAM_BASE": 0x25F00000,
    "VDP2_REGISTER_BASE": 0x25F80000,
    "VDP2_TVSTAT": 0x25F80004,
    "VDP2_CYCA0L": 0x25F80010,
}


def be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def be32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def sh2_movl_pc_literal_target(instruction_offset: int, opcode: int, data_size: int) -> int | None:
    """Resolve MOV.L @(disp,PC),Rn using SH-2's aligned PC-relative rule.

    For this instruction, the longword effective address is
    ((PC + 4) & ~3) + disp*4, where PC is the current instruction address.
    The returned target is a file-relative candidate only when it fits in data.
    """
    if instruction_offset < 0 or instruction_offset % 2 or instruction_offset + 2 > data_size:
        return None
    if opcode & 0xF000 != 0xD000:
        return None
    target = ((instruction_offset + 4) & ~3) + (opcode & 0x00FF) * 4
    if target < 0 or target + 4 > data_size:
        return None
    return target


def scan_sh2_literal_references(data: bytes) -> dict:
    """Count hardware address values reached by MOV.L PC-relative candidates."""
    instruction_candidates = 0
    valid_literal_targets = 0
    refs = {
        name: {"instruction_offsets": set(), "literal_offsets": set(), "reference_count": 0}
        for name in HARDWARE_ADDRESSES
    }

    for offset in range(0, len(data) - 1, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000:
            continue
        instruction_candidates += 1
        target = sh2_movl_pc_literal_target(offset, opcode, len(data))
        if target is None:
            continue
        valid_literal_targets += 1
        value = be32(data, target)
        for name, address in HARDWARE_ADDRESSES.items():
            if value == address:
                refs[name]["instruction_offsets"].add(offset)
                refs[name]["literal_offsets"].add(target)
                refs[name]["reference_count"] += 1
                break

    hardware_references = []
    for name, address in HARDWARE_ADDRESSES.items():
        entry = refs[name]
        if not entry["reference_count"]:
            continue
        hardware_references.append({
            "name": name,
            "address": f"0x{address:08X}",
            "instruction_reference_count": entry["reference_count"],
            "unique_instruction_count": len(entry["instruction_offsets"]),
            "unique_literal_slot_count": len(entry["literal_offsets"]),
        })

    return {
        "mov_l_pc_relative_instruction_candidates": instruction_candidates,
        "valid_literal_target_count": valid_literal_targets,
        "hardware_reference_instruction_count": sum(
            entry["instruction_reference_count"] for entry in hardware_references
        ),
        "unique_hardware_literal_slot_count": sum(
            entry["unique_literal_slot_count"] for entry in hardware_references
        ),
        "hardware_references": hardware_references,
        "interpretation": (
            "SH-2 instruction-pattern and literal-target candidates only. The file has "
            "not been fully disassembled, so code/data boundaries and active control flow "
            "remain unverified."
        ),
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    target = next(
        (entry for entry in disc["game_files"] if entry["path"].upper() == "/0TH2.BIN"),
        None,
    )
    if target is None:
        raise ValueError("Expected /0TH2.BIN in the ISO root directory")
    if target["size_bytes"] > MAX_PROBE_BYTES:
        raise ValueError("/0TH2.BIN exceeds the safe probe size")

    with image.open("rb") as stream:
        stream.seek(target["extent_sector"] * SECTOR)
        data = stream.read(target["size_bytes"])
    if len(data) != target["size_bytes"]:
        raise ValueError("Short read from /0TH2.BIN")

    return {
        "schema_version": 1,
        "stage": "stage13_sh2_pc_relative_hardware_cross_reference",
        "disc_sha256": disc["sha256"],
        "disc_product": disc["saturn_header"]["product"],
        "target_file": target["path"],
        "target_file_size_bytes": target["size_bytes"],
        "scan": scan_sh2_literal_references(data),
        "limitations": [
            "This recognizes only the SH-2 MOV.L @(disp,PC),Rn opcode pattern; it is not a full disassembler.",
            "The entire file is scanned, including possible data, so some instruction-shaped words may be false positives.",
            "Literal references do not prove that a renderer path executes or reveal the full VDP1 command-building logic.",
            "No exact offsets, original bytes, textures, palettes, audio, or video are exported.",
            "No native game engine or Switch NRO is produced.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Private local Sega Saturn ISO")
    parser.add_argument("-o", "--output", type=Path, help="Metadata-only JSON output path")
    args = parser.parse_args()
    output = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print("Stage 13 metadata-only report saved:", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
