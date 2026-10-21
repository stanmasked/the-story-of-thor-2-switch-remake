#!/usr/bin/env python3
"""Stage17: audit direct SH-2 references to the Stage16 descriptor writer.

Metadata only; no source bytes, file offsets, or assets are exported.
Absence of direct references does NOT prove the function is unreachable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from inspect_saturn_iso import inventory, SECTOR
from stage03_index_tables import MAX_PROBE_BYTES
from stage16_vdp1_descriptor_writer_probe import descriptor_writer_candidates
from stage14_vdp1_record_copy_probe import be16, be32, mov_l_pc_target

LOAD_BASE_HYPOTHESIS = 0x06004000


def writer_guard_positions(data: bytes) -> list[int]:
    """Reuse Stage16 predicates and locate guard positions internally."""
    if not descriptor_writer_candidates(data):
        return []
    matches = []
    for pos in range(0, len(data) - 10, 2):
        op = be16(data, pos)
        if op & 0xFF00 != 0xD300:
            continue
        if be16(data, pos + 2) != 0x6231:
            continue
        cap = be16(data, pos + 4)
        if cap & 0xF000 != 0x9000 or be16(data, pos + 6) != 0x3213:
            continue
        word_target = pos + 8 + (cap & 255) * 2
        if word_target + 2 > len(data) or be16(data, word_target) != 512:
            continue
        if be16(data, pos + 8) & 0xFF00 != 0x8900:
            continue
        matches.append(pos)
    return matches


def audit_direct_references(data: bytes, target_positions: list[int], load_base: int) -> dict:
    """Check BSR target words and PC-relative MOV.L literal references.

    A literal must be followed by matching JSR @Rn within 12 instructions to
    count as a nearby indirect-call candidate. This is a heuristic only.
    """
    targets = set(target_positions)
    direct = 0
    literal = 0
    nearby_jsr = 0
    for pos in range(0, len(data) - 1, 2):
        op = be16(data, pos)
        if op & 0xF000 == 0xB000:
            displacement = op & 0x0FFF
            if displacement & 0x0800:
                displacement -= 0x1000
            if pos + 4 + displacement * 2 in targets:
                direct += 1
        if op & 0xF000 != 0xD000:
            continue
        offset = mov_l_pc_target(pos, op, len(data))
        if offset is None or be32(data, offset) not in {load_base + t for t in targets}:
            continue
        literal += 1
        register = (op >> 8) & 0xF
        jsr_opcode = 0x400B | (register << 8)
        if any(be16(data, nxt) == jsr_opcode
               for nxt in range(pos + 2, min(len(data) - 1, pos + 26), 2)):
            nearby_jsr += 1
    return {
        "writer_guard_candidates": len(targets),
        "direct_bsr_to_writer_count": direct,
        "pc_relative_absolute_writer_literal_references": literal,
        "nearby_jsr_using_literal_register_candidates": nearby_jsr,
        "load_base_hypothesis": f"0x{load_base:08X}",
        "interpretation": (
            "Direct references absent under these narrow tests do not prove the "
            "writer unused; address arithmetic, register-indirect calls, external "
            "modules and control-flow decoding remain open."
        ),
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    entry = next((e for e in disc["game_files"] if e["path"].upper() == "/0TH2.BIN"), None)
    if entry is None or entry["size_bytes"] > MAX_PROBE_BYTES:
        raise ValueError("Expected bounded 0TH2.BIN")
    with image.open("rb") as stream:
        stream.seek(entry["extent_sector"] * SECTOR)
        data = stream.read(entry["size_bytes"])
    if len(data) != entry["size_bytes"]:
        raise ValueError("Short ISO read")
    positions = writer_guard_positions(data)
    return {
        "schema_version": 1,
        "stage": "stage17_writer_callsite_audit",
        "disc_sha256": disc["sha256"],
        "target_file": entry["path"],
        "analysis": audit_direct_references(data, positions, LOAD_BASE_HYPOTHESIS),
        "limitations": [
            "This is not a full SH-2 control flow graph or emulator trace.",
            "No runtime values of descriptor count, size argument or staging buffer are known.",
            "No code positions or original bytes are emitted.",
        ],
    }


def main():
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
