#!/usr/bin/env python3
"""Stage18: detect SH-2 branch flow around a conditional VDP1 descriptor writer.

Exports aggregate metadata only: no game code, exact offsets or assets.
The scanner is deliberately narrow; it is not a full control-flow graph.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

BUDGET_GLOBAL = 0x0609651E
EXPECTED_CAPACITY = 512
SECTOR = 2048


def be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def be32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def movl_target(pos: int, opcode: int, length: int) -> int | None:
    if pos < 0 or pos % 2 or pos + 2 > length or opcode & 0xF000 != 0xD000:
        return None
    target = ((pos + 4) & ~3) + (opcode & 255) * 4
    return target if target + 4 <= length else None


def movw_target(pos: int, opcode: int, length: int) -> int | None:
    if pos < 0 or pos % 2 or pos + 2 > length or opcode & 0xF000 != 0x9000:
        return None
    target = pos + 4 + (opcode & 255) * 2
    return target if target + 2 <= length else None


def conditional_branch_target(pos: int, opcode: int) -> int | None:
    if pos < 0 or pos % 2 or opcode & 0xFF00 not in (0x8900, 0x8B00, 0x8D00, 0x8F00):
        return None
    displacement = opcode & 255
    if displacement & 128:
        displacement -= 256
    return pos + 4 + displacement * 2


def find_guarded_writer_blocks(data: bytes) -> list[dict]:
    """Find guarded 4/2/2 stores and pointer advance with a common exit.

    Internal positions are not included in the report.
    """
    found = []
    for start in range(0, len(data) - 12, 2):
        load = be16(data, start)
        if load & 0xFF00 != 0xD300:
            continue
        target = movl_target(start, load, len(data))
        if target is None or be32(data, target) != BUDGET_GLOBAL:
            continue
        if be16(data, start + 2) != 0x6231 or be16(data, start + 6) != 0x3213:
            continue
        capacity = movw_target(start + 4, be16(data, start + 4), len(data))
        if capacity is None or be16(data, capacity) != EXPECTED_CAPACITY:
            continue
        jump = be16(data, start + 8)
        if jump & 0xFF00 != 0x8900:
            continue
        exit_pos = conditional_branch_target(start + 8, jump)
        if exit_pos is None or exit_pos <= start + 10 or exit_pos >= min(len(data), start + 120):
            continue
        if [be16(data, exit_pos - 6 + i * 2) for i in range(3)] != [0x6382, 0x7308, 0x2832]:
            continue
        instructions = [be16(data, pos) for pos in range(start + 10, exit_pos - 6, 2)]
        try:
            s0 = instructions.index(0x2322)
            s1 = instructions.index(0x2301, s0 + 1)
            s2 = instructions.index(0x2321, s1 + 1)
            s3 = instructions.index(0x7101, s2 + 1)
            instructions.index(0x2311, s3 + 1)
        except ValueError:
            continue
        previous = (
            start >= 4
            and be16(data, start - 4) & 0xFF00 == 0x8F00
            and conditional_branch_target(start - 4, be16(data, start - 4)) == exit_pos
        )
        found.append({
            "start": start,
            "exit": exit_pos,
            "guard_branches_over_all_stores": True,
            "previous_delayed_branch_same_exit": previous,
            "ordered_field_stores": True,
            "single_counter_increment": True,
        })
    return found


def summarize_guard_flow(data: bytes) -> dict:
    blocks = find_guarded_writer_blocks(data)
    return {
        "capacity_guards_with_validated_writer_block": len(blocks),
        "guarded_writer_blocks_with_target_after_pointer_advance": sum(
            b["guard_branches_over_all_stores"] for b in blocks
        ),
        "pre_guard_bf_s_branches_sharing_writer_exit": sum(
            b["previous_delayed_branch_same_exit"] for b in blocks
        ),
        "ordered_source_destination_count_stores": sum(
            b["ordered_field_stores"] for b in blocks
        ),
        "writer_blocks_with_single_budget_increment": sum(
            b["single_counter_increment"] for b in blocks
        ),
        "descriptor_capacity": EXPECTED_CAPACITY if blocks else None,
        "descriptor_bytes": 8 if blocks else None,
        "control_flow_interpretation": (
            "The descriptor writer is a conditionally executed code block with "
            "branch paths that skip its stores. Stage17's absence of BSR to the "
            "capacity guard must not be treated as evidence of an unused function: "
            "the guard is not established as a function entry."
        ),
        "limitations": [
            "This is a narrow signature, not the full parent function or call graph.",
            "The budget invariant (one increment versus copies per descriptor) remains unresolved.",
            "Runtime argument values and source resource identities are not confirmed.",
            "No source offsets, code bytes, images, palettes, audio or video are exported.",
        ],
    }


def iso_file_payload(image: Path, name: bytes = b"0TH2.BIN") -> bytes:
    """Read one ISO9660 root file locally without writing source payload."""
    with image.open("rb") as stream:
        stream.seek(16 * SECTOR)
        pvd = stream.read(SECTOR)
        if pvd[:7] != b"\x01CD001\x01":
            raise ValueError("Not a supported ISO9660 volume")
        root = int.from_bytes(pvd[158:162], "little")
        length = int.from_bytes(pvd[166:170], "little")
        if root * SECTOR + length > image.stat().st_size:
            raise ValueError("Root directory out of bounds")
        stream.seek(root * SECTOR)
        directory = stream.read(length)
        index = 0
        while index < len(directory):
            size = directory[index]
            if not size:
                index = (index // SECTOR + 1) * SECTOR
                continue
            entry = directory[index:index + size]
            index += size
            if entry[33:33 + entry[32]].split(b";")[0] != name:
                continue
            extent = int.from_bytes(entry[2:6], "little")
            payload_size = int.from_bytes(entry[10:14], "little")
            if payload_size > 5 * 1024 * 1024 or extent * SECTOR + payload_size > image.stat().st_size:
                raise ValueError("File exceeds safe limits")
            stream.seek(extent * SECTOR)
            data = stream.read(payload_size)
            if len(data) != payload_size:
                raise ValueError("Incomplete file read")
            return data
        raise ValueError("0TH2.BIN not found")


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    digest = hashlib.sha256()
    with image.open("rb") as stream:
        for chunk in iter(lambda: stream.read(2 * 1024 * 1024), b""):
            digest.update(chunk)
    return {
        "schema_version": 1,
        "stage": "stage18_vdp1_writer_guard_flow",
        "disc_sha256": digest.hexdigest(),
        "file_name": "0TH2.BIN",
        "summary": summarize_guard_flow(data),
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
