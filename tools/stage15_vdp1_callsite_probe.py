#!/usr/bin/env python3
"""Stage 15: resolve the VDP1 copy routine's indirect call and argument contract.

Reads a private local Sega Saturn ISO and emits aggregate metadata only.
No source offsets, raw bytes, textures, palettes, or other game assets are
written to the report.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage03_index_tables import MAX_PROBE_BYTES
from stage14_vdp1_record_copy_probe import (
    ROUTINE_WORDS,
    be16,
    be32,
    matches_vdp1_record_copy_routine,
    mov_l_pc_target,
)

# Inferred from the code's absolute reference to the matched routine at file
# offset 0xBA: 0x06004000 + 0xBA == 0x060040BA.
SATURN_MAIN_LOAD_BASE = 0x06004000
DESCRIPTOR_BUFFER_ADDRESS = 0x06096A70
TOTAL_RECORD_COUNT_ADDRESS = 0x0609651E
BUFFER_POINTER_SLOT_ADDRESS = 0x06096510
COPY_UNIT_BYTES = 32
DESCRIPTOR_BYTES = 8


def is_control_flow(opcode: int) -> bool:
    """Recognize common SH-2 control-flow instructions for a short xref window."""
    if opcode & 0xF000 in (0xA000, 0xB000):
        return True
    if opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00):
        return True
    if opcode & 0xF0FF in (0x400B, 0x402B):
        return True
    return opcode in (0x0002, 0x0003, 0x000B, 0x002B)


def writes_register(opcode: int, register: int) -> bool:
    """Conservative GPR clobber check for the short indirect-call window."""
    top = opcode & 0xF000
    n = (opcode >> 8) & 0x0F
    m = (opcode >> 4) & 0x0F
    low = opcode & 0x0F

    if opcode == 0x0009:  # NOP
        return False
    if top in (0x5000, 0x6000, 0x7000, 0x9000, 0xD000, 0xE000):
        return n == register
    if top == 0x2000:
        if low in (0, 1, 2, 3, 7, 8, 13, 14):
            return False
        if low in (4, 5, 6, 9, 10, 11, 12):
            return n == register
        if low == 15:  # MAC.W updates both address registers
            return register in (n, m)
        return True
    if top == 0x3000:
        if low in (0, 2, 3, 4, 5, 6, 7, 13):
            return False
        if low in (8, 9, 10, 11, 12, 14, 15):
            return n == register
        return n == register
    if top == 0x4000:
        if opcode & 0xF0FF in (0x400B, 0x402B):
            return False
        return n == register
    if top == 0xC000:
        return register == 0
    return True


def routine_offsets(data: bytes) -> list[int]:
    """Return internal candidate offsets; they are never emitted in reports."""
    width = len(ROUTINE_WORDS) * 2
    return [
        offset
        for offset in range(0, len(data) - width + 1, 2)
        if matches_vdp1_record_copy_routine(data, offset)
    ]


def find_indirect_call_sites(data: bytes, offsets: list[int]) -> list[dict]:
    """Resolve PC-relative target literals and a nearby JSR through the same register."""
    runtime_targets = {
        SATURN_MAIN_LOAD_BASE + offset: offset
        for offset in offsets
    }
    sites = []
    for load_offset in range(0, len(data) - 1, 2):
        opcode = be16(data, load_offset)
        if opcode & 0xF000 != 0xD000:
            continue
        literal_offset = mov_l_pc_target(load_offset, opcode, len(data))
        if literal_offset is None:
            continue
        runtime_target = be32(data, literal_offset)
        if runtime_target not in runtime_targets:
            continue

        target_register = (opcode >> 8) & 0x0F
        for step in range(1, 5):
            call_offset = load_offset + step * 2
            if call_offset + 2 > len(data):
                break
            call_opcode = be16(data, call_offset)
            if call_opcode & 0xF0FF == 0x400B:  # JSR @Rn
                if ((call_opcode >> 8) & 0x0F) == target_register:
                    sites.append({
                        "routine_offset": runtime_targets[runtime_target],
                        "call_offset": call_offset,
                        "literal_load_offset": load_offset,
                        "call_register": target_register,
                    })
                break
            if is_control_flow(call_opcode) or writes_register(call_opcode, target_register):
                break
    return sites


def direct_bsr_call_count(data: bytes, offsets: list[int]) -> int:
    """Count direct BSR instructions targeting the matched routine offsets."""
    target_set = set(offsets)
    count = 0
    for offset in range(0, len(data) - 1, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xB000:
            continue
        displacement = opcode & 0x0FFF
        if displacement & 0x0800:
            displacement -= 0x1000
        if offset + 4 + displacement * 2 in target_set:
            count += 1
    return count


def pc_relative_reference_count(data: bytes, value: int) -> int:
    """Count SH-2 MOV.L PC-relative candidates resolving to one literal value."""
    count = 0
    for offset in range(0, len(data) - 1, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000:
            continue
        target = mov_l_pc_target(offset, opcode, len(data))
        if target is not None and be32(data, target) == value:
            count += 1
    return count


def call_has_buffer_argument(data: bytes, call_offset: int) -> bool:
    """Check that R4 receives the known staging-buffer address shortly before JSR."""
    start = max(0, call_offset - 24)
    for offset in range(start, call_offset, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000 or ((opcode >> 8) & 0x0F) != 4:
            continue
        target = mov_l_pc_target(offset, opcode, len(data))
        if target is not None and be32(data, target) == DESCRIPTOR_BUFFER_ADDRESS:
            return True
    return False


def call_has_nonzero_record_budget_guard(data: bytes, call_offset: int) -> bool:
    """Recognize count-word load, sign extension, zero test and branch around the call."""
    start = max(0, call_offset - 28)
    stop = max(start, call_offset - 8)
    for offset in range(start, stop + 1, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000 or ((opcode >> 8) & 0x0F) != 0:
            continue
        target = mov_l_pc_target(offset, opcode, len(data))
        if target is None or be32(data, target) != TOTAL_RECORD_COUNT_ADDRESS:
            continue
        if offset + 10 >= len(data):
            continue
        if (
            be16(data, offset + 2) == 0x6501
            and be16(data, offset + 4) == 0x625F
            and be16(data, offset + 6) == 0x2228
        ):
            branch = be16(data, offset + 8)
            if branch & 0xFF00 == 0x8900:
                displacement = branch & 0xFF
                if displacement & 0x80:
                    displacement -= 0x100
                if offset + 8 + 4 + displacement * 2 > call_offset:
                    return True
    return False


def call_resets_record_budget(data: bytes, call_offset: int) -> bool:
    """Recognize the post-call zero store to the same 16-bit record-budget word."""
    start = call_offset + 4
    stop = min(len(data) - 3, call_offset + 24)
    for offset in range(start, stop, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000:
            continue
        if ((opcode >> 8) & 0x0F) != 3:
            continue
        target = mov_l_pc_target(offset, opcode, len(data))
        if target is not None and be32(data, target) == TOTAL_RECORD_COUNT_ADDRESS:
            if offset + 2 < len(data) and be16(data, offset + 2) == 0x2311:
                return True
    return False


def summarize_callsite_analysis(data: bytes) -> dict:
    """Produce a metadata-only call/argument summary without exact source offsets."""
    offsets = routine_offsets(data)
    sites = find_indirect_call_sites(data, offsets)
    call_offsets = [site["call_offset"] for site in sites]
    return {
        "routine_signature_match_count": len(offsets),
        "indirect_jsr_call_site_count": len(sites),
        "direct_relative_bsr_call_count": direct_bsr_call_count(data, offsets),
        "descriptor_buffer_runtime_address": f"0x{DESCRIPTOR_BUFFER_ADDRESS:08X}",
        "descriptor_buffer_literal_reference_count": pc_relative_reference_count(
            data, DESCRIPTOR_BUFFER_ADDRESS
        ),
        "descriptor_buffer_passed_in_r4": any(
            call_has_buffer_argument(data, call_offset)
            for call_offset in call_offsets
        ),
        "record_budget_runtime_address": f"0x{TOTAL_RECORD_COUNT_ADDRESS:08X}",
        "record_budget_literal_reference_count": pc_relative_reference_count(
            data, TOTAL_RECORD_COUNT_ADDRESS
        ),
        "record_budget_loaded_into_r5_and_zero_guarded": any(
            call_has_nonzero_record_budget_guard(data, call_offset)
            for call_offset in call_offsets
        ),
        "record_budget_cleared_after_call": any(
            call_resets_record_budget(data, call_offset)
            for call_offset in call_offsets
        ),
        "descriptor_pointer_global_slot_runtime_address": f"0x{BUFFER_POINTER_SLOT_ADDRESS:08X}",
        "descriptor_bytes_consumed_per_entry": DESCRIPTOR_BYTES,
        "descriptor_fields": [
            {"field": "source_address", "bytes": 4},
            {"field": "destination_index", "bytes": 2},
            {"field": "record_count_for_this_source", "bytes": 2},
        ],
        "total_record_budget_decremented_per_copy": True,
        "copy_unit_bytes": COPY_UNIT_BYTES,
        "destination_address_formula": "VDP1_VRAM_BASE + zero_extended_destination_index * 8",
        "interpretation": (
            "A PC-relative literal reference resolves to the matched routine's inferred "
            "runtime address and is followed by JSR through the same register. The caller "
            "passes the staging buffer in R4 and guards the global total-record budget "
            "before calling. In the callee, R5 is decremented once per 32-byte copy, "
            "while each 8-byte descriptor supplies a source address, destination index, "
            "and per-source record count. The budget is cleared after the call."
        ),
        "limitations": [
            "The 0x06004000 load base is inferred from the matching routine pointer reference; runtime execution was not traced in an emulator.",
            "The SH-2 scanner recognizes a narrow signature and short call window, not all possible control flow.",
            "The staging buffer is runtime data; its contents and producer routine are not decoded by this stage.",
            "No exact source offsets, original bytes, textures, palettes, audio, or video are emitted.",
            "No native game engine or Nintendo Switch NRO is produced.",
        ],
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
        "stage": "stage15_vdp1_callsite_analysis",
        "disc_sha256": disc["sha256"],
        "disc_product": disc["saturn_header"]["product"],
        "target_file": target["path"],
        "target_file_size_bytes": target["size_bytes"],
        "analysis": summarize_callsite_analysis(data),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Private local Sega Saturn ISO")
    parser.add_argument("-o", "--output", type=Path, help="Metadata-only JSON output path")
    args = parser.parse_args()
    output = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print("Stage 15 metadata-only report saved:", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
