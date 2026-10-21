#!/usr/bin/env python3
"""Stage14: recognize a 32-byte-stride VDP1 VRAM record-copy routine.

The scanner uses a conservative SH-2 opcode signature and validates its
PC-relative VDP1 VRAM literal. It reports aggregate metadata only; no code
offsets, source bytes, textures, or game assets are exported.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage03_index_tables import MAX_PROBE_BYTES

VDP1_VRAM_BASE = 0x25C00000

# Exact instruction words for the observed routine, except for its PC-relative
# MOV.L literal load into R7. The branch displacements encode two loop backedges.
# This intentionally conservative signature is not a general SH-2 disassembler.
ROUTINE_WORDS: tuple[int | None, ...] = (
    0x2FE6,  # MOV.L R14,@-R15
    0xE600,  # MOV #0,R6
    None,    # MOV.L @(disp,PC),R7 -> VDP1 VRAM base
    0x6346,  # MOV.L @R4+,R3
    0x6145,  # MOV.W @R4+,R1
    0x611D,  # EXTU.W R1,R1
    0x4108,  # SHLL2 R1
    0x4100,  # SHLL R1
    0x317C,  # ADD R7,R1
    0x6245,  # MOV.W @R4+,R2
    0x6032,  # MOV.L @R3,R0
    0x5E31,  # MOV.L @(1,R3),R14
    0x2102,  # MOV.L R0,@R1
    0x11E1,  # MOV.L R14,@(1,R1)
    0x5032,  # MOV.L @(2,R3),R0
    0x5E33,  # MOV.L @(3,R3),R14
    0x1102,  # MOV.L R0,@(2,R1)
    0x11E3,  # MOV.L R14,@(3,R1)
    0x5034,  # MOV.L @(4,R3),R0
    0x5E35,  # MOV.L @(5,R3),R14
    0x1104,  # MOV.L R0,@(4,R1)
    0x11E5,  # MOV.L R14,@(5,R1)
    0x5036,  # MOV.L @(6,R3),R0
    0x5E37,  # MOV.L @(7,R3),R14
    0x1106,  # MOV.L R0,@(6,R1)
    0x11E7,  # MOV.L R14,@(7,R1)
    0x7320,  # ADD #32,R3
    0x72FF,  # ADD #-1,R2
    0x7120,  # ADD #32,R1
    0x3260,  # CMP/EQ R6,R2
    0x8BEA,  # BF/S inner-loop backedge
    0x75FF,  # delay-slot decrement
    0x3560,  # CMP/EQ R6,R5
    0x8BE0,  # BF outer-loop backedge
    0x000B,  # RTS
    0x6EF6,  # delay-slot restore of R14
)


def be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def be32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


def mov_l_pc_target(instruction_offset: int, opcode: int, data_size: int) -> int | None:
    """Resolve SH-2 MOV.L @(disp,PC),Rn with aligned PC-relative addressing."""
    if instruction_offset < 0 or instruction_offset % 2:
        return None
    if instruction_offset + 2 > data_size or opcode & 0xF000 != 0xD000:
        return None
    target = ((instruction_offset + 4) & ~3) + (opcode & 0x00FF) * 4
    if target < 0 or target + 4 > data_size:
        return None
    return target


def matches_vdp1_record_copy_routine(data: bytes, offset: int) -> bool:
    """Return true only for the complete known copy-loop signature."""
    byte_length = len(ROUTINE_WORDS) * 2
    if offset < 0 or offset % 2 or offset + byte_length > len(data):
        return False

    words = [be16(data, offset + index * 2) for index in range(len(ROUTINE_WORDS))]
    for actual, expected in zip(words, ROUTINE_WORDS):
        if expected is None:
            if actual & 0xFF00 != 0xD700:
                return False
        elif actual != expected:
            return False

    instruction_offset = offset + 4
    literal_offset = mov_l_pc_target(instruction_offset, words[2], len(data))
    if literal_offset is None or literal_offset < offset + byte_length:
        return False
    return be32(data, literal_offset) == VDP1_VRAM_BASE


def find_vdp1_index_times_eight(data: bytes, load_offset: int, base_register: int) -> int | None:
    """Find SHLL2; SHLL; ADD(base,index) following a VDP1 base literal load."""
    start = load_offset + 2
    stop = min(len(data) - 1, load_offset + 42)
    for index_register in range(16):
        shll2 = 0x4008 | (index_register << 8)
        shll = 0x4000 | (index_register << 8)
        add_base = 0x300C | (index_register << 8) | (base_register << 4)
        for first in range(start, stop, 2):
            if be16(data, first) != shll2:
                continue
            for second in range(first + 2, min(first + 10, stop), 2):
                if be16(data, second) != shll:
                    continue
                for third in range(second + 2, min(second + 10, stop), 2):
                    if be16(data, third) == add_base:
                        return index_register
    return None


def vdp1_indexed_address_profile(data: bytes, copy_offsets: list[int]) -> dict:
    """Count independent base + index*8 patterns without emitting offsets."""
    base_loads = []
    for offset in range(0, len(data) - 1, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000:
            continue
        target = mov_l_pc_target(offset, opcode, len(data))
        if target is None or be32(data, target) != VDP1_VRAM_BASE:
            continue
        base_register = (opcode >> 8) & 0x0F
        index_register = find_vdp1_index_times_eight(data, offset, base_register)
        if index_register is not None:
            base_loads.append((offset, index_register))

    routine_bytes = len(ROUTINE_WORDS) * 2
    outside_copy = sum(
        not any(start <= offset < start + routine_bytes for start in copy_offsets)
        for offset, _ in base_loads
    )
    vdp1_base_literal_load_count = 0
    for offset in range(0, len(data) - 1, 2):
        opcode = be16(data, offset)
        if opcode & 0xF000 != 0xD000:
            continue
        target = mov_l_pc_target(offset, opcode, len(data))
        if target is not None and be32(data, target) == VDP1_VRAM_BASE:
            vdp1_base_literal_load_count += 1

    return {
        "vdp1_base_literal_load_count": vdp1_base_literal_load_count,
        "base_plus_index_times_8_sequence_count": len(base_loads),
        "sequence_count_outside_copy_routine": outside_copy,
        "interpretation": (
            "An SHLL2/SHLL/ADD pattern computes base + index*8. This independently "
            "corroborates indexed VDP1 address arithmetic but does not identify the "
            "meaning of the indexed structure."
        ),
    }


def scan_vdp1_record_copy_routines(data: bytes) -> dict:
    """Find the conservative signature and return facts, never source offsets."""
    byte_length = len(ROUTINE_WORDS) * 2
    matches = [
        offset
        for offset in range(0, len(data) - byte_length + 1, 2)
        if matches_vdp1_record_copy_routine(data, offset)
    ]
    indexed = vdp1_indexed_address_profile(data, matches)
    return {
        "routine_signature": "SH-2 VDP1-base load plus 32-byte copy-loop signature",
        "matching_routine_count": len(matches),
        "vdp1_vram_base": f"0x{VDP1_VRAM_BASE:08X}",
        "destination_address_formula": "VDP1_VRAM_BASE + zero_extended_16_bit_descriptor_field * 8",
        "longwords_copied_per_iteration": 8,
        "bytes_copied_per_iteration": 32,
        "source_stride_bytes": 32,
        "destination_stride_bytes": 32,
        "loop_backedge_count": 2,
        "return_delay_slot_restores_saved_register": True,
        "independent_vdp1_indexing_evidence": indexed,
        "interpretation": (
            "The routine copies 32-byte records into VDP1 VRAM. This stride matches "
            "the Saturn VDP1 command-record size and is strong evidence for a command "
            "upload path. Additional base + index*8 patterns occur outside this routine, "
            "but the copied source records have not yet been decoded."
        ),
        "limitations": [
            "This is an exact signature for one observed routine, not a complete SH-2 disassembler.",
            "The source descriptor and copied 32-byte records are not interpreted field by field.",
            "Indexed VDP1 addressing patterns do not establish the semantic type of the indexed structure.",
            "Callers and runtime reachability are not established by this signature scan.",
            "No exact offsets, original bytes, textures, palettes, audio, or video are emitted.",
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
        "stage": "stage14_vdp1_record_copy_probe",
        "disc_sha256": disc["sha256"],
        "disc_product": disc["saturn_header"]["product"],
        "target_file": target["path"],
        "target_file_size_bytes": target["size_bytes"],
        "scan": scan_vdp1_record_copy_routines(data),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Private local Sega Saturn ISO")
    parser.add_argument("-o", "--output", type=Path, help="Metadata-only JSON output path")
    args = parser.parse_args()
    output = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print("Stage 14 metadata-only report saved:", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
