#!/usr/bin/env python3
"""Stage32: match direct and literal-resolved indirect callers of Stage31 readers.

Original Saturn game binaries stay private. JSON output is aggregate-only:
no executable offsets, instruction bytes or proprietary game assets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage30_field_consumer_audit import find_consumer_groups
from stage31_entry_guard_audit import candidate_prologue, field16_before_group

LOAD_BASE = 0x06004000
R14_TO_R4 = 0x64E3  # MOV R14,R4 in a SH-2 call delay slot
R5_IMMEDIATE_TWO = 0xE502
SAFE_INTERVENING = (0x7FFC, 0x2F42)  # reserve four bytes, write R4 at SP


def bsr_destination(position: int, opcode: int) -> int | None:
    """Signed 12-bit displacement in SH-2 BSR, relative to PC+4."""
    if position < 0 or position & 1 or opcode & 0xF000 != 0xB000:
        return None
    displacement = opcode & 0xFFF
    if displacement & 0x800:
        displacement -= 0x1000
    return position + 4 + displacement * 2


def movl_pc_literal(data: bytes, position: int) -> dict | None:
    """Decode MOV.L @(disp,PC),Rn; the source is 4-byte aligned."""
    if position < 0 or position & 1 or position + 2 > len(data):
        return None
    opcode = be16(data, position)
    if opcode & 0xF000 != 0xD000:
        return None
    literal_pos = ((position + 4) & ~3) + (opcode & 0xFF) * 4
    if literal_pos + 4 > len(data):
        return None
    return {
        "literal_pos": literal_pos,
        "register": (opcode >> 8) & 15,
        "value": int.from_bytes(data[literal_pos:literal_pos + 4], "big"),
    }


def direct_call_sites(data: bytes, destination: int) -> list[dict]:
    """Do not mistake numeric BSR matches for a full disassembly/CFG."""
    sites = []
    for pos in range(0, len(data) - 3, 2):
        if bsr_destination(pos, be16(data, pos)) == destination:
            sites.append({
                "position": pos,
                "delay_r14_to_r4": be16(data, pos + 2) == R14_TO_R4,
            })
    return sites


def indirect_call_sites(data: bytes, destination: int) -> list[dict]:
    """Track PC-literal -> matching JSR register within 2/4/6 bytes.

    For the 6-byte variant, the two supported intermediate instructions
    adjust the stack and save R4 without modifying the JSR target register.
    This is intentionally not general-purpose data-flow reconstruction.
    """
    expected = LOAD_BASE + destination
    sites: list[dict] = []
    for pos in range(0, len(data) - 11, 2):
        info = movl_pc_literal(data, pos)
        if info is None or info["value"] != expected:
            continue
        target_reg = info["register"]
        jsr = 0x400B | (target_reg << 8)
        for distance in (2, 6):
            call = pos + distance
            if call + 4 > len(data) or be16(data, call) != jsr:
                continue
            if distance == 6 and tuple(be16(data, pos + off) for off in (2, 4)) != SAFE_INTERVENING:
                continue
            delay = be16(data, call + 2)
            sites.append({
                "load_pos": pos,
                "jsr_pos": call,
                "literal_pos": info["literal_pos"],
                "delay_r14_to_r4": delay == R14_TO_R4,
                "delay_r5_two": delay == R5_IMMEDIATE_TWO,
                "literal_load_register": target_reg,
                "distance_bytes": distance,
            })
            break
    return sites


def matched_consumer_entries(data: bytes) -> list[dict]:
    """Reuse Stage31's recognized reader groups and their strict prologues."""
    entries = []
    for group in find_consumer_groups(data):
        first = group["reads"][0]["instruction_position"]
        prologue = candidate_prologue(data, first)
        if prologue is None or not field16_before_group(data, prologue["entry"], first):
            continue
        entries.append({
            "entry": prologue["entry"],
            "extended": len(group["reads"]) == 6,
            "saved_count": len(prologue["saved_registers"]),
        })
    return entries


def summarize_callers(data: bytes) -> dict:
    entries = matched_consumer_entries(data)
    direct_counts = []
    indirect_counts = []
    direct_delays = []
    indirect_delays = []
    indirect_r5_two = []
    indirect_distances = []
    for entry in entries:
        direct = direct_call_sites(data, entry["entry"])
        indirect = indirect_call_sites(data, entry["entry"])
        direct_counts.append(len(direct))
        indirect_counts.append(len(indirect))
        direct_delays.append(sum(x["delay_r14_to_r4"] for x in direct))
        indirect_delays.append(sum(x["delay_r14_to_r4"] for x in indirect))
        indirect_r5_two.append(sum(x["delay_r5_two"] for x in indirect))
        indirect_distances.append([x["distance_bytes"] for x in indirect])
    return {
        "stage31_consumer_entries_examined": len(entries),
        "direct_bsr_calls_by_consumer": direct_counts,
        "pc_literal_linked_jsr_calls_by_consumer": indirect_counts,
        "direct_bsr_delay_slots_passing_r14_as_r4": direct_delays,
        "indirect_jsr_delay_slots_passing_r14_as_r4": indirect_delays,
        "indirect_jsr_delay_slots_setting_r5_to_two": indirect_r5_two,
        "indirect_load_to_jsr_distances_bytes": indirect_distances,
        "totals": {
            "direct_bsr": sum(direct_counts),
            "resolved_indirect_jsr": sum(indirect_counts),
            "calls_passing_r14_to_r4_in_delay_slot": sum(direct_delays + indirect_delays),
            "indirect_calls_setting_r5_to_two_in_delay_slot": sum(indirect_r5_two),
        },
        "interpretation": (
            "Two consumer routines have one direct BSR caller each, both "
            "passing R14 through R4 in the delay slot. The full seven-byte "
            "reader is addressed by eight PC-relative function literals "
            "and indirect JSR calls: seven pass R14 as R4 in the delay slot; "
            "the remaining caller sets R5=2 while R4 has an unresolved origin."
        ) if len(entries) == 3 else "Partial caller-link analysis.",
        "limitations": [
            "PC-relative pointer matching does not prove gameplay reachability.",
            "The origin of callers' R14 or preexisting R4 is not established.",
            "Shared target routines do not prove that all callers pass the same object.",
            "No verified producer-consumer link to VDP1 command memory or P0-P3.",
            "No original program offsets, machine-code bytes or assets are output.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version": 1, "stage": "stage32_field_consumer_callers",
            "target_file": "0TH2.BIN",
            "analysis": summarize_callers(iso_file_payload(image))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(args.image), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
