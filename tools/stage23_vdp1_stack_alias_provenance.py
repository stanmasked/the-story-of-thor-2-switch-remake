#!/usr/bin/env python3
"""Stage23: bounded provenance for SP-relative writes via temporary SH-2 registers.

The original Saturn ISO is processed locally. Only aggregate findings are
reported; original instruction locations, bytes and assets are never emitted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage21_vdp1_stack_sources import matching_stack_source_chains

STACK_FIELDS = (20, 32, 56, 80)
FRAME_ALLOC = 0x7FA8  # ADD #-88,R15


def find_frame(data: bytes, before: int, max_back: int = 4096) -> int | None:
    if before > len(data) or before < 2:
        return None
    for pos in range(before - 2, max(0, before - max_back) - 1, -2):
        if be16(data, pos) == FRAME_ALLOC:
            return pos
    return None


def overwrites_register(opcode: int, register: int) -> bool:
    """Conservative set of register-write instructions used in alias windows."""
    top = opcode & 0xF000
    n = (opcode >> 8) & 0xF
    low = opcode & 0xF
    if top in (0x6000, 0x7000, 0x9000, 0xD000, 0xE000):
        return n == register
    if top in (0x3000, 0x4000):
        return n == register
    if top == 0x2000 and low in (4, 5, 6, 9, 10, 11, 12):
        return n == register
    return False


def has_control_flow(opcode: int) -> bool:
    if opcode & 0xF000 in (0xA000, 0xB000):
        return True
    if opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00):
        return True
    return opcode & 0xF0FF in (0x400B, 0x402B)


def classify_value_source(data: bytes, store_position: int, source_register: int,
                          alias_position: int) -> dict:
    """Recognize two observed local SH-2 source idioms without assuming reachability."""
    if source_register != 0:
        return {"kind": "unknown_register"}

    # SP+20 := (byte at SP+20) AND 0x3f. ADD #20,R1 lies between the
    # indexed byte load and AND; exact pre-store pattern avoids false matches.
    if store_position >= 10 and (
        be16(data, store_position - 2) == 0xC93F
        and be16(data, store_position - 6) == 0x00FC
        and be16(data, store_position - 10) == 0xE014
    ):
        return {"kind": "masked_stack_byte", "mask": 63, "source_stack_field": 20}

    # MOV.B @(disp,R4),R0: value comes from an offset in the input structure
    # pointed to by R4, not from a confirmed original asset container.
    for pos in range(store_position - 2, max(alias_position - 4, 0) - 1, -2):
        word = be16(data, pos)
        if word & 0xFFF0 == 0x8490:
            return {"kind": "input_R4_byte", "input_displacement": word & 0xF}
        if word & 0xF000 == 0xE000 and (word >> 8) & 15 == 0:
            break
        if has_control_flow(word):
            break
    return {"kind": "unknown_register"}


def stack_alias_writes(data: bytes, start: int, end: int) -> list[dict]:
    """Identify MOV R15,Rn; ADD #imm,Rn; MOV.B/W/L Rm,@Rn paths.

    The scanner rejects a known alias-register overwrite or branch in the
    bounded window. This is a static candidate list, not emulator execution.
    """
    results: dict[int, dict] = {}
    if start < 0 or end > len(data) or start >= end:
        return []
    for alias_pos in range(start, end - 2, 2):
        instruction = be16(data, alias_pos)
        if instruction & 0xF0FF != 0x60F3:
            continue
        base_reg = (instruction >> 8) & 0xF
        if base_reg == 15:
            continue
        for add_pos in range(alias_pos + 2, min(alias_pos + 18, end - 1), 2):
            add_op = be16(data, add_pos)
            if add_op & 0xFF00 == 0x7000 | (base_reg << 8):
                displacement = add_op & 0xFF
                if displacement & 0x80:
                    displacement -= 0x100
                if displacement < 0:
                    continue
                for store_pos in range(add_pos + 2, min(add_pos + 32, end - 1), 2):
                    store_op = be16(data, store_pos)
                    if (store_op & 0xF00F == 0x2000
                            and (store_op >> 8) & 0xF == base_reg):
                        width = {0: 1, 1: 2, 2: 4}[store_op & 0xF]
                        source_reg = (store_op >> 4) & 0xF
                        results[store_pos] = {
                            "store_position": store_pos,
                            "stack_field": displacement,
                            "width": width,
                            "value_source": classify_value_source(
                                data, store_pos, source_reg, alias_pos),
                        }
                    if overwrites_register(store_op, base_reg) or has_control_flow(store_op):
                        break
            if overwrites_register(add_op, base_reg) or has_control_flow(add_op):
                break
    return list(results.values())


def summarize_alias_provenance(data: bytes) -> dict:
    chains = matching_stack_source_chains(data)
    all_sites: dict[int, dict] = {}
    with_frame = 0
    for chain in chains:
        before = chain["block_start"] - 26
        frame = find_frame(data, before)
        if frame is None:
            continue
        with_frame += 1
        for item in stack_alias_writes(data, frame + 2, before):
            all_sites[item["store_position"]] = item

    records = list(all_sites.values())
    counts = {
        f"SP+{field}": sum(
            item["stack_field"] <= field < item["stack_field"] + item["width"]
            for item in records
        )
        for field in STACK_FIELDS
    }
    r4_byte_inputs = {
        f"SP+{field}": sorted({
            item["value_source"]["input_displacement"]
            for item in records
            if item["stack_field"] <= field < item["stack_field"] + item["width"]
            and item["value_source"]["kind"] == "input_R4_byte"
        })
        for field in STACK_FIELDS
    }
    masked_rewrites = sum(
        item["stack_field"] == 20
        and item["value_source"]["kind"] == "masked_stack_byte"
        and item["value_source"]["mask"] == 63
        for item in records
    )
    return {
        "stage21_stack_source_chains": len(chains),
        "chains_with_88_byte_frame": with_frame,
        "stack_alias_store_candidates": len(records),
        "stack_alias_stores_by_field": counts,
        "source_bytes_from_R4_input_displacements": r4_byte_inputs,
        "conditional_masked_rewrites_of_first_factor": masked_rewrites,
        "masked_first_factor_max_when_rewrite_executes": 63 if masked_rewrites else None,
        "interpretation": (
            "Temporary aliases of R15 show writes to both factors that the earlier "
            "strict direct-store audit could not detect. The input displacement "
            "values refer to data pointed to by R4, not verified game resources. "
            "A separate path masks the first factor with 0x3f; it must not be "
            "assumed to run on all game paths."
        ),
        "limitations": [
            "Narrow sequential SH-2 pattern matching cannot prove control-flow reachability.",
            "Calls, computed pointers and other register writes may create additional paths.",
            "R4 origin, stack-slot runtime values and actual copy-budget invariant are unknown.",
            "Stack displacements are semantic memory offsets, not game binary positions.",
            "No original program offsets, code bytes, textures, audio or video are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage23_vdp1_stack_alias_provenance",
        "target_file": "0TH2.BIN",
        "analysis": summarize_alias_provenance(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    output = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
