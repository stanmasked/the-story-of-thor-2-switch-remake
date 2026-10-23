#!/usr/bin/env python3
"""Stage75: conservative audit of indirect service-slot write candidates.

Original Saturn ISO stays local. Report emits only counts and explicit
uncertainty; a PC-relative store candidate does not establish the stored
function pointer's origin, reachability, or runtime execution.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal

SERVICE_SLOTS = (0x06000300, 0x06000310)


def scan_slot_writes(data: bytes, slot: int, window: int = 16) -> dict:
    loads, store_candidates = 0, set()
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None or literal[1] != slot:
            continue
        loads += 1
        pointer_reg = literal[2]
        for next_pos in range(pos + 2, min(len(data) - 1, pos + 2 + window * 2), 2):
            opcode = be16(data, next_pos)
            # MOV.L Rm,@Rn: 0010 nnnn mmmm 0010
            if opcode & 0xF00F == 0x2002 and (opcode >> 8) & 15 == pointer_reg:
                store_candidates.add(next_pos)
                break
            # A control transfer breaks our strictly linear evidence. Delay
            # slots and indirect pointers are intentionally not inferred.
            if opcode & 0xF000 in (0xA000, 0xB000) or opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00) or opcode & 0xF0FF in (0x400B, 0x402B):
                break
            # Overwrite of pointer register invalidates the candidate.
            n = (opcode >> 8) & 15
            if n == pointer_reg and opcode >> 12 in (0x6, 0x7, 0x9, 0xD, 0xE):
                break
    return {
        "pointer_literal_loads": loads,
        "bounded_direct_longword_store_candidates": len(store_candidates),
        "all_writers_proven": False,
        "stored_function_pointer_values_proven": False,
        "runtime_invocation_confirmed": False,
    }


def summarize(data: bytes) -> dict:
    slots = [scan_slot_writes(data, slot) for slot in SERVICE_SLOTS]
    return {
        "schema_version": 1,
        "stage": "stage75_indirect_service_slots",
        "slot_count": len(slots),
        "total_pc_literal_loads": sum(s["pointer_literal_loads"] for s in slots),
        "total_bounded_direct_store_candidates": sum(s["bounded_direct_longword_store_candidates"] for s in slots),
        "slot_results": slots,
        "all_service_writers_resolved": False,
        "runtime_dma_completion_confirmed": False,
        "private_addresses_or_offsets_emitted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(summarize(iso_file_payload(args.image)), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")


if __name__ == "__main__":
    main()
