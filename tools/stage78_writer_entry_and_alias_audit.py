#!/usr/bin/env python3
"""Stage78: bounded SH-2 audit of length-writer callers and literal aliases.

Only aggregate counts and explicit proof limits are emitted. Matching code
references are static evidence, not runtime call order or DMA completion.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage46_vdp1_submit_gate import find_submit_gates
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import LENGTH_SOURCE_GLOBAL
from stage76_length_field_feedback_cfg import (
    _find_routine_prologues,
    _find_source_writer_sites,
)


def _is_control_transfer(opcode: int) -> bool:
    return (
        opcode >> 12 in (0xA, 0xB)
        or opcode in (0x000B, 0x002B)
        or opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00)
        or opcode & 0xF0FF in (0x400B, 0x402B)
    )


def _is_word_store_at(opcode: int, pointer_reg: int) -> bool:
    return (
        opcode & 0xF00F == 0x2001
        and ((opcode >> 8) & 15) == pointer_reg
    )


def _is_pointer_clobber(opcode: int, pointer_reg: int) -> bool:
    destination = (opcode >> 8) & 15
    group = opcode >> 12
    return destination == pointer_reg and group in (0x6, 0x9, 0xD, 0xE)


def scan_literal_alias_writes(
    data: bytes,
    address: int,
    radius: int = 64,
    max_steps: int = 24,
) -> dict:
    """Bounded straight-line ADD #imm and MOV.W store recognition.

    Includes the delay slot of a terminal branch. Does not infer pointer
    arithmetic through arbitrary registers, loops, or indirect RAM aliases.
    """
    load_sites = 0
    stores: dict[int, bool] = {}
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None:
            continue
        _, initial, register = literal
        if abs(initial - address) > radius:
            continue
        load_sites += 1
        current = initial
        for step in range(1, max_steps + 1):
            q = pos + 2 * step
            if q + 2 > len(data):
                break
            opcode = be16(data, q)
            if _is_word_store_at(opcode, register):
                if current == address:
                    stores[q] = stores.get(q, False) or (initial != address)
                break
            if opcode >> 12 == 0x7 and (opcode >> 8) & 15 == register:
                immediate = opcode & 255
                if immediate & 128:
                    immediate -= 256
                current = (current + immediate) & 0xFFFFFFFF
                continue
            if _is_control_transfer(opcode):
                delay = q + 2
                if delay + 2 <= len(data):
                    if _is_word_store_at(be16(data, delay), register) and current == address:
                        stores[delay] = stores.get(delay, False) or (initial != address)
                break
            if _is_pointer_clobber(opcode, register):
                break
    return {
        "nearby_literal_pointer_load_candidates": load_sites,
        "bounded_word_store_candidates": len(stores),
        "additive_alias_word_store_candidates": sum(stores.values()),
        "indirect_or_arbitrary_register_alias_writes_excluded": False,
        "global_writer_census_exhaustive": False,
    }


def audit_writer_callers(
    data: bytes,
    entry: int | None,
    gate_entry: int | None,
    max_nearby: int = 128,
) -> dict:
    if entry is None or entry < 0 or entry + 2 > len(data):
        return {
            "writer_routine_literal_references": 0,
            "literal_backed_jsr_callsites": 0,
            "literal_backed_jsr_nop_delay_slots": 0,
            "direct_bsr_to_writer_entry_candidates": 0,
            "direct_bra_to_writer_entry_candidates": 0,
            "nearby_callsite_before_submit_gate": False,
            "nearby_callsite_separated_from_gate_by_rts": False,
            "runtime_execution_order_proven": False,
            "alternative_entry_points_excluded": False,
        }

    address = CODE_LOAD_ADDRESS + entry
    refs = 0
    calls: set[int] = set()
    nop_delays = 0
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None or literal[1] != address:
            continue
        refs += 1
        register = literal[2]
        if pos + 6 > len(data):
            continue
        if be16(data, pos + 2) == (0x400B | register << 8):
            calls.add(pos + 2)
            nop_delays += be16(data, pos + 4) == 0x0009

    bsr = bra = 0
    for pos in range(0, len(data) - 1, 2):
        opcode = be16(data, pos)
        if opcode >> 12 not in (0xA, 0xB):
            continue
        target = branch_destination(pos, opcode)
        if target == ("BSR", entry):
            bsr += 1
        elif target == ("BRA", entry):
            bra += 1

    nearby = [
        call for call in calls
        if gate_entry is not None
        and call + 4 <= gate_entry <= call + max_nearby
    ]
    separated = [
        call for call in nearby
        if any(be16(data, pos) == 0x000B
               for pos in range(call + 4, gate_entry, 2))
    ]
    return {
        "writer_routine_literal_references": refs,
        "literal_backed_jsr_callsites": len(calls),
        "literal_backed_jsr_nop_delay_slots": nop_delays,
        "direct_bsr_to_writer_entry_candidates": bsr,
        "direct_bra_to_writer_entry_candidates": bra,
        "nearby_callsite_before_submit_gate": bool(nearby),
        "nearby_callsite_separated_from_gate_by_rts": bool(separated),
        "runtime_execution_order_proven": False,
        "alternative_entry_points_excluded": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    prologues = _find_routine_prologues(data)
    r10_sites, r13_reads = _find_source_writer_sites(data)
    targets = r10_sites + r13_reads
    candidates = [
        entry for entry in prologues
        if targets and entry < min(targets)
    ]
    writer_entry = max(candidates) if candidates else None
    gates = find_submit_gates(data)
    gate_entry = gates[0]["start"] if len(gates) == 1 else None
    return {
        "schema_version": 1,
        "stage": "stage78_writer_entry_and_alias_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            "containing_routine_prologue_unique": len(prologues) == 1,
            "length_writer_sites_recognized": len(r10_sites),
            "length_feedback_read_sites_recognized": len(r13_reads),
            "unique_submit_gate_signature": len(gates) == 1,
            **audit_writer_callers(data, writer_entry, gate_entry),
            **scan_literal_alias_writes(data, LENGTH_SOURCE_GLOBAL),
            "length_source_initialized_before_first_callback_proven": False,
            "global_length_upper_bound_proven": False,
            "runtime_dma_completion_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
