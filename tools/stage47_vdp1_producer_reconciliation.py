#!/usr/bin/env python3
"""Stage47: reconcile an older VDP1 descriptor-writer candidate with Stage46 gate.

This is a bounded static SH-2 cross-check, not a CFG, execution trace, or
proof that the producer writes the same runtime object as the submitter.
Outputs only aggregate metadata (no private addresses/offsets/code bytes).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage15_vdp1_callsite_probe import (
    DESCRIPTOR_BUFFER_ADDRESS, TOTAL_RECORD_COUNT_ADDRESS,
    BUFFER_POINTER_SLOT_ADDRESS, is_control_flow, writes_register,
)
from stage16_vdp1_descriptor_writer_probe import descriptor_writer_candidates
from stage17_writer_callsite_audit import writer_guard_positions
from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal
from stage46_vdp1_submit_gate import bt_target, find_submit_gates

MAX_LOOKAHEAD_BYTES = 24


def _store_registers(op: int, width: str) -> tuple[int, int] | None:
    """Decode only MOV.B/W Rm,@Rn, not indexed or post-increment forms."""
    low = 0 if width == "byte" else 1
    if op & 0xF00F != 0x2000 | low:
        return None
    return (op >> 8) & 15, (op >> 4) & 15  # pointer Rn, data Rm


def _immediate_value_before(data: bytes, load: int, store: int,
                            source: int, pointer: int) -> int | None:
    """Infer a value only from nearby straight-line MOV #imm,Rm.

    This deliberately does not infer values through branches or arithmetic.
    """
    if source == pointer:
        return None
    first = max(0, load - 4)
    found = None
    for p in range(first, store, 2):
        op = be16(data, p)
        if is_control_flow(op):
            found = None
            continue
        if op & 0xF000 == 0xE000 and ((op >> 8) & 15) == source:
            imm = op & 255
            found = imm - 256 if imm & 128 else imm
        elif writes_register(op, source):
            found = None
    return found


def direct_store_candidates(data: bytes, target: int, width: str) -> list[dict]:
    """Follow a literal-loaded base register through a short branch-free window.

    Results are *syntactic candidates*. Dynamic aliases, data mistaken for code,
    and unmodelled instructions can prevent a proof of producer ownership.
    """
    stores = {}
    for p in range(0, len(data) - 5, 2):
        literal = movl_literal(data, p)
        if literal is None or literal[1] != target:
            continue
        pointer = literal[2]
        for q in range(p + 2, min(len(data) - 1, p + MAX_LOOKAHEAD_BYTES + 2), 2):
            op = be16(data, q)
            dst_src = _store_registers(op, width)
            if dst_src is not None and dst_src[0] == pointer:
                imm = _immediate_value_before(data, p, q, dst_src[1], pointer)
                stores[q] = {"position": q, "immediate": imm}
            if is_control_flow(op) or writes_register(op, pointer):
                break
    return list(stores.values())


def counter_increment_patterns(data: bytes, target: int) -> int:
    """MOV.L PC,R3; MOV.W @R3,R1; ADD #1,R1; MOV.W R1,@R3."""
    matches = 0
    for p in range(0, len(data) - 7, 2):
        lit = movl_literal(data, p)
        if (lit is not None and lit[1] == target and lit[2] == 3
                and be16(data, p+2) == 0x6131
                and be16(data, p+4) == 0x7101
                and be16(data, p+6) == 0x2311):
            matches += 1
    return matches


def capacity_branch_skips_minimal_writer(data: bytes, guard: int) -> bool:
    """Verify BT skips a nearby pointer advance, not just any BT opcode.

    The older Stage16 recognizer checks a CMP/GE and BT but not its target.
    This check proves only one local branch relationship, not runtime safety.
    """
    if guard < 0 or guard + 10 > len(data):
        return False
    target = bt_target(guard + 8, be16(data, guard + 8))
    if target is None or target <= guard or target > len(data):
        return False
    for p in range(guard + 10, min(len(data) - 5, guard + 114), 2):
        if (be16(data, p) == 0x6382 and be16(data, p+2) == 0x7308
                and be16(data, p+4) == 0x2832):
            return target >= p + 6
    return False


def summarize(data: bytes) -> dict:
    gates = find_submit_gates(data)
    producers = descriptor_writer_candidates(data)
    guards = writer_guard_positions(data) if producers else []
    matching_source = [g for g in gates if g["source_address"] == DESCRIPTOR_BUFFER_ADDRESS]
    matching_count = [g for g in gates if g["count_address"] == TOTAL_RECORD_COUNT_ADDRESS]
    matching_pointer = [g for g in gates if g["last_submitted_pointer_address"] == BUFFER_POINTER_SLOT_ADDRESS]
    all_three = [g for g in gates if
                 g["source_address"] == DESCRIPTOR_BUFFER_ADDRESS and
                 g["count_address"] == TOTAL_RECORD_COUNT_ADDRESS and
                 g["last_submitted_pointer_address"] == BUFFER_POINTER_SLOT_ADDRESS]
    flag_stores = direct_store_candidates(data, gates[0]["status_address"], "byte") if gates else []
    # Stage46 itself writes zero after checking the flag. Count separately.
    gate_clear_positions = {g["start"]+0x10 for g in gates}
    external_flag = [s for s in flag_stores if s["position"] not in gate_clear_positions]
    count_stores = direct_store_candidates(data, TOTAL_RECORD_COUNT_ADDRESS, "word") if gates else []
    verified_guard_branches = sum(capacity_branch_skips_minimal_writer(data, p) for p in guards)
    return {
        "stage46_submit_gates": len(gates),
        "stage16_descriptor_writer_candidates": len(producers),
        "submit_gates_sharing_stage15_buffer_address": len(matching_source),
        "submit_gates_sharing_stage15_count_address": len(matching_count),
        "submit_gates_sharing_stage15_pointer_slot": len(matching_pointer),
        "submit_gates_matching_all_three_addresses": len(all_three),
        "static_cross_stage_candidate": bool(producers and all_three),
        "descriptor_layout_width_bytes": 8 if producers and all_three else None,
        "stage16_capacity_comparison_literal": producers[0]["capacity_entries"] if producers else None,
        "capacity_branch_locally_skips_pointer_advance_candidates": verified_guard_branches,
        "capacity_bound_enforced_on_all_runtime_paths": False,
        "byte_status_direct_store_candidates": len(flag_stores),
        "byte_status_gate_clear_stores": sum(s["position"] in gate_clear_positions for s in flag_stores),
        "byte_status_other_direct_store_candidates": len(external_flag),
        "byte_status_other_negative_immediate_candidates": sum(
            s["immediate"] is not None and s["immediate"] < 0 for s in external_flag),
        "byte_status_other_nonnegative_immediate_candidates": sum(
            s["immediate"] is not None and s["immediate"] >= 0 for s in external_flag),
        "pending_count_direct_word_store_candidates": len(count_stores),
        "pending_count_exact_increment_patterns": counter_increment_patterns(data, TOTAL_RECORD_COUNT_ADDRESS) if gates else 0,
        "producer_identity_by_runtime_pointer_alias_proven": False,
        "producer_to_gate_control_flow_proven": False,
        "record_count_vs_per_descriptor_copy_count_reconciled": False,
        "handler_39_to_vdp1_proven": False,
        "actual_saturn_execution_captured": False,
        "interpretation": (
            "Compares the newly located Stage46 gate with the pre-existing "
            "Stage15/16 staging-buffer addresses and descriptor-writer signature. "
            "Also counts strictly bounded candidate stores to the status flag "
            "and pending count, and separately checks whether the Stage16 "
            "capacity branch skips its local pointer-advance sequence. "
            "Cross-stage address agreement is evidence, not a complete alias/CFG proof."
        ),
        "limitations": [
            "Stage16 has a candidate descriptor writer, not a proven runtime call path.",
            "Matching absolute addresses do not prove every pointer alias or execution order.",
            "A 512-entry comparison is not a general proof of buffer bounds.",
            "Local byte/word-store scans may miss indirect, indexed or computed stores.",
            "No live VDP1 trace, decoded sprites, or Nintendo Switch executable exists.",
            "No original offsets, RAM addresses, machine bytes or game resources are exported.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version": 1, "stage": "stage47_vdp1_producer_reconciliation",
            "target_file": "0TH2.BIN", "analysis": summarize(iso_file_payload(image))}


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
