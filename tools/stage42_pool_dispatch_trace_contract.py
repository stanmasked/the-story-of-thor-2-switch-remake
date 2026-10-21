#!/usr/bin/env python3
"""Stage42: audit dispatch argument entry, and validate *supplied* trace events.

A synthetic trace can be self-consistent without reflecting real Saturn
execution. Never treat this checker alone as runtime/VDP1 confirmation.
Original Saturn ISO and program locations remain private.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import CODE_LOAD_BASE, movl_literal
from stage36_dispatch_index_audit import _pointer_table, match_indexed_dispatch
from stage41_pool_readers import pool_base

ENTRY_DISTANCE = {"table_start": 0x90, "selected_cell": 0xD0}
ENTRY_PROLOGUES = {
    "table_start": (0x2FE6, 0x6E43, 0x4F22),
    "selected_cell": (0x2FE6, 0x6E43, 0x2FD6, 0x2FC6, 0x4F22),
}
EXPECTED_SLOT_BYTES = 276
EXPECTED_SLOT_COUNT = 43
EXPECTED_FUNCTION_SLOT = 39


def signed12(value: int) -> int:
    val = value & 0xFFF
    return val - 4096 if val & 0x800 else val


def exact_entry_prologue(data: bytes, entry: int, anchor: str) -> bool:
    ops = ENTRY_PROLOGUES.get(anchor)
    if ops is None or entry < 0 or entry & 1 or entry + 2 * len(ops) > len(data):
        return False
    return all(be16(data, entry + 2*i) == opcode
               for i, opcode in enumerate(ops))


def direct_reference_counts(data: bytes, target: int) -> dict:
    """Raw, bounded SH-2 direct references. NOT an exhaustive call graph."""
    bsr = bra = conditional = literals = 0
    pointer = CODE_LOAD_BASE + target
    for pos in range(0, len(data) - 5, 2):
        op = be16(data, pos)
        if op & 0xF000 in (0xB000, 0xA000):
            dest = pos + 4 + 2 * signed12(op)
            if dest == target:
                if op & 0xF000 == 0xB000:
                    bsr += 1
                else:
                    bra += 1
        elif op & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00):
            disp = op & 0xFF
            if disp & 0x80:
                disp -= 256
            if pos + 4 + disp*2 == target:
                conditional += 1
        loaded = movl_literal(data, pos)
        if loaded is not None and loaded[1] == pointer:
            literals += 1
    return {"direct_bsr": bsr, "direct_bra": bra,
            "direct_conditional": conditional, "pc_literal_loads": literals}


def scan_dispatch_entries(data: bytes) -> dict:
    table = _pointer_table(data)
    pool = pool_base(data)
    if table is None or pool is None:
        return {
            "prerequisite_68_pointer_table_found": bool(table),
            "prerequisite_43_slot_pool_found": bool(pool),
            "matched_indexed_dispatches": 0,
            "entry_prologues_copy_R4_to_R14": 0,
            "pool_to_dispatch_pointer_identity_verified": False,
            "limitations": ["Missing Stage35/Stage41 static signature prerequisite."],
        }
    anchors = (
        ("table_start", CODE_LOAD_BASE + table["table_start"]),
        ("selected_cell", CODE_LOAD_BASE + table["entry_cell"]),
    )
    results = []
    for name, ptr in anchors:
        for pos in range(12, len(data) - 12, 2):
            if match_indexed_dispatch(data, pos, ptr) is None:
                continue
            entry = pos - ENTRY_DISTANCE[name]
            valid = exact_entry_prologue(data, entry, name)
            results.append({"anchor": name, "prologue_valid": valid,
                            "references": direct_reference_counts(data, entry)
                            if valid else None})
    valid = [x for x in results if x["prologue_valid"]]
    refs = [x["references"] for x in valid]
    return {
        "prerequisite_68_pointer_table_found": True,
        "prerequisite_43_slot_pool_found": True,
        "pool_records": pool[2],
        "pool_stride_bytes": pool[1],
        "function_table_entries": table["entries"],
        "matched_indexed_dispatches": len(results),
        "entry_prologues_copy_R4_to_R14": len(valid),
        "prologue_forms": sorted(x["anchor"] for x in valid),
        "static_direct_bsr_refs_to_entries": sum(r["direct_bsr"] for r in refs),
        "static_direct_bra_refs_to_entries": sum(r["direct_bra"] for r in refs),
        "static_conditional_refs_to_entries":
            sum(r["direct_conditional"] for r in refs),
        "static_pc_literal_refs_to_entries":
            sum(r["pc_literal_loads"] for r in refs),
        "pool_to_dispatch_pointer_identity_verified": False,
        "runtime_index_38_dispatch_observed": False,
        "limitations": [
            "R4-to-R14 at function entry does not identify the incoming R4 object.",
            "No literal/BSR/BRA references do not exclude computed/table callers.",
            "A compiler could branch into a procedure at another instruction.",
            "No live clone-object address has been observed at either dispatch.",
            "Original executable positions, program bytes and assets are not emitted.",
        ],
    }


def validate_trace_contract(events: object) -> dict:
    """Correlate *untrusted supplied events* by symbolic object ID and slot.

    Does not inspect a real emulator; caller is responsible for provenance
    and factual correctness of every event.
    """
    if not isinstance(events, list):
        return {"events_checked": 0, "trace_contract_consistent": False,
                "failure_code": "events_not_list",
                "runtime_proven_by_checker": False}
    state = 0
    obj = None
    slot = None
    error = None
    for event in events:
        if not isinstance(event, dict):
            error = "invalid_event"
            break
        kind = event.get("kind")
        if kind == "slot-selected" and state == 0:
            s = event.get("slot")
            oid = event.get("object_id")
            if (type(s) is not int or s < 0 or s >= EXPECTED_SLOT_COUNT
                    or not isinstance(oid, str) or not oid):
                error = "invalid_slot_or_identity"
                break
            obj, slot, state = oid, s, 1
        elif kind == "object-cloned" and state == 1:
            if (event.get("object_id") != obj
                    or event.get("slot") != slot
                    or type(event.get("copied_bytes")) is not int
                    or event["copied_bytes"] != EXPECTED_SLOT_BYTES):
                error = "copy_identity_or_size_mismatch"
                break
            state = 2
        elif kind == "index-written" and state == 2:
            if (event.get("object_id") != obj or event.get("slot") != slot
                    or event.get("field_offset") != 126
                    or event.get("index") != 38):
                error = "index_writer_mismatch"
                break
            state = 3
        elif kind == "table-dispatched" and state == 3:
            anchor = event.get("anchor")
            index = event.get("index")
            expected = (38 if anchor == "table_start" else 0
                        if anchor == "selected_cell" else None)
            if (event.get("object_id") != obj
                    or event.get("slot") != slot
                    or type(index) is not int
                    or expected is None or index != expected
                    or event.get("selected_slot_one_based") != EXPECTED_FUNCTION_SLOT):
                error = "dispatch_identity_or_table_mismatch"
                break
            state = 4
        else:
            error = "invalid_event_order"
            break
    if error is None and state != 4:
        error = "incomplete_trace"
    return {
        "events_checked": len(events),
        "trace_contract_consistent": error is None,
        "matched_clone_to_slot39_dispatch_sequence": error is None,
        "failure_code": error,
        "runtime_proven_by_checker": False,
        "note": "Consistency is not emulator provenance or verified runtime execution.",
    }


def analyze(image: Path, trace_path: Path | None = None) -> dict:
    result = {"schema_version": 1,
              "stage": "stage42_pool_to_dispatch_trace_contract",
              "target_file": "0TH2.BIN",
              "static_analysis": scan_dispatch_entries(iso_file_payload(image))}
    if trace_path is not None:
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        events = trace.get("events") if isinstance(trace, dict) else trace
        result["supplied_trace_consistency"] = validate_trace_contract(events)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--trace-json", type=Path,
                        help="Optional PRIVATE externally captured event log")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(args.image, args.trace_json),
                        ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
