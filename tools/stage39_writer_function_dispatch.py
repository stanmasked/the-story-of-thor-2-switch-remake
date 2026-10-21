#!/usr/bin/env python3
"""Stage39: resolve function-table dispatch to the constant-38 writer.

Static SH-2 evidence only. The Saturn ISO stays private; output is aggregate
structure and register provenance metadata, never executable offsets.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import CODE_LOAD_BASE, find_table_runs, movl_literal
from stage38_constant_index_writer import candidate_store_pairs, exact_slot39_writer

WRITER_PROLOGUE = (0x2FE6, 0x2FD6, 0x2FC6, 0x6D43)
DISPATCH_SUFFIX = (0xE07E, 0x03DD, None, 0x4308, 0x023E, 0x420B, 0x64D3)
POINTER_HELPER_SEGMENT = {
    0x6A: 0x430B,  # JSR @R3
    0x6C: 0x0009,  # JSR delay slot NOP
    0x6E: 0x2008,  # TST R0,R0
    0x70: 0x8F02,  # BF/S nonzero branch
    0x72: 0x6E03,  # MOV R0,R14 in BF/S delay slot
    0x74: 0xA0C4,  # BRA past successful initialization
    0x76: 0x0009,  # BRA delay slot NOP
    0x7A: 0x65E3,  # MOV R14,R5
    0x7C: 0x430B,  # JSR @R3
    0x7E: 0x64D3,  # MOV R13,R4 in JSR delay slot
    0x80: 0x84E7,  # MOV.B @(7,R14),R0
}


def signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def find_writer_entries(data: bytes) -> list[dict]:
    """Pair Stage38's exact local writer with the nearest supported prologue."""
    out = []
    for pair in candidate_store_pairs(data, 14):
        store = pair["position"]
        if not exact_slot39_writer(data, store):
            continue
        for entry in range(store - 2, max(-2, store - 0x122), -2):
            if entry < 0 or entry + 8 > len(data):
                continue
            if all(be16(data, entry + 2*i) == op
                   for i, op in enumerate(WRITER_PROLOGUE)):
                out.append({"entry": entry, "store": store,
                            "entry_argument_saved_in_R13": True})
                break
    return out


def match_table_dispatch(data: bytes, location: int,
                         table_start: int) -> bool:
    """Check signed word [R13+126], *4, PC table base and JSR @R2."""
    if location < 0 or location & 1 or location + 14 > len(data):
        return False
    if any(be16(data, location + 2*i) != op
           for i, op in enumerate(DISPATCH_SUFFIX) if op is not None):
        return False
    literal = movl_literal(data, location + 4)
    return (literal is not None and literal[2] == 0
            and literal[1] == CODE_LOAD_BASE + table_start)


def indexed_dispatch_sites(data: bytes, table_start: int) -> list[int]:
    return [p for p in range(0, len(data) - 13, 2)
            if match_table_dispatch(data, p, table_start)]


def validate_returned_object(data: bytes, entry: int) -> dict | None:
    """Verify R0 -> R14 nonzero BF/S delay-slot path; not a runtime alias proof."""
    if entry < 0 or entry & 1 or entry + 0x90 > len(data):
        return None
    if any(be16(data, entry + offset) != op
           for offset, op in POINTER_HELPER_SEGMENT.items()):
        return None
    if (be16(data, entry + 0x68) & 0xFF00 != 0xD300
            or be16(data, entry + 0x78) & 0xFF00 != 0xD300):
        return None
    first = movl_literal(data, entry + 0x68)
    second = movl_literal(data, entry + 0x78)
    if (first is None or second is None
            or first[2] != 3 or second[2] != 3
            or not all(CODE_LOAD_BASE <= item[1] < CODE_LOAD_BASE + len(data)
                       for item in (first, second))):
        return None
    return {"nonzero_branch": True, "captured_register": "R14",
            "result_register": "R0",
            "intervening_indirect_jsr": True}


def summarize_writer_dispatch(data: bytes) -> dict:
    chains = []
    for writer in find_writer_entries(data):
        for table in find_table_runs(data, writer["entry"]):
            sites = indexed_dispatch_sites(data, table["table_start"])
            if sites:
                chains.append({
                    "writer": writer, "table": table, "sites": sites,
                    "returned": validate_returned_object(data, writer["entry"])
                })
    if not chains:
        return {
            "complete_indexed_dispatch_to_constant_writer_chains": 0,
            "writer_and_later_68_entry_dispatch_object_alias_verified": False,
            "limitations": [
                "No complete table-to-writer dispatch signature found.",
                "No original program positions or game assets are output."
            ],
        }
    one = max(chains, key=lambda item: item["table"]["entries"])
    table = one["table"]
    origin = one["returned"]
    return {
        "complete_indexed_dispatch_to_constant_writer_chains": len(chains),
        "contiguous_code_pointer_run_entries": table["entries"],
        "writer_slot_one_based": table["entry_index_zero_based"] + 1,
        "signed_index_required_from_start": table["entry_index_zero_based"],
        "indirect_jsr_dispatch_sites_for_run": len(one["sites"]),
        "dispatch_index_source": "signed16(memory[R13+126])",
        "index_scaled_by_four": True,
        "dispatch_argument": "R4=R13 in JSR delay slot",
        "writer_entry_argument_saved_in_R13":
            one["writer"]["entry_argument_saved_in_R13"],
        "writer_stores_constant_38_in_word_R14_plus_126": True,
        "nonzero_R0_result_captured_in_R14_via_BF_S_delay_slot": bool(origin),
        "helper_call_between_R14_capture_and_index_write":
            bool(origin and origin["intervening_indirect_jsr"]),
        "writer_and_later_68_entry_dispatch_object_alias_verified": False,
        "writer_and_dispatcher_runtime_execution_verified": False,
        "mathematical_index_bounds_from_start": [0, table["entries"] - 1],
        "interpretation": (
            "A signed word at R13+126 indexes a contiguous run of code "
            "pointers. JSR passes R13 as R4 to the constant-38 writer. "
            "Its incoming R4 is saved as R13, while a nonzero helper result "
            "R0 is transferred into R14 in a BF/S delay slot. Constant 38 "
            "is later written through R14, not directly through the original "
            "R13. Runtime aliasing to the 68-entry table remains unproven."
        ),
        "limitations": [
            "The contiguous code-pointer run may represent multiple logical arrays.",
            "Mathematical index bounds are not confirmed runtime guards.",
            "An intervening indirect JSR may affect registers.",
            "The returned object's identity and lifetime are unknown.",
            "Static callsites do not prove execution or VDP1 command emission.",
            "No original code positions, machine bytes or game assets are output.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1, "stage": "stage39_writer_function_dispatch",
        "target_file": "0TH2.BIN",
        "analysis": summarize_writer_dispatch(iso_file_payload(image)),
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
        print(rendered)


if __name__ == "__main__":
    main()
