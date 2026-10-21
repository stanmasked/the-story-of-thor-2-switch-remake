#!/usr/bin/env python3
"""Stage35: static function-table -> BRA tail-call -> wrapper -> field-reader chain.

Private Saturn ISO stays local. Only aggregate metadata is reported.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage30_field_consumer_audit import find_consumer_groups
from stage31_entry_guard_audit import candidate_prologue, field16_before_group

CODE_LOAD_BASE = 0x06004000
PUSH_R14, PUSH_PR = 0x2FE6, 0x4F22
PASS_R4_TO_R14, PASS_R14_TO_R4 = 0x6E43, 0x64E3
RESTORE_PR, RESTORE_R14, SLOT_R5_TWO = 0x4F26, 0x6EF6, 0xE502


def movl_literal(data: bytes, pos: int) -> tuple[int, int, int] | None:
    if pos < 0 or pos & 1 or pos + 2 > len(data):
        return None
    word = be16(data, pos)
    if word & 0xF000 != 0xD000:
        return None
    loc = ((pos + 4) & ~3) + (word & 0xFF) * 4
    if loc + 4 > len(data):
        return None
    return loc, int.from_bytes(data[loc:loc + 4], "big"), (word >> 8) & 15


def branch_destination(pos: int, op: int) -> tuple[str, int] | None:
    if pos < 0 or pos & 1:
        return None
    if op & 0xF000 in (0xA000, 0xB000):
        disp = op & 0xFFF
        if disp & 0x800:
            disp -= 0x1000
        return ("BRA" if op & 0xF000 == 0xA000 else "BSR",
                pos + 4 + disp * 2)
    tag = {0x8900: "BT", 0x8B00: "BF", 0x8D00: "BT/S",
           0x8F00: "BF/S"}.get(op & 0xFF00)
    if tag:
        disp = op & 0xFF
        if disp & 0x80:
            disp -= 0x100
        return tag, pos + 4 + disp * 2
    return None


def extended_reader_entries(data: bytes) -> set[int]:
    result = set()
    for group in find_consumer_groups(data):
        if len(group["reads"]) != 6:
            continue
        first = group["reads"][0]["instruction_position"]
        prologue = candidate_prologue(data, first)
        if prologue and field16_before_group(data, prologue["entry"], first):
            result.add(prologue["entry"])
    return result


def discover_inner_wrappers(data: bytes) -> list[dict]:
    readers = extended_reader_entries(data)
    result = []
    for load_pos in range(2, len(data) - 10, 2):
        if (be16(data, load_pos - 2) != PUSH_PR
                or be16(data, load_pos + 2) != 0x7FFC
                or be16(data, load_pos + 4) != 0x2F42
                or be16(data, load_pos + 8) != SLOT_R5_TWO):
            continue
        literal = movl_literal(data, load_pos)
        if literal is None:
            continue
        _, value, reg = literal
        if value not in {CODE_LOAD_BASE + entry for entry in readers}:
            continue
        if be16(data, load_pos + 6) != (0x400B | reg << 8):
            continue
        result.append({"entry": load_pos - 2,
                       "target_reader": value - CODE_LOAD_BASE})
    return result


def find_tail_callers(data: bytes, target: int) -> list[dict]:
    result = []
    for pos in range(4, len(data) - 4, 2):
        if branch_destination(pos, be16(data, pos)) != ("BRA", target):
            continue
        if (be16(data, pos - 4) != PASS_R14_TO_R4
                or be16(data, pos - 2) != RESTORE_PR
                or be16(data, pos + 2) != RESTORE_R14):
            continue
        for start in range(max(0, pos - 160), pos - 5, 2):
            if (be16(data, start) == PUSH_R14
                    and be16(data, start + 2) == PUSH_PR
                    and be16(data, start + 4) == PASS_R4_TO_R14):
                result.append({"tail_branch": pos, "entry": start,
                               "slot_restores_r14": True})
    # One link per tail-branch; if multiple candidate prologues choose nearest.
    return list({x["tail_branch"]: x for x in result}.values())


def find_table_runs(data: bytes, function: int,
                    min_items: int = 4) -> list[dict]:
    pointer = (CODE_LOAD_BASE + function).to_bytes(4, "big")
    results = []
    scan = 0
    while True:
        location = data.find(pointer, scan)
        if location < 0:
            break
        scan = location + 1
        if location % 4:
            continue

        def is_code_pointer(pos: int) -> bool:
            if pos < 0 or pos + 4 > len(data):
                return False
            val = int.from_bytes(data[pos:pos + 4], "big")
            return (CODE_LOAD_BASE <= val < CODE_LOAD_BASE + len(data)
                    and val % 2 == 0)

        start = location
        while start >= 4 and is_code_pointer(start - 4):
            start -= 4
        end = location + 4
        while is_code_pointer(end):
            end += 4
        size = (end - start) // 4
        if size >= min_items:
            results.append({"table_start": start, "table_end": end,
                            "entries": size,
                            "entry_index_zero_based": (location - start) // 4,
                            "entry_cell": location})
    return results


def pc_movl_refs(data: bytes, target_address: int) -> int:
    return sum(1 for pos in range(0, len(data) - 5, 2)
               if (literal := movl_literal(data, pos)) is not None
               and literal[1] == target_address)


def count_reference_words(data: bytes, target: int) -> dict:
    return {"big_endian": data.count(target.to_bytes(4, "big")),
            "little_endian": data.count(target.to_bytes(4, "little"))}


def disc_word_counts(image: Path, words: dict[str, int]) -> dict:
    needles = {(label, endian): value.to_bytes(4, endian)
               for label, value in words.items()
               for endian in ("big", "little")}
    result = {label: {"big_endian": 0, "little_endian": 0}
              for label in words}
    carry = b""
    with image.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            buf = carry + block
            for (label, endian), needle in needles.items():
                key = "big_endian" if endian == "big" else "little_endian"
                result[label][key] += buf.count(needle)
            carry = buf[-3:]
    return result


def summarize_references(data: bytes, image: Path | None = None) -> dict:
    wrappers = discover_inner_wrappers(data)
    paths = [(w, t) for w in wrappers
             for t in find_tail_callers(data, w["entry"])]
    tables = [(w, t, tab) for w, t in paths
              for tab in find_table_runs(data, t["entry"])]
    if tables:
        w, t, tab = max(tables, key=lambda item: item[2]["entries"])
        table_address = CODE_LOAD_BASE + tab["table_start"]
        cell_address = CODE_LOAD_BASE + tab["entry_cell"]
        details = {
            "full_function_table_to_tail_to_wrapper_chains": len(tables),
            "table_entry_count": tab["entries"],
            "tail_function_slot_one_based": tab["entry_index_zero_based"] + 1,
            "direct_bra_edges_into_inner_wrapper": sum(
                len(find_tail_callers(data, x["entry"])) for x in wrappers),
            "tail_bra_delay_slot_restores_r14": t["slot_restores_r14"],
            "tail_route_restores_pr_before_bra": True,
            "tail_route_copies_saved_r14_to_r4": True,
            "absolute_pointer_to_tail_in_executable":
                count_reference_words(data, CODE_LOAD_BASE + t["entry"]),
            "absolute_pointer_to_inner_wrapper_in_executable":
                count_reference_words(data, CODE_LOAD_BASE + w["entry"]),
            "table_base_address_occurrences":
                count_reference_words(data, table_address)["big_endian"],
            "table_entry_cell_address_occurrences":
                count_reference_words(data, cell_address)["big_endian"],
            "pc_relative_movl_refs_to_table_base":
                pc_movl_refs(data, table_address),
            "pc_relative_movl_refs_to_entry_cell":
                pc_movl_refs(data, cell_address),
        }
        if image is not None:
            details["disc_absolute_pointer_occurrences"] = disc_word_counts(
                image, {"tail_function": CODE_LOAD_BASE + t["entry"],
                        "inner_wrapper": CODE_LOAD_BASE + w["entry"]})
    else:
        details = {"full_function_table_to_tail_to_wrapper_chains": 0}
    return {
        "schema_version": 1,
        "stage": "stage35_table_tail_wrapper_chain",
        "target_file": "0TH2.BIN",
        "analysis": {**details, "limitations": [
            "Static pointer-table membership and BRA do not prove live dispatch.",
            "Unrecognized pointer encodings, address arithmetic and other modules may exist.",
            "A function pointer array is not evidence of VDP1 command output.",
            "Runtime pointer identity and actual gameplay reachability remain unverified.",
            "Only aggregate counts are reported; no proprietary program offsets or bytes.",
        ]},
    }


def analyze(image: Path) -> dict:
    return summarize_references(iso_file_payload(image), image)


def main():
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
