#!/usr/bin/env python3
"""Stage85: root-file census for direct service-slot references and writers.

Scans root files up to a conservative size cap. Raw byte matches and bounded
store candidates are not proof of runtime pointer registration or execution.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16
from stage35_table_tail_link import movl_literal
from stage79_expanded_store_alias_audit import scan_store_aliases

SECTOR = 2048
MAX_FILE_SIZE = 5 * 1024 * 1024
SERVICE_SLOT_A = 0x06000300
SERVICE_SLOT_B = 0x06000310


def _raw_alignment_summary(data: bytes, value: int) -> dict:
    needle = value.to_bytes(4, "big")
    positions = []
    start = 0
    while True:
        start = data.find(needle, start)
        if start < 0:
            break
        positions.append(start)
        start += 1
    literal_pool_positions = set()
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is not None:
            literal_pool_positions.add(literal[0])
    return {
        "raw_big_endian_occurrences": len(positions),
        "occurrences_aligned_to_halfword": sum(pos % 2 == 0 for pos in positions),
        "occurrences_aligned_to_longword": sum(pos % 4 == 0 for pos in positions),
        "occurrences_used_as_pc_literal_pool_words": sum(
            pos in literal_pool_positions for pos in positions
        ),
    }


def summarize_payload(data: bytes) -> dict:
    slot_a_refs = 0
    slot_b_refs = 0
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None:
            continue
        if literal[1] == SERVICE_SLOT_A:
            slot_a_refs += 1
        elif literal[1] == SERVICE_SLOT_B:
            slot_b_refs += 1
    slot_a_writes = scan_store_aliases(data, SERVICE_SLOT_A)
    slot_b_writes = scan_store_aliases(data, SERVICE_SLOT_B)
    return {
        "slot_a_pc_literal_load_sites": slot_a_refs,
        "slot_b_pc_literal_load_sites": slot_b_refs,
        "slot_a_bounded_store_candidates": slot_a_writes[
            "exact_target_store_candidates"
        ],
        "slot_b_bounded_store_candidates": slot_b_writes[
            "exact_target_store_candidates"
        ],
        "slot_a_raw_occurrences": _raw_alignment_summary(
            data, SERVICE_SLOT_A
        ),
        "slot_b_raw_occurrences": _raw_alignment_summary(
            data, SERVICE_SLOT_B
        ),
        "all_slot_writers_resolved": False,
    }


def read_small_root_files(image: Path, max_file_size: int = MAX_FILE_SIZE) -> dict:
    """Read only root files below a conservative limit, keeping bytes local."""
    image_size = image.stat().st_size
    with image.open("rb") as stream:
        stream.seek(16 * SECTOR)
        pvd = stream.read(SECTOR)
        if pvd[:7] != b"\x01CD001\x01":
            raise ValueError("Not a supported ISO9660 volume")
        root_extent = int.from_bytes(pvd[158:162], "little")
        root_length = int.from_bytes(pvd[166:170], "little")
        if root_extent * SECTOR + root_length > image_size:
            raise ValueError("Root directory out of bounds")
        stream.seek(root_extent * SECTOR)
        directory = stream.read(root_length)

        files = {}
        skipped_oversize = 0
        index = 0
        while index < len(directory):
            record_length = directory[index]
            if record_length == 0:
                index = (index // SECTOR + 1) * SECTOR
                continue
            record = directory[index:index + record_length]
            index += record_length
            if len(record) < 34 or record[32] == 0:
                continue
            name = record[33:33 + record[32]].split(b";")[0]
            if name in (b"\x00", b"\x01") or record[25] & 0x02:
                continue
            extent = int.from_bytes(record[2:6], "little")
            size = int.from_bytes(record[10:14], "little")
            if size > max_file_size:
                skipped_oversize += 1
                continue
            if extent * SECTOR + size > image_size:
                continue
            stream.seek(extent * SECTOR)
            payload = stream.read(size)
            if len(payload) == size:
                files[name.decode("ascii", "replace")] = payload
        return {
            "files": files,
            "root_file_count_scanned": len(files),
            "root_files_skipped_oversize": skipped_oversize,
            "max_file_size_bytes": max_file_size,
        }


def analyze(image: Path) -> dict:
    root = read_small_root_files(image)
    files = root["files"]
    per_file = {}
    total_a_refs = total_b_refs = 0
    total_a_writes = total_b_writes = 0
    raw_only_files = 0
    for name, data in files.items():
        result = summarize_payload(data)
        total_a_refs += result["slot_a_pc_literal_load_sites"]
        total_b_refs += result["slot_b_pc_literal_load_sites"]
        total_a_writes += result["slot_a_bounded_store_candidates"]
        total_b_writes += result["slot_b_bounded_store_candidates"]
        raw_a = result["slot_a_raw_occurrences"]["raw_big_endian_occurrences"]
        raw_b = result["slot_b_raw_occurrences"]["raw_big_endian_occurrences"]
        if (
            result["slot_a_pc_literal_load_sites"]
            or result["slot_b_pc_literal_load_sites"]
            or result["slot_a_bounded_store_candidates"]
            or result["slot_b_bounded_store_candidates"]
        ):
            per_file[name] = {
                "slot_a_pc_literal_load_sites": result["slot_a_pc_literal_load_sites"],
                "slot_b_pc_literal_load_sites": result["slot_b_pc_literal_load_sites"],
                "slot_a_bounded_store_candidates": result["slot_a_bounded_store_candidates"],
                "slot_b_bounded_store_candidates": result["slot_b_bounded_store_candidates"],
            }
        elif raw_a or raw_b:
            raw_only_files += 1

    low = files.get("TH2.LOW", b"")
    low_a = _raw_alignment_summary(low, SERVICE_SLOT_A)
    low_b = _raw_alignment_summary(low, SERVICE_SLOT_B)
    return {
        "schema_version": 1,
        "stage": "stage85_disc_slot_writer_census",
        "analysis": {
            "root_files_scanned_under_size_limit": root["root_file_count_scanned"],
            "root_files_skipped_over_size_limit": root["root_files_skipped_oversize"],
            "max_file_size_bytes": root["max_file_size_bytes"],
            "files_with_direct_pc_literal_refs_to_service_slots": per_file,
            "files_with_only_raw_slot_byte_matches": raw_only_files,
            "total_slot_a_pc_literal_load_sites": total_a_refs,
            "total_slot_b_pc_literal_load_sites": total_b_refs,
            "total_slot_a_bounded_store_candidates": total_a_writes,
            "total_slot_b_bounded_store_candidates": total_b_writes,
            "low_slot_a_raw_occurrences": low_a,
            "low_slot_b_raw_occurrences": low_b,
            "all_disc_files_scanned": False,
            "all_service_slot_writers_resolved": False,
            "runtime_pointer_registration_proven": False,
            "runtime_callback_execution_confirmed": False,
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
