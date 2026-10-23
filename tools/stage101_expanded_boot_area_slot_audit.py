#!/usr/bin/env python3
"""Stage101: targeted low-memory slot scan of oversized ISO containers.

The ISO is read locally and never modified. Large payloads are scanned for the
exact slot byte sequence and SH-2 PC-relative MOV.L references only; this is
not a full disassembly or a claim that compressed resources are executable.
Output is aggregate-only and emits no private addresses, offsets, or bytes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage35_table_tail_link import movl_literal
from stage75_indirect_services_count_provenance import MAX_FILE_SIZE
from stage86_set_module_signature_audit import read_root_payloads
from stage100_low_memory_service_slot_provenance import _discover_service_slot

SECTOR_SIZE = 2048
EXPECTED_LARGE_CONTAINERS = {"CPK0.BIN", "CPK1.BIN", "CPK2.BIN"}


def _pc_literal_reference_count(data: bytes, target: int) -> int:
    """Count aligned MOV.L @(disp,PC),Rn instructions whose literal equals target."""
    count = 0
    for pos in range(0, max(0, len(data) - 5), 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == target:
            count += 1
    return count


def _scan_container(data: bytes, target: int) -> dict:
    """Return only aggregate matches; never retain or emit the scanned payload."""
    return {
        "size_bytes": len(data),
        "exact_pointer_byte_sequence_occurrences": data.count(
            target.to_bytes(4, "big")
        ),
        "pc_relative_literal_reference_count": _pc_literal_reference_count(
            data, target
        ),
        "full_code_disassembly_performed": False,
    }


def analyze(image: Path) -> dict:
    root = read_root_payloads(image, max_file_size=MAX_FILE_SIZE)
    payloads = root["payloads"]
    target = _discover_service_slot(payloads)
    if target is None:
        return {
            "schema_version": 1,
            "stage": "stage101_expanded_boot_area_slot_audit",
            "analysis": {
                "stage100_service_slot_recovered": False,
                "oversized_container_scan_performed": False,
                "slot_value_resolved_from_disc": False,
                "private_addresses_or_code_offsets_emitted": False,
            },
        }

    oversized = [
        (name, extent, size)
        for name, extent, size in root["entries"]
        if size > MAX_FILE_SIZE
    ]
    summaries = []
    with image.open("rb") as stream:
        for name, extent, size in oversized:
            stream.seek(extent * SECTOR_SIZE)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Truncated oversized ISO payload")
            result = _scan_container(data, target)
            summaries.append({
                "container_name": name,
                **result,
            })
            # Drop the reference before reading the next potentially large file.
            del data

    total_exact = sum(
        item["exact_pointer_byte_sequence_occurrences"] for item in summaries
    )
    total_pc_refs = sum(
        item["pc_relative_literal_reference_count"] for item in summaries
    )
    found_names = {item["container_name"] for item in summaries}
    return {
        "schema_version": 1,
        "stage": "stage101_expanded_boot_area_slot_audit",
        "analysis": {
            "root_file_count": root["root_file_count"],
            "full_payloads_scanned": root.get(
                "full_payloads_scanned", len(payloads)
            ),
            "oversized_container_count_scanned": len(summaries),
            "expected_cpk_container_set_found": (
                EXPECTED_LARGE_CONTAINERS.issubset(found_names)
            ),
            "oversized_container_total_bytes_scanned": sum(
                item["size_bytes"] for item in summaries
            ),
            "oversized_container_exact_pointer_byte_sequence_occurrences": total_exact,
            "oversized_container_pc_relative_literal_reference_count": total_pc_refs,
            "oversized_containers_with_exact_pointer_byte_sequence": sum(
                item["exact_pointer_byte_sequence_occurrences"] > 0
                for item in summaries
            ),
            "slot_initialization_candidate_found_in_oversized_containers": bool(
                total_exact or total_pc_refs
            ),
            "oversized_container_full_code_disassembly_performed": False,
            "slot_value_resolved_from_disc": False,
            "slot_runtime_target_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
            "container_summaries": summaries,
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
