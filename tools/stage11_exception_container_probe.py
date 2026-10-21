#!/usr/bin/env python3
"""Stage11: profile exceptional MONS.BIN and P4.BIN container structures.

Only record counts, size histograms, and aggregate byte statistics are emitted.
No original bytes, exact offsets, images, palettes, audio, or video are exported.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES, inspect_counted_table
from stage04_record_layout import indexed_records

TARGET_FILES = {"/MONS.BIN", "/P4.BIN"}
GEOMETRY_RECORD_BYTES = 14
GEOMETRY_TAIL_MARKER = 0x7FFF


def be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def byte_statistics(data: bytes) -> dict:
    """Return entropy and byte-frequency aggregates without raw values."""
    if not data:
        return {
            "size_bytes": 0,
            "unique_byte_values": 0,
            "zero_fraction": None,
            "ff_fraction": None,
            "entropy_bits_per_byte": None,
        }
    counts = Counter(data)
    size = len(data)
    entropy = -sum((count / size) * math.log2(count / size) for count in counts.values())
    return {
        "size_bytes": size,
        "unique_byte_values": len(counts),
        "zero_fraction": round(counts.get(0, 0) / size, 4),
        "ff_fraction": round(counts.get(255, 0) / size, 4),
        "entropy_bits_per_byte": round(entropy, 4),
    }


def profile_indexed_records(records: list[bytes]) -> dict:
    """Summarize variable-length spans from a validated counted offset table."""
    if not records:
        return {
            "record_count": 0,
            "record_size_min": None,
            "record_size_max": None,
            "record_size_histogram": [],
            "records_with_6_plus_8n_shape": 0,
            "records_matching_stage04_header_counter": 0,
            "records_with_zero_first_word": 0,
            "records_ending_in_7fff": 0,
        }
    sizes = [len(record) for record in records]
    shape = [
        len(record) >= 14 and (len(record) - 6) % 8 == 0
        for record in records
    ]
    header_match = [
        ok and be16(record, 0) == ((len(record) - 6) // 8 - 1)
        for record, ok in zip(records, shape)
    ]
    size_counts = Counter(sizes)
    return {
        "record_count": len(records),
        "record_size_min": min(sizes),
        "record_size_max": max(sizes),
        "record_size_histogram": [
            {"size_bytes": size, "count": count}
            for size, count in sorted(size_counts.items())
        ],
        "records_with_6_plus_8n_shape": sum(shape),
        "records_matching_stage04_header_counter": sum(header_match),
        "records_with_zero_first_word": sum(be16(record, 0) == 0 for record in records),
        "records_ending_in_7fff": sum(
            len(record) >= 2 and be16(record, len(record) - 2) == GEOMETRY_TAIL_MARKER
            for record in records
        ),
    }


def profile_14_byte_tail_markers(section: bytes) -> dict:
    """Count 14-byte spans ending in 0x7fff at even offsets, without exporting them."""
    word_marker_count = sum(
        be16(section, offset) == GEOMETRY_TAIL_MARKER
        for offset in range(0, len(section) - 1, 2)
    )
    offsets = [
        offset for offset in range(0, len(section) - GEOMETRY_RECORD_BYTES + 1, 2)
        if be16(section, offset + 12) == GEOMETRY_TAIL_MARKER
    ]
    offset_set = set(offsets)
    return {
        "word_7fff_count": word_marker_count,
        "candidate_14_byte_tail_marker_count": len(offsets),
        "unique_candidate_14_byte_record_count": len({
            section[offset:offset + GEOMETRY_RECORD_BYTES] for offset in offsets
        }),
        "candidate_records_at_14_byte_grid_count": sum(
            offset % GEOMETRY_RECORD_BYTES == 0 for offset in offsets
        ),
        "candidate_records_with_14_byte_successor_count": sum(
            offset + GEOMETRY_RECORD_BYTES in offset_set for offset in offsets
        ),
        "interpretation": "marker/stride statistics only; record semantics are unproven",
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    results = []
    found = set()

    with image.open("rb") as stream:
        for entry in disc["game_files"]:
            if entry["path"].upper() not in TARGET_FILES:
                continue
            found.add(entry["path"].upper())
            size = entry["size_bytes"]
            if size > MAX_PROBE_BYTES:
                raise ValueError("Target file exceeds the safe probe size: " + entry["path"])
            stream.seek(entry["extent_sector"] * SECTOR)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Short read from ISO extent: " + entry["path"])
            layout = offsets_layout(data)
            if layout is None:
                raise ValueError("Exceptional file lacks the known three-section layout: " + entry["path"])
            base = layout["table_offset"]
            bounds = [base + value for value in layout["relative_offsets"]] + [len(data)]
            sections = [data[left:right] for left, right in zip(bounds, bounds[1:])]
            table = inspect_counted_table(sections[0])
            records = indexed_records(sections[0])
            if table is None or records is None:
                raise ValueError("First section lacks a validated counted index table: " + entry["path"])

            results.append({
                "path": entry["path"],
                "file_size_bytes": size,
                "table_summary": {
                    "indexed_slots": table["indexed_slots"],
                    "present_slots": table["present_slots"],
                    "missing_zero_slots": table["missing_zero"],
                    "missing_ffff_slots": table["missing_ffff"],
                    "duplicate_offsets": table["duplicate_offsets"],
                },
                "first_section_record_profile": profile_indexed_records(records),
                "sections": [
                    {
                        "index": index,
                        **byte_statistics(section),
                        **profile_14_byte_tail_markers(section),
                    }
                    for index, section in enumerate(sections)
                ],
            })

    if found != TARGET_FILES:
        raise ValueError("Expected both MONS.BIN and P4.BIN; found: " + ", ".join(sorted(found)))

    return {
        "schema_version": 1,
        "stage": "stage11_exception_container_structure_probe",
        "disc_sha256": disc["sha256"],
        "disc_product": disc["saturn_header"]["product"],
        "files_analyzed": len(results),
        "files": results,
        "interpretation": [
            "The first sections of MONS.BIN and P4.BIN contain counted index tables, but their record headers mostly fail the Stage04 counter rule.",
            "Record lengths may follow a 6 + 8×N shape even when the first word has different semantics.",
            "A 0x7fff word near the end of a 14-byte span is only a candidate marker; sparse alignment does not prove geometry records.",
        ],
        "limitations": [
            "Only aggregate counts, size histograms, and byte statistics are exported.",
            "No record meanings, compression, texture format, dimensions, palette, or transparency rule are established.",
            "No exact offsets, source bytes, sprites, maps, audio, or video are emitted.",
            "No native game engine or Switch NRO is produced.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Private local Sega Saturn ISO")
    parser.add_argument("-o", "--output", type=Path, help="Metadata-only JSON output path")
    args = parser.parse_args()
    output = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print("Stage 11 metadata-only report saved:", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
