#!/usr/bin/env python3
"""Stage48: private offline witness for the Stage45/46 VDP1 copy loop.

Compares expected writes from operator-provided descriptor metadata and PRIVATE
source command bytes against two PRIVATE 512-KiB VDP1 VRAM snapshots. No
original image, RAM addresses, VRAM bytes or source commands appear in output.
A matching offline model never authenticates emulator origin or causality.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

VRAM_BYTES = 0x80000
COMMAND_BYTES = 32
DESCRIPTOR_BYTES = 8
INDEX_UNIT_BYTES = 8
MAX_DESCRIPTORS = 512  # Stage16 comparison *candidate*, not a proven global bound.
MAX_COMMANDS = VRAM_BYTES // COMMAND_BYTES
MAX_MANIFEST_BYTES = 262144
REQUIRED_FIELDS = frozenset({
    "schema_version", "status_before", "status_after", "pending_count_before",
    "pending_count_after", "descriptors",
})
DESCRIPTOR_FIELDS = frozenset({"destination_index", "copy_count"})


def _integer(value: object, low: int, high: int, label: str) -> int:
    # Reject bool (subclass of int), strings and floats even when integral.
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"invalid {label}: expected bounded integer")
    return value


def parse_manifest(obj: object) -> dict:
    """Reject unknown keys and malformed or oversized capture metadata."""
    if type(obj) is not dict or set(obj) != REQUIRED_FIELDS:
        raise ValueError("manifest must contain precisely the required fields")
    if _integer(obj["schema_version"], 1, 1, "schema version") != 1:
        raise ValueError("unsupported manifest version")
    for field in ("status_before", "status_after"):
        _integer(obj[field], -128, 127, field)
    for field in ("pending_count_before", "pending_count_after"):
        _integer(obj[field], 0, 65535, field)
    records = obj["descriptors"]
    if type(records) is not list or not 1 <= len(records) <= MAX_DESCRIPTORS:
        raise ValueError("descriptors must be a nonempty bounded list")
    command_total = 0
    for record in records:
        if type(record) is not dict or set(record) != DESCRIPTOR_FIELDS:
            raise ValueError("descriptor keys are not valid")
        _integer(record["destination_index"], 0, 65535, "destination index")
        _integer(record["copy_count"], 1, 32767, "positive signed copy count")
        command_total += record["copy_count"]
        if command_total > MAX_COMMANDS:
            raise ValueError("total copied commands exceed bounded audit limit")
        begin = record["destination_index"] * INDEX_UNIT_BYTES
        end = begin + record["copy_count"] * COMMAND_BYTES
        if end > VRAM_BYTES:
            raise ValueError("descriptor write extends beyond VDP1 VRAM")
    return obj


def _count_changed(a: bytes | bytearray, b: bytes | bytearray) -> int:
    return sum(x != y for x, y in zip(a, b))


def audit_witness(manifest: object, before: bytes, after: bytes,
                  source_commands: bytes | None = None) -> dict:
    manifest = parse_manifest(manifest)
    if len(before) != VRAM_BYTES or len(after) != VRAM_BYTES:
        raise ValueError("both VDP1 VRAM snapshots must be exactly 524288 bytes")
    if source_commands is not None and type(source_commands) is not bytes:
        raise ValueError("private source commands must be binary bytes")

    records = manifest["descriptors"]
    copies = sum(d["copy_count"] for d in records)
    expected_source_size = copies * COMMAND_BYTES
    if source_commands is not None and len(source_commands) != expected_source_size:
        raise ValueError("private command-stream size does not match descriptor copy counts")

    # Stage46 reads global count into R5; Stage45 decrements R5 in the inner
    # loop on each 32-byte copy (BF/S delay slot), not once per descriptor.
    budget_agrees = manifest["pending_count_before"] == copies
    gate_conditions = manifest["status_before"] < 0 and manifest["pending_count_before"] > 0
    reset_agrees = manifest["status_after"] == 0 and manifest["pending_count_after"] == 0
    aligned = sum((d["destination_index"] * INDEX_UNIT_BYTES) % COMMAND_BYTES == 0
                  for d in records)

    touched = bytearray(VRAM_BYTES)
    overlaps = 0
    for d in records:
        begin = d["destination_index"] * INDEX_UNIT_BYTES
        end = begin + d["copy_count"] * COMMAND_BYTES
        overlaps += touched[begin:end].count(1)
        touched[begin:end] = b"\x01" * (end - begin)

    changed_in = changed_out = 0
    for i, (a, b) in enumerate(zip(before, after)):
        if a != b:
            if touched[i]:
                changed_in += 1
            else:
                changed_out += 1

    model_match = None
    model_mismatch = None
    if source_commands is not None:
        expected = bytearray(before)
        cursor = 0
        for d in records:
            size = d["copy_count"] * COMMAND_BYTES
            begin = d["destination_index"] * INDEX_UNIT_BYTES
            expected[begin:begin + size] = source_commands[cursor:cursor + size]
            cursor += size
        model_mismatch = _count_changed(expected, after)
        model_match = model_mismatch == 0

    return {
        "schema_version": 1,
        "stage": "stage48_vdp1_copy_witness",
        "descriptor_count": len(records),
        "commands_expected_by_descriptors": copies,
        "pending_count_matches_commands_not_descriptors": budget_agrees,
        "pending_count_equals_descriptor_count": manifest["pending_count_before"] == len(records),
        "negative_flag_and_nonzero_count_observed_in_manifest": gate_conditions,
        "post_return_zero_resets_observed_in_manifest": reset_agrees,
        "destinations_aligned_to_32_bytes": aligned,
        "destinations_not_32_byte_aligned": len(records) - aligned,
        "overwritten_vram_bytes_in_overlap": overlaps,
        "observed_changed_vram_bytes": changed_in + changed_out,
        "observed_changed_bytes_inside_expected_write_ranges": changed_in,
        "observed_changed_bytes_outside_expected_write_ranges": changed_out,
        "private_source_capture_supplied": source_commands is not None,
        "predicted_vram_equals_after_dump": model_match,
        "predicted_vs_observed_mismatching_vram_bytes": model_mismatch,
        "synthetic_or_operator_supplied_data_only": True,
        "emulator_origin_authenticated": False,
        "stage45_46_runtime_execution_proven": False,
        "handler_39_to_vdp1_proven": False,
        "copy_path_consistent_with_observation": bool(
            source_commands is not None and model_match and gate_conditions
            and reset_agrees and budget_agrees and changed_in > 0
            and changed_out == 0),
        "limitations": [
            "Inputs are offline operator-supplied captures, not authenticated SH-2 execution.",
            "An exact memory-delta match does not prove that the game executed this copy loop.",
            "The Stage16 capacity comparison is not an established runtime buffer bound.",
            "Other VDP1 clients can write VRAM concurrently; outside-range changes are reported.",
            "No source command bytes, exact VRAM positions, pointers or original assets are emitted.",
        ],
    }


def load_manifest(path: Path) -> dict:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("private capture manifest exceeds size cap")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate manifest key")
            result[key] = value
        return result

    return parse_manifest(json.loads(path.read_text(encoding="utf-8"),
                                     object_pairs_hook=unique_pairs))


def run_private(manifest_path: Path, before_path: Path, after_path: Path,
                source_path: Path | None = None) -> dict:
    manifest = load_manifest(manifest_path)
    # Enforce size before reading attacker-sized files into RAM.
    for p in (before_path, after_path):
        if p.stat().st_size != VRAM_BYTES:
            raise ValueError("private VDP1 VRAM dump must be exactly 524288 bytes")
    if source_path is not None:
        expected = sum(d["copy_count"] for d in manifest["descriptors"]) * COMMAND_BYTES
        if source_path.stat().st_size != expected:
            raise ValueError("private command-stream byte length disagrees with manifest")
    return audit_witness(manifest, before_path.read_bytes(), after_path.read_bytes(),
                        source_path.read_bytes() if source_path is not None else None)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest-private", required=True, type=Path)
    p.add_argument("--before-vram-private", required=True, type=Path)
    p.add_argument("--after-vram-private", required=True, type=Path)
    p.add_argument("--source-commands-private", type=Path)
    p.add_argument("--output-private", type=Path,
                   help="A NEW restricted owner-only local JSON metadata report")
    args = p.parse_args()
    report = run_private(args.manifest_private, args.before_vram_private,
                         args.after_vram_private, args.source_commands_private)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output_private:
        # O_EXCL avoids overwriting or following existing private files/symlinks.
        fd = os.open(args.output_private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
