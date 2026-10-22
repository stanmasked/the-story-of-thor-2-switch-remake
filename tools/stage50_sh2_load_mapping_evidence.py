#!/usr/bin/env python3
"""Stage50: validate a PRIVATE SH-2 high-work-RAM snapshot against Saturn code.

A genuine 1-MiB RAM dump can support or contradict the inferred 0x06004000
load mapping. A synthetic or manually reconstructed dump can also match:
this tool DOES NOT authenticate emulator origin, PC execution or VDP1 writes.
Only aggregate evidence is printed or stored; never emit RAM/code bytes or PCs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from stage18_writer_guard_flow import iso_file_payload
from stage49_sh2_vdp1_trace_contract import SH2_LOAD_BASE, find_private_roles

RAM_BASE = 0x06000000
HIGH_WORK_RAM_BYTES = 0x100000
ANCHOR_BYTES = 12
EXPECTED_ROLE_COUNT = 12
MAX_IMAGE_BYTES = 256 * 1024 * 1024
REFERENCE_ISO_SHA256 = "25b0b2774d4621bd9f95a01fc5420ded37b481b61b3cdf515360d82b2cb7bb0d"


def _roles(program: bytes) -> list[tuple[int, bytes]]:
    """Internal PC-relative code signatures for one Stage45/46 pairing."""
    private = find_private_roles(program)
    addresses = [private["gate"], private["jsr"], *private["stores"],
                 private["copy_rts"], private["submit_rts"]]
    if len(addresses) != EXPECTED_ROLE_COUNT or len(set(addresses)) != EXPECTED_ROLE_COUNT:
        raise ValueError("expected twelve unique private SH-2 instruction roles")
    anchors = []
    for pc in addresses:
        file_offset = pc - SH2_LOAD_BASE
        if (file_offset < 0 or file_offset % 2
                or file_offset + ANCHOR_BYTES > len(program)):
            raise ValueError("an instruction anchor falls outside the source module")
        anchors.append((file_offset, program[file_offset:file_offset + ANCHOR_BYTES]))
    if len(set(sample for _, sample in anchors)) < 4:
        raise ValueError("insufficient diversity in SH-2 instruction signatures")
    return anchors


def _score(ram: bytes, anchors: list[tuple[int, bytes]], image_start: int) -> int:
    return sum(0 <= image_start + off
               and image_start + off + len(code) <= len(ram)
               and ram[image_start + off:image_start + off + len(code)] == code
               for off, code in anchors)


def _candidates(ram: bytes, anchors: list[tuple[int, bytes]]) -> tuple[list[int], int]:
    """Find complete image-base placements using one anchor plus cross-checks."""
    first_offset, first_bytes = anchors[0]
    matches = set()
    observed_seed_matches = 0
    current = 0
    while True:
        at = ram.find(first_bytes, current)
        if at < 0:
            break
        observed_seed_matches += 1
        image_start = at - first_offset
        if image_start >= 0 and image_start % 2 == 0 and _score(ram, anchors, image_start) == len(anchors):
            matches.add(image_start)
        current = at + 1
    return sorted(matches), observed_seed_matches


def static_preflight(program: bytes) -> dict:
    anchors = _roles(program)
    return {
        "static_sh2_role_count": len(anchors),
        "role_signature_width_bytes": ANCHOR_BYTES,
        "unique_static_role_sample_patterns": len(set(code for _, code in anchors)),
        "matched_original_stage45_and_stage46_roles": True,
        "emulator_snapshot_provided": False,
        "runtime_image_mapping_observed": False,
        "emulator_origin_authenticated": False,
        "actual_sh2_execution_observed": False,
    }


def summarize(program: bytes, high_work_ram: bytes | None = None) -> dict:
    """Bounded static/snapshot cross-check. Snapshot results are untrusted."""
    anchors = _roles(program)
    summary = static_preflight(program)
    summary["limitations"] = [
        "Load address 0x06004000 originates from static SH-2 references; it is a hypothesis.",
        "Matching RAM bytes do not establish that an emulator produced the snapshot.",
        "Matched code can be dormant, copied, or synthesized without executing.",
        "Original game execution, VDP1 command writes and handler 39 remain unproven.",
        "Neither original instruction offsets nor RAM bytes or addresses appear in this report.",
    ]
    summary.update({
        "expected_mapping_role_matches": None,
        "complete_static_image_mapping_candidates": None,
        "complete_alternative_image_mapping_candidates": None,
        "seed_signature_occurrences": None,
        "expected_mapping_uniquely_supported_by_supplied_snapshot": False,
        "inferred_load_base_observed_in_authenticated_execution": False,
    })
    if high_work_ram is None:
        return summary
    if type(high_work_ram) is not bytes or len(high_work_ram) != HIGH_WORK_RAM_BYTES:
        raise ValueError("expected a complete 1048576-byte SH-2 high-work-RAM snapshot")
    expected_image_start = SH2_LOAD_BASE - RAM_BASE
    count = _score(high_work_ram, anchors, expected_image_start)
    full_candidates, seeds = _candidates(high_work_ram, anchors)
    summary.update({
        "emulator_snapshot_provided": True,  # supplied, NOT authenticated
        "expected_mapping_role_matches": count,
        "complete_static_image_mapping_candidates": len(full_candidates),
        "complete_alternative_image_mapping_candidates":
            sum(base != expected_image_start for base in full_candidates),
        "seed_signature_occurrences": seeds,
        "expected_mapping_uniquely_supported_by_supplied_snapshot":
            count == len(anchors) and full_candidates == [expected_image_start],
        "runtime_image_mapping_observed": count == len(anchors),
    })
    return summary


def _iso_sha256(image: Path) -> str:
    size = image.stat().st_size
    if size <= 0 or size > MAX_IMAGE_BYTES:
        raise ValueError("private ISO exceeds bounded input size")
    digest = hashlib.sha256()
    with image.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_private(iso: Path, snapshot: Path | None = None) -> dict:
    if _iso_sha256(iso) != REFERENCE_ISO_SHA256:
        raise ValueError("private ISO does not match the pinned Stage46 reference SHA-256")
    if snapshot is not None and snapshot.stat().st_size != HIGH_WORK_RAM_BYTES:
        raise ValueError("private high-work-RAM dump must contain exactly 1048576 bytes")
    program = iso_file_payload(iso)
    report = summarize(program, snapshot.read_bytes() if snapshot is not None else None)
    return {
        "schema_version": 1,
        "stage": "stage50_sh2_load_mapping_evidence",
        "original_iso_sha256_matches_pinned_reference": True,
        "analysis": report,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-private", required=True, type=Path)
    p.add_argument("--high-work-ram-private", type=Path,
                   help="Optional 1-MiB emulator memory snapshot of 0x06000000-0x060FFFFF")
    p.add_argument("--output-private", type=Path,
                   help="Create a NEW private metadata-only report with permissions 0600")
    args = p.parse_args()
    report = analyze_private(args.iso_private, args.high_work_ram_private)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output_private:
        fd = os.open(args.output_private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
