#!/usr/bin/env python3
"""Stage12: count Sega Saturn graphics-hardware address literals in local files.

This is a literal census, not a disassembler. Reports counts only and never
exports exact offsets, source bytes, or copyrighted game assets.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage03_index_tables import MAX_PROBE_BYTES

VDP1_VRAM_BASE = 0x25C00000
VDP1_FRAMEBUFFER_BASE = 0x25C80000
VDP1_REGISTER_ADDRESSES = (
    0x25D00000, 0x25D00002, 0x25D00004, 0x25D00006,
    0x25D00008, 0x25D0000A, 0x25D0000C, 0x25D00010,
    0x25D00012, 0x25D00014, 0x25D00016,
)
VDP2_VRAM_BASE = 0x25E00000
VDP2_CRAM_BASE = 0x25F00000
VDP2_REGISTER_ADDRESSES = tuple(0x25F80000 + offset for offset in range(0, 0x20, 2))


def count_exact_literal(data: bytes, value: int) -> int:
    """Count occurrences of one exact big-endian 32-bit address literal."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("literal must fit in an unsigned 32-bit word")
    return data.count(value.to_bytes(4, "big"))


def profile_hardware_literals(data: bytes) -> dict:
    """Return counts for documented memory-map address constants."""
    vdp1_register_counts = {
        f"0x{address:08X}": count_exact_literal(data, address)
        for address in VDP1_REGISTER_ADDRESSES
    }
    vdp2_register_counts = {
        f"0x{address:08X}": count_exact_literal(data, address)
        for address in VDP2_REGISTER_ADDRESSES
    }
    return {
        "vdp1_vram_base_literal_count": count_exact_literal(data, VDP1_VRAM_BASE),
        "vdp1_framebuffer_base_literal_count": count_exact_literal(data, VDP1_FRAMEBUFFER_BASE),
        "vdp1_register_base_literal_count": count_exact_literal(data, VDP1_REGISTER_ADDRESSES[0]),
        "vdp1_register_literal_count": sum(vdp1_register_counts.values()),
        "vdp1_register_literal_counts": vdp1_register_counts,
        "vdp2_vram_base_literal_count": count_exact_literal(data, VDP2_VRAM_BASE),
        "vdp2_cram_base_literal_count": count_exact_literal(data, VDP2_CRAM_BASE),
        "vdp2_register_base_literal_count": count_exact_literal(data, VDP2_REGISTER_ADDRESSES[0]),
        "vdp2_register_literal_count": sum(vdp2_register_counts.values()),
        "vdp2_register_literal_counts": vdp2_register_counts,
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    file_results = []
    skipped_large_files = 0
    target_found = False

    with image.open("rb") as stream:
        for entry in disc["game_files"]:
            size = entry["size_bytes"]
            if size > MAX_PROBE_BYTES:
                skipped_large_files += 1
                continue
            stream.seek(entry["extent_sector"] * SECTOR)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Short read from ISO extent: " + entry["path"])
            profile = profile_hardware_literals(data)
            if entry["path"].upper() == "/0TH2.BIN":
                target_found = True
            if any(
                value for key, value in profile.items()
                if key.endswith("_count") and isinstance(value, int)
            ):
                file_results.append({
                    "path": entry["path"],
                    "size_bytes": size,
                    "hardware_literal_profile": profile,
                })

    if not target_found:
        raise ValueError("Expected /0TH2.BIN in the ISO root directory")
    primary = next((item for item in file_results if item["path"].upper() == "/0TH2.BIN"), None)
    if primary is None:
        primary = {
            "path": "/0TH2.BIN",
            "size_bytes": next(
                entry["size_bytes"] for entry in disc["game_files"]
                if entry["path"].upper() == "/0TH2.BIN"
            ),
            "hardware_literal_profile": profile_hardware_literals(b""),
        }

    return {
        "schema_version": 1,
        "stage": "stage12_saturn_hardware_literal_census",
        "disc_sha256": disc["sha256"],
        "disc_product": disc["saturn_header"]["product"],
        "files_scanned": len(disc["game_files"]) - skipped_large_files,
        "files_skipped_above_probe_limit": skipped_large_files,
        "primary_file": primary,
        "other_files_with_hardware_literals": [
            item for item in file_results if item["path"].upper() != "/0TH2.BIN"
        ],
        "interpretation": [
            "Exact hardware-address constants occur in 0TH2.BIN and in other files, including MAP.BIN and TH2.LOW.",
            "A literal occurrence does not prove that the value is executed as code; it may be data, a lookup value, or an embedded structure.",
            "The scan narrows where to investigate but does not identify a VDP1 command builder or recover texture dimensions/palettes.",
        ],
        "limitations": [
            "The analyzer counts exact big-endian 32-bit literals only; it does not disassemble SH-2 instructions or resolve PC-relative literal loads.",
            "Files larger than the configured probe limit are skipped.",
            "No exact offsets, original bytes, sprites, maps, palettes, audio, or video are exported.",
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
        print("Stage 12 metadata-only report saved:", args.output)
    else:
        print(output)


if __name__ == "__main__":
    main()
