#!/usr/bin/env python3
"""Stage51: prove the *declared* Saturn 1st-read mapping from private ISO9660.

SEGA IP header at 0xF0 declares the 1st-read destination, and ISO9660 file
identifier [2] is the first non-special root directory entry. These are
static on-disc facts, never proof of emulator transfer or SH-2 execution.
Never exports original code, executable offsets, raw directory, or assets.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from stage50_sh2_load_mapping_evidence import (
    RAM_BASE, HIGH_WORK_RAM_BYTES, REFERENCE_ISO_SHA256,
    SH2_LOAD_BASE, _iso_sha256, static_preflight,
)

SECTOR = 2048
IP_MIN = 0x1000
IP_MAX = 0x8000
IPL_RAM_BASE = RAM_BASE + 0x2000
SYSTEM_RESERVED_TAIL_START = RAM_BASE + HIGH_WORK_RAM_BYTES - 0x1000
EXPECTED_PROGRAM = b"0TH2.BIN"
MAX_ROOT_SIZE = 128 * 1024


def _both_endian32(record: bytes, le: int, be: int) -> int:
    if len(record) < be + 4:
        raise ValueError("truncated ISO9660 directory field")
    a = int.from_bytes(record[le:le+4], "little")
    b = int.from_bytes(record[be:be+4], "big")
    if a != b:
        raise ValueError("inconsistent ISO9660 both-endian field")
    return a


def _entry_at(record: bytes) -> dict:
    if len(record) < 34 or record[0] != len(record):
        raise ValueError("malformed ISO9660 directory record")
    length = record[32]
    if length < 1 or 33 + length > len(record):
        raise ValueError("truncated ISO9660 file identifier")
    return {
        "id": record[33:33+length].split(b";", 1)[0],
        "extent": _both_endian32(record, 2, 6),
        "size": _both_endian32(record, 10, 14),
        "is_directory": bool(record[25] & 2),
    }


def _root_entries(raw: bytes, pvd: bytes) -> list[dict]:
    root_record_size = pvd[156]
    if not 34 <= root_record_size <= 255 or 156 + root_record_size > SECTOR:
        raise ValueError("invalid primary volume root directory record")
    root = _entry_at(pvd[156:156 + root_record_size])
    if not root["is_directory"] or root["size"] < 68 or root["size"] > MAX_ROOT_SIZE:
        raise ValueError("invalid ISO9660 root directory extent size")
    start = root["extent"] * SECTOR
    end = start + root["size"]
    if start < 17 * SECTOR or end > len(raw):
        raise ValueError("ISO9660 root directory exceeds image")
    data = raw[start:end]
    out = []
    off = 0
    while off < len(data):
        size = data[off]
        if size == 0:
            off = (off // SECTOR + 1) * SECTOR
            continue
        if (off % SECTOR) + size > SECTOR or off + size > len(data):
            raise ValueError("root directory record crosses a sector boundary")
        e = _entry_at(data[off:off+size])
        if e["extent"] * SECTOR + e["size"] > len(raw):
            raise ValueError("root file data is outside image")
        out.append(e)
        if len(out) > 1024:
            raise ValueError("too many ISO9660 root directory entries")
        off += size
    return out


def verify_boot_layout(raw: bytes) -> dict:
    """Check original disc header, FID[2] file and Stage45/46 code signatures."""
    if type(raw) is not bytes or len(raw) < 25 * SECTOR:
        raise ValueError("ISO9660 image is missing or truncated")
    if raw[:16] != b"SEGA SEGASATURN ":
        raise ValueError("not a Sega Saturn boot header")
    ip_size = int.from_bytes(raw[0xE0:0xE4], "big")
    first_read_address = int.from_bytes(raw[0xF0:0xF4], "big")
    if not IP_MIN <= ip_size <= IP_MAX or ip_size % 4:
        raise ValueError("IP size is outside the documented aligned range")
    if first_read_address % 4 or not RAM_BASE <= first_read_address < RAM_BASE + HIGH_WORK_RAM_BYTES:
        raise ValueError("invalid or disabled first-read transfer address")
    pvd = raw[16 * SECTOR:17 * SECTOR]
    if pvd[:7] != b"\x01CD001\x01":
        raise ValueError("primary volume descriptor missing")
    entries = _root_entries(raw, pvd)
    if len(entries) < 3 or entries[0]["id"] != b"\x00" or entries[1]["id"] != b"\x01":
        raise ValueError("ISO9660 special first two root file identifiers missing")
    first = entries[2]
    if first["is_directory"] or first["id"] != EXPECTED_PROGRAM:
        raise ValueError("file identifier [2] is not the target 0TH2.BIN program")
    if first["size"] <= 0 or first["size"] > 5 * 1024 * 1024:
        raise ValueError("invalid bounded first-read file size")
    begin = first["extent"] * SECTOR
    program = raw[begin:begin+first["size"]]
    if len(program) != first["size"]:
        raise ValueError("first-read file truncated")
    boot_ip_end = IPL_RAM_BASE + ip_size
    transfer_end = first_read_address + len(program)
    reserved_overlap = first_read_address < boot_ip_end
    crosses_system_tail = transfer_end > SYSTEM_RESERVED_TAIL_START
    mapped_inside_hwr = transfer_end <= RAM_BASE + HIGH_WORK_RAM_BYTES
    if reserved_overlap or crosses_system_tail or not mapped_inside_hwr:
        raise ValueError("boot first-read mapping conflicts with system RAM or exceeds WRAM-H")
    static = static_preflight(program)
    return {
        "schema_version": 1,
        "stage": "stage51_saturn_boot_first_read_map",
        "saturn_boot_header_valid": True,
        "iso9660_primary_volume_valid": True,
        "ip_program_size_bytes": ip_size,
        "iso9660_first_program_is_0th2_bin": True,
        "first_read_file_byte_length": len(program),
        "first_read_address_equals_stage49_assumption": first_read_address == SH2_LOAD_BASE,
        "first_read_transfer_size_field_ignored_for_cd": True,
        "first_read_mapping_overlaps_ip": reserved_overlap,
        "first_read_mapping_crosses_reserved_system_tail": crosses_system_tail,
        "first_read_mapping_fits_high_work_ram": mapped_inside_hwr,
        "stage45_46_private_static_role_count": static["static_sh2_role_count"],
        "first_read_program_code_roles_match_stage45_46": static["stage45_stage46_code_role_signatures_found"],
        "independent_boot_metadata_supports_static_load_base":
            first_read_address == SH2_LOAD_BASE and not reserved_overlap and mapped_inside_hwr,
        "actual_bootrom_file_transfer_observed": False,
        "actual_sh2_execution_observed": False,
        "emulator_origin_authenticated": False,
        "limitations": [
            "Header transfer destination is a documented static boot setting, not an observed DMA event.",
            "The 1st-read file is transferred during the logo screen but is not automatically executed.",
            "This analysis cannot authenticate a high-work-RAM dump or trace.",
            "No private program offsets, instruction bytes, file extents or RAM addresses are exported.",
        ],
    }


def analyze_private(path: Path) -> dict:
    if _iso_sha256(path) != REFERENCE_ISO_SHA256:
        raise ValueError("private ISO does not match the pinned original SHA-256")
    report = verify_boot_layout(path.read_bytes())
    report["private_original_iso_checksum_matched"] = True
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-private", type=Path, required=True)
    p.add_argument("--output-private", type=Path,
                   help="Write NEW owner-only aggregate report (permissions 0600)")
    args = p.parse_args()
    encoded = json.dumps(analyze_private(args.iso_private),
                         indent=2, ensure_ascii=False) + "\n"
    if args.output_private:
        fd = os.open(args.output_private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
