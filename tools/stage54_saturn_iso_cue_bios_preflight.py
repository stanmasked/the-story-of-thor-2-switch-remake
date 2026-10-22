#!/usr/bin/env python3
"""Stage54: validate private 2048-byte Saturn ISO and prepare *provisional* CUE.

Checks the original disc SHA, IP/PVD, declared region, and optional emulator
binary/BIOS provenance. Creates a new private MODE1/2048 cue sheet referencing
the ISO BY BASENAME ONLY. It cannot restore audio tracks or subchannel data
that were absent in the source ISO. No emulator is executed by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from stage50_sh2_load_mapping_evidence import REFERENCE_ISO_SHA256, _iso_sha256
from stage51_saturn_boot_first_read_map import SECTOR, verify_boot_layout

KNOWN_BIOS = {
    "E": ("mpr-17933.bin",
          "96e106f740ab448cf89f0dd49dfbac7fe5391cb6bd6e14ad5e3061c13330266f"),
    "J": ("sega_101.bin",
          "dcfef4b99605f872b6c3b6d05c045385cdea3d1b702906a0ed930df7bcb7deac"),
}
BIOS_BYTES = 512 * 1024
MIN_DISC_BYTES = 20 * SECTOR
MAX_DISC_BYTES = 256 * 1024 * 1024
CUE_SUFFIX = ".private-mode1.cue"


def disc_preflight(raw: bytes) -> dict:
    """Confirm a coherent synthetic/original cooked Saturn ISO image."""
    if type(raw) is not bytes or not MIN_DISC_BYTES <= len(raw) <= MAX_DISC_BYTES:
        raise ValueError("unsupported cooked Saturn ISO size")
    if len(raw) % SECTOR:
        raise ValueError("ISO is not a multiple of 2048-byte sectors")
    boot = verify_boot_layout(raw)
    area = raw[0x40:0x50].decode("ascii", "strict").strip()
    regions = "".join(sorted(set(area.replace(" ", ""))))
    if not regions or any(c not in "EJ" for c in regions):
        raise ValueError("only independently documented E/J BIOS region mapping is supported")
    # Multiple advertised regions cannot be mapped to just one BIOS automatically.
    if len(regions) != 1:
        raise ValueError("multi-region disc requires explicit emulator configuration")
    if not boot["independent_boot_metadata_supports_static_load_base"]:
        raise ValueError("first-read address does not match Stage51 code load model")
    return {
        "region": regions,
        "sectors": len(raw) // SECTOR,
        "iso9660_primary_volume_verified": boot["iso9660_primary_volume_valid"],
        "stage51_first_read_mapping_verified":
            boot["independent_boot_metadata_supports_static_load_base"],
        "first_read_program_size": boot["first_read_file_byte_length"],
        "cooked_data_sectors_only": True,
        "raw_cd_subchannels_available": False,
        "original_audio_track_layout_verified": False,
    }


def make_cue(iso_basename: str) -> str:
    """Only a restricted relative ISO basename; never permit CUE path escaping."""
    if (type(iso_basename) is not str or not 1 <= len(iso_basename) <= 180
            or iso_basename in (".", "..")
            or not iso_basename.lower().endswith(".iso")
            or any(not (c.isascii() and (c.isalnum() or c in " ._()-"))
                   for c in iso_basename)
            or "/" in iso_basename or "\\" in iso_basename
            or iso_basename.startswith(".")):
        raise ValueError("unsafe or unsupported ISO basename in cue")
    return 'FILE "' + iso_basename + '" BINARY\n  TRACK 01 MODE1/2048\n    INDEX 01 00:00:00\n'


def _digest(path: Path, expected_size: int | None = None) -> str:
    if not path.is_file():
        raise ValueError("file is missing or not regular")
    if expected_size is not None and path.stat().st_size != expected_size:
        raise ValueError("private firmware has unexpected size")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_bios(region: str, bios: Path | None) -> dict:
    if region not in KNOWN_BIOS:
        raise ValueError("unsupported BIOS region")
    filename, expected_hash = KNOWN_BIOS[region]
    if bios is None:
        return {
            "private_bios_supplied": False,
            "known_region_firmware_expected": filename,
            "private_bios_matches_official_mednafen_reference": False,
        }
    if _digest(bios, BIOS_BYTES) != expected_hash:
        raise ValueError("private Saturn BIOS does not match documented SHA-256")
    return {
        "private_bios_supplied": True,
        "known_region_firmware_expected": filename,
        "private_bios_matches_official_mednafen_reference": True,
    }


def check_emulator(executable: Path | None) -> dict:
    """Check a *supplied* local Mednafen binary; never invoke it."""
    if executable is None:
        return {"emulator_binary_supplied": False,
                "emulator_binary_executable": False}
    if (not executable.is_file() or not os.access(executable, os.X_OK)
            or executable.is_symlink()):
        raise ValueError("provided local emulator is not a regular executable")
    # Explicit path, not a PATH lookup; no import, child process or execution.
    if executable.stat().st_size < 4096:
        raise ValueError("emulator binary is too small to be plausible")
    return {"emulator_binary_supplied": True,
            "emulator_binary_executable": True}


def write_private_cue(path: Path, iso: Path, content: str) -> None:
    # A CUE's FILE entry is relative to the containing directory.
    if path.parent.resolve() != iso.parent.resolve() or path.resolve() == iso.resolve():
        raise ValueError("private cue must be beside original ISO")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(content)


def run_private(iso: Path, cue: Path, bios: Path | None = None,
                emulator: Path | None = None) -> dict:
    if _iso_sha256(iso) != REFERENCE_ISO_SHA256:
        raise ValueError("private ISO differs from pinned original SHA-256")
    if iso.is_symlink():
        raise ValueError("private source ISO must not be a symlink")
    disc = disc_preflight(iso.read_bytes())
    bios_check = check_bios(disc["region"], bios)
    executable_check = check_emulator(emulator)
    content = make_cue(iso.name)
    write_private_cue(cue, iso, content)
    return {
        "schema_version": 1,
        "stage": "stage54_saturn_iso_cue_bios_preflight",
        "original_disc_sha256_verified": True,
        "disc_region": disc["region"],
        "cooked_data_sectors": disc["sectors"],
        "disc_first_read_mapping_verified": disc["stage51_first_read_mapping_verified"],
        "single_track_mode1_2048_cue_created_privately": True,
        "original_cd_audio_tracks_recovered": False,
        "original_disc_subchannel_data_recovered": False,
        "full_original_cd_track_layout_authenticated": False,
        **bios_check, **executable_check,
        "all_launch_prerequisites_locally_present":
            bios_check["private_bios_matches_official_mednafen_reference"]
            and executable_check["emulator_binary_executable"],
        "mednafen_launch_attempted": False,
        "saturn_execution_observed": False,
        "real_ram_vram_capture_available": False,
        "limitations": [
            "One provisional MODE1/2048 track cannot restore missing CD-DA audio tracks.",
            "Mednafen CUE acceptance and original title booting require a real local test.",
            "An emulator file being executable does not prove its identity or module support.",
            "Firmware must come from a lawfully obtained private source; this tool will not download it.",
            "No original image, audio, BIOS, or game data is published by this tool.",
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-private", type=Path, required=True)
    p.add_argument("--cue-private", type=Path, required=True,
                   help="NEW private CUE file in the same directory as the ISO")
    p.add_argument("--bios-private", type=Path)
    p.add_argument("--mednafen-private", type=Path)
    args = p.parse_args()
    result = run_private(args.iso_private, args.cue_private,
                         args.bios_private, args.mednafen_private)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
