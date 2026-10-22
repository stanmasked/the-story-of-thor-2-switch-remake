#!/usr/bin/env python3
"""Stage55: BIOS-independent, private Yabause/RetroArch launch readiness.

Yabause libretro supports .iso input and an optional HLE BIOS. Verify the
pinned user's Saturn image and conservatively check supplied local host
binaries. Produce a private run sheet, NEVER launch code or publish ISO/BIOS.
Program presence is not proof that RetroArch can boot the game.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from stage50_sh2_load_mapping_evidence import REFERENCE_ISO_SHA256, _iso_sha256
from stage54_saturn_iso_cue_bios_preflight import disc_preflight

SOURCE_LIBRETRO = "https://docs.libretro.com/library/yabause/"
SOURCE_CLI = "https://docs.libretro.com/guides/cli-intro/"
ELF = b"\x7fELF"
MAX_ELF_BYTES = 200 * 1024 * 1024
MAX_PATH_LENGTH = 4096
FORBIDDEN_CONTROL = frozenset(chr(x) for x in range(0, 32))


def validate_binary(path: Path | None, *, executable: bool) -> dict:
    """Do not load shared libraries, invoke commands, or follow symlink stubs."""
    if path is None:
        return {"supplied": False, "elf_header_valid": False,
                "executable_permission": False, "local_binary_looks_usable": False}
    if not isinstance(path, Path):
        raise ValueError("local binary path must be a Path")
    if (path.is_symlink() or not path.is_file() or
            not 4096 <= path.stat().st_size <= MAX_ELF_BYTES):
        raise ValueError("local binary missing, symlinked, or outside size bound")
    with path.open("rb") as stream:
        header = stream.read(64)
    valid = (len(header) == 64 and header[:4] == ELF
             and header[4] in (1, 2) and header[5] == 1)
    permitted = os.access(path, os.X_OK)
    return {
        "supplied": True,
        "elf_header_valid": valid,
        "executable_permission": permitted,
        "local_binary_looks_usable": valid and (permitted if executable else True),
    }


def safe_local_path(path: Path) -> str:
    raw = str(path)
    if (not 1 <= len(raw) <= MAX_PATH_LENGTH
            or any(c in FORBIDDEN_CONTROL for c in raw)
            or '"' in raw or "\\" in raw):
        raise ValueError("unsafe launch-plan path")
    return raw


def readiness(iso: Path, frontend: Path | None, core: Path | None,
              *, display_available: bool = False) -> tuple[dict, dict]:
    """Return public aggregates and sensitive operator-only command plan."""
    if not isinstance(iso, Path) or iso.is_symlink():
        raise ValueError("original disc must be a local nonsymlink path")
    if _iso_sha256(iso) != REFERENCE_ISO_SHA256:
        raise ValueError("original Saturn ISO SHA-256 does not match pinned reference")
    disc = disc_preflight(iso.read_bytes())
    f = validate_binary(frontend, executable=True)
    c = validate_binary(core, executable=False)
    if type(display_available) is not bool:
        raise ValueError("display_available must be a bool")
    # According to libretro docs this Yabause core can load ISO directly.
    # The provisional MODE1/2048 CUE is not required for this path.
    cmd = None
    ready = f["local_binary_looks_usable"] and c["local_binary_looks_usable"]
    if frontend is not None and core is not None and ready:
        cmd = [safe_local_path(frontend), "-L",
               safe_local_path(core), safe_local_path(iso)]
    public = {
        "schema_version": 1,
        "stage": "stage55_yabause_hle_retroarch_readiness",
        "original_iso_sha256_matches_reference": True,
        "original_iso_region": disc["region"],
        "disc_iso9660_and_boot_layout_valid": disc["stage51_first_read_mapping_verified"],
        "single_track_cue_required_for_yabause_libretro_iso": False,
        "software_hle_bios_option_documented": True,
        "external_original_saturn_bios_required_for_this_path": False,
        "retroarch_binary_supplied": f["supplied"],
        "retroarch_elf_header_and_exec_permission_pass": f["local_binary_looks_usable"],
        "yabause_libretro_core_supplied": c["supplied"],
        "yabause_core_elf_header_pass": c["local_binary_looks_usable"],
        "host_display_declared_available": display_available,
        "host_executable_prerequisites_present": ready,
        "private_launch_command_written_by_helper": False,
        "actual_emulator_process_started": False,
        "saturn_game_booted": False,
        "original_ram_vram_trace_captured": False,
        "limitations": [
            "Yabause HLE BIOS is less accurate and not guaranteed to boot The Story of Thor 2.",
            "ELF header checks do not verify platform ABI, symbols, library dependencies or software correctness.",
            "Host display availability is an operator assertion and not a graphics-context validation.",
            "This ISO may lack the original CD-DA tracks and subchannel data.",
            "RetroArch/libretro backend requires installation; this program never downloads or runs executables.",
            "No private filenames, code, BIOS, RAM, sprite pixels, PC values or launch arguments appear here.",
        ],
    }
    private = {
        "schema_version": 1,
        "stage": "stage55_private_yabause_hle_run_sheet",
        "launch_argv_if_host_binaries_pass": cmd,
        "input_content_type": "original ISO (no CUE required by Yabause libretro)",
        "requires_original_bios": False,
        "yabause_core_setting": "yabause_force_hle_bios = enabled (restart core)",
        "operator_steps": [
            "Use a locally installed RetroArch executable and locally installed Yabause libretro core.",
            "Keep the original ISO offline/private; do not upload game assets or BIOS to GitHub.",
            "Open RetroArch > Quick Menu > Core Options > Force HLE BIOS; set enabled; restart content.",
            "If the game fails with HLE, report HLE compatibility failure; do not claim boot success.",
            "If retroarch and Yabause are available, run the recorded argv directly without a shell.",
            "Capture emulator version, screenshot and the Stage53 RAM watchpoints privately if the game boots.",
            "Avoid importing a different Saturn game's assets or emulated screenshots into public CI.",
        ],
        "sources": [SOURCE_LIBRETRO, SOURCE_CLI],
        "execution_not_attempted": True,
    }
    return public, private


def create_private_file(path: Path, obj: dict) -> None:
    rendered = json.dumps(obj, ensure_ascii=False, indent=2) + "\n"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        out.write(rendered)


def run_private(iso: Path, output_private: Path,
                frontend: Path | None = None, core: Path | None = None,
                display_available: bool = False) -> dict:
    public, private = readiness(iso, frontend, core, display_available=display_available)
    create_private_file(output_private, private)
    public["private_launch_command_written_by_helper"] = True
    return public


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso-private", type=Path, required=True)
    parser.add_argument("--retroarch-private", type=Path)
    parser.add_argument("--yabause-core-private", type=Path)
    parser.add_argument("--host-display-present", action="store_true",
                        help="Operator declares an available graphical session")
    parser.add_argument("--output-private", type=Path, required=True)
    args = parser.parse_args()
    result = run_private(args.iso_private, args.output_private,
                         args.retroarch_private, args.yabause_core_private,
                         args.host_display_present)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
