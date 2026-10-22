#!/usr/bin/env python3
"""Stage57: decode documented Saturn VDP1 sprite mode/geometry from PRIVATE VRAM.

Stage10 showed that file-block lengths alone do not resolve 4/8/16 bpp.
A *real* VDP1 command provides three independent fields: CMDPMOD (bits 5..3),
CMDSRCA (8-byte texture base), and CMDSIZE (width / 8, height).
This module parses those fields and bounds-checks the memory interval.

Raw texels can be unpacked in RAM for private research, but NO original pixels,
individual texture addresses or commands are exported into aggregate reports.
A supplied VRAM dump is NOT authenticated as game execution.
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path

from stage18_writer_guard_flow import iso_file_payload
from stage44_vdp1_vram_audit import (
    COMMAND_BYTES, VDP1_VRAM_BYTES, parse_command_chain,
)
from stage45_vdp1_command_copy import find_vdp1_writers
from stage46_vdp1_submit_gate import find_submit_gates
from stage50_sh2_load_mapping_evidence import REFERENCE_ISO_SHA256, _iso_sha256

# Official Sega Saturn VDP1 User's Manual, chapter 6: CMDPMOD bits 5..3.
COLOR_MODES = {
    0: ("4bpp_color_bank_16", 4),
    1: ("4bpp_lookup_table_16", 4),
    2: ("8bpp_color_bank_64", 8),
    3: ("8bpp_color_bank_128", 8),
    4: ("8bpp_color_bank_256", 8),
    5: ("16bpp_direct_rgb555", 16),
}
SPRITE_COMMANDS = (0, 1, 2)
MAX_TEXELS = 504 * 255
REFERENCE_MANUAL = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp1/hon/p06_36.htm"


def _word(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def decode_sprite_descriptor(vram: bytes, offset: int) -> dict:
    """Private per-command details, never serialize this dict to public stdout."""
    if type(vram) is not bytes or len(vram) != VDP1_VRAM_BYTES:
        raise ValueError("requires a full 524288-byte private VDP1 VRAM snapshot")
    if type(offset) is not int or offset < 0 or offset % COMMAND_BYTES:
        raise ValueError("VDP1 command address must be 32-byte aligned")
    if offset + COMMAND_BYTES > len(vram):
        raise ValueError("command position is outside VDP1 VRAM")
    ctrl, pmod = _word(vram, offset), _word(vram, offset + 4)
    if ctrl & 0x8000:
        raise ValueError("end-bit terminator is not a sprite command")
    kind = ctrl & 15
    if kind not in SPRITE_COMMANDS:
        raise ValueError("VDP1 command is not a sprite type")
    mode = (pmod >> 3) & 7
    mode_info = COLOR_MODES.get(mode)
    if mode_info is None:
        raise ValueError("VDP1 color modes 6 and 7 are prohibited")
    size = _word(vram, offset + 10)
    # High two bits of the width word are reserved; width unit is eight pixels.
    reserved_size_bits = (size >> 14) & 3
    width, height = ((size >> 8) & 0x3F) * 8, size & 0xFF
    if reserved_size_bits or width == 0 or height == 0:
        raise ValueError("sprite size is zero or has reserved bits set")
    pixels = width * height
    if pixels > MAX_TEXELS:
        raise ValueError("sprite exceeds conservative texture pixel bound")
    mode_name, bpp = mode_info
    texture_bytes = pixels * bpp // 8
    texture_start = _word(vram, offset + 8) * 8
    texture_end = texture_start + texture_bytes
    if texture_end > VDP1_VRAM_BYTES:
        raise ValueError("sprite texture would read past VDP1 VRAM")
    color_control_word = _word(vram, offset + 6)
    lut_start = color_control_word * 8 if mode == 1 else None
    if lut_start is not None and lut_start + 32 > VDP1_VRAM_BYTES:
        raise ValueError("16-entry lookup table would read past VDP1 VRAM")
    return {
        "command_offset_private": offset,
        "sprite_type": kind,
        "control_mode": (ctrl >> 12) & 7,
        "skipped_by_jump_control": bool(ctrl & 0x4000),
        "color_mode": mode,
        "color_mode_name": mode_name,
        "bits_per_pixel": bpp,
        "width_pixels": width,
        "height_pixels": height,
        "texture_bytes": texture_bytes,
        "texture_address_private": texture_start,
        "texture_end_private": texture_end,
        "color_lut_address_private": lut_start,
        "color_bank_or_lut_word_private": color_control_word,
        "transparent_pixel_disabled": bool(pmod & 0x40),
        "end_code_disabled": bool(pmod & 0x80),
        "source_might_overlap_current_command_slot":
            texture_start < offset + COMMAND_BYTES and offset < texture_end,
    }


def unpack_texels_private(vram: bytes, descriptor: dict) -> tuple[int, ...]:
    """Decode raw indices/RGB555 words only, without applying transparency/end codes.

    This returns copyrighted pixels on private data: NEVER include in JSON
    reports or public test fixtures. Does not rasterize geometry/coordinates.
    """
    if type(vram) is not bytes or len(vram) != VDP1_VRAM_BYTES:
        raise ValueError("private VDP1 VRAM size invalid")
    if type(descriptor) is not dict:
        raise ValueError("descriptor must be privately decoded first")
    start, end = descriptor["texture_address_private"], descriptor["texture_end_private"]
    width, height, bpp = (descriptor["width_pixels"],
                          descriptor["height_pixels"], descriptor["bits_per_pixel"])
    if (type(start) is not int or type(end) is not int or
            type(width) is not int or type(height) is not int or
            bpp not in (4, 8, 16) or width % 8 != 0 or
            not 1 <= width <= 504 or not 1 <= height <= 255 or
            not 0 <= start < end <= len(vram) or
            end - start != width * height * bpp // 8):
        raise ValueError("invalid private sprite geometry or texture span")
    raw = vram[start:end]
    if bpp == 4:
        pixels = tuple(p for value in raw for p in (value >> 4, value & 15))
    elif bpp == 8:
        pixels = tuple(raw)
    else:
        pixels = tuple(_word(raw, p) for p in range(0, len(raw), 2))
    if len(pixels) != width * height:
        raise ValueError("texel decoder returned an invalid count")
    return pixels


def analyze_vram_geometry(vram: bytes, max_commands: int = 4096) -> dict:
    """Aggregate *offline* VDP1 command geometry from an untrusted private dump."""
    chain, positions = parse_command_chain(vram, max_commands)
    modes, bpps, sprite_kinds = Counter(), Counter(), Counter()
    valid, malformed, skipped, overlaps, lut = 0, 0, 0, 0, 0
    texture_bytes_total = 0
    sizes: list[int] = []
    for offset in sorted(positions):
        ctrl = _word(vram, offset)
        # Stage44 includes the END-bit terminator in visited positions;
        # it is NOT a malformed sprite command and must not be decoded.
        if ctrl & 0x8000 or (ctrl & 15) not in SPRITE_COMMANDS:
            continue
        try:
            descriptor = decode_sprite_descriptor(vram, offset)
        except ValueError:
            malformed += 1
            continue
        if descriptor["skipped_by_jump_control"]:
            skipped += 1
            continue
        valid += 1
        modes[str(descriptor["color_mode"])] += 1
        bpps[str(descriptor["bits_per_pixel"])] += 1
        sprite_kinds[str(descriptor["sprite_type"])] += 1
        texture_bytes_total += descriptor["texture_bytes"]
        sizes.append(descriptor["texture_bytes"])
        overlaps += bool(descriptor["source_might_overlap_current_command_slot"])
        lut += descriptor["color_lut_address_private"] is not None
    return {
        "schema_version": 1,
        "stage": "stage57_vdp1_texture_mode_geometry",
        "vdp1_chain": chain,
        "visited_sprite_records_with_valid_mode_and_bounds": valid,
        "malformed_or_out_of_bounds_sprite_records": malformed,
        "skipped_sprite_records_not_counted_as_draws": skipped,
        "sprite_entries_by_color_mode": dict(sorted(modes.items())),
        "sprite_entries_by_bits_per_pixel": dict(sorted(bpps.items())),
        "sprite_entries_by_command_type": dict(sorted(sprite_kinds.items())),
        "lut_sprite_entries_with_in_bounds_16color_table": lut,
        "sprite_texture_source_overlaps_own_command_slot_candidates": overlaps,
        "texture_source_bytes_summed_over_command_references": texture_bytes_total,
        "median_valid_sprite_source_span_bytes": statistics.median(sizes) if sizes else None,
        "pixel_format_disambiguated_by_command_metadata": bool(valid),
        "disc_resource_block_to_vdp1_source_mapping_proven": False,
        "source_snapshot_authenticated_as_live_emulator": False,
        "rendered_sprite_pixels_confirmed": False,
        "raw_pixel_values_or_private_vram_addresses_exported": False,
        "limitations": [
            "VDP1 command fields resolve format/dimensions for provided command bytes, not for arbitrary ISO file blocks.",
            "Skip control is not a draw event; command walker remains bounded and does not emulate the GPU.",
            "Texture data can contain end-codes, transparency, LUT/bank references and flip/scaling rules not rendered here.",
            "No authenticated original-game VDP1 VRAM snapshot was available for this stage.",
        ],
    }


def analyze_private(iso: Path, vram_path: Path | None = None) -> dict:
    if _iso_sha256(iso) != REFERENCE_ISO_SHA256:
        raise ValueError("original Saturn ISO SHA-256 does not match pinned reference")
    code = iso_file_payload(iso)
    writers, gates = find_vdp1_writers(code), find_submit_gates(code)
    if len(writers) != 1 or len(gates) != 1:
        raise ValueError("original Stage45/46 VDP1 roles are not unique")
    result = {
        "schema_version": 1,
        "stage": "stage57_vdp1_texture_mode_geometry",
        "private_original_iso_sha256_verified": True,
        "original_sh2_vdp1_command_copy_writer_count": len(writers),
        "original_sh2_submit_gate_count": len(gates),
        "official_sprite_color_mode_count": len(COLOR_MODES),
        "documented_color_depths": [4, 8, 16],
        "official_vdp1_manual": REFERENCE_MANUAL,
        "private_vdp1_dump_provided": vram_path is not None,
        "live_emulator_capture_authenticated": False,
    }
    if vram_path is not None:
        if vram_path.stat().st_size != VDP1_VRAM_BYTES:
            raise ValueError("private VRAM snapshot must be exactly 524288 bytes")
        result["untrusted_offline_vram_geometry"] = analyze_vram_geometry(vram_path.read_bytes())
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso-private", type=Path, required=True)
    parser.add_argument("--vdp1-vram-private", type=Path)
    parser.add_argument("--output-private", type=Path)
    args = parser.parse_args()
    report = analyze_private(args.iso_private, args.vdp1_vram_private)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output_private:
        import os
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(args.output_private, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
