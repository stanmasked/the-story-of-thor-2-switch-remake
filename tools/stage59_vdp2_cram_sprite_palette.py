#!/usr/bin/env python3
"""Stage59: private offline VDP1 sprite-pixel -> VDP2 CRAM interpretation.

VDP2 registers and CRAM must originate from the SAME private frame as VDP1
VRAM. They are untrusted bytes unless independently captured from an emulator.
Palette lookup is NOT a completed Saturn compositor: priority, shadow, color
calculation, offsets, special modes and frame-buffer effects remain unresolved.

Never serialize private RGB values, raw palette words, memory addresses or
original game pixels. Synthetic-only fixtures are used in public GitHub CI.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path

from stage44_vdp1_vram_audit import parse_command_chain
from stage57_vdp1_texture_mode_geometry import (
    VDP1_VRAM_BYTES, decode_sprite_descriptor,
)
from stage58_vdp1_pixel_policy import interpret_texels_private
from stage57_vdp1_texture_mode_geometry import analyze_private as stage57_verify_iso

VDP2_CRAM_BYTES = 4096
VDP2_REG_BYTES = 512
MAX_TEXELS = 131072
# Sprite color-bit widths per VDP2 User's Manual, chapter 10.
# Types 8-F use alternate 8-bit framebuffer bit layouts. Not yet modeled.
SUPPORTED_PALETTE_TYPES = {0: 11, 1: 11, 2: 11, 3: 11,
                           4: 10, 5: 11, 6: 10, 7: 9}
VDP2_COLOR_MANUAL = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp2/hon/p03_40.htm"
VDP2_PALETTE_MANUAL = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp2/hon/p10_10.htm"
VDP2_SPRITE_MANUAL = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp2/hon/p09_10.htm"


def _word(raw: bytes, off: int) -> int:
    return int.from_bytes(raw[off:off + 2], "big")


def decode_vdp2_registers(regs: bytes) -> dict:
    """Internal VDP2 state, including sprite palette offset and CRAM mode."""
    if type(regs) is not bytes or len(regs) != VDP2_REG_BYTES:
        raise ValueError("VDP2 register snapshot must be exactly 512 bytes")
    ramctl = _word(regs, 0x0E)
    spctl = _word(regs, 0xE0)
    craofb = _word(regs, 0xE6)
    mode = (ramctl >> 12) & 3
    if mode == 3:
        raise ValueError("reserved VDP2 color RAM mode 3 is unsupported")
    return {
        "cram_mode": mode,
        "cram_capacity_entries": 2048 if mode == 1 else 1024,
        "sprite_type": spctl & 15,
        "sprite_palette_and_rgb_mixed": bool(spctl & 0x20),
        "sprite_color_ram_address_offset": (craofb >> 4) & 7,
        "cram_coefficient_table_enabled": bool(ramctl & 0x8000),
        "sprite_color_calculation_condition": (spctl >> 8) & 7,
    }


def rgb555_to_output8(word: int) -> tuple[int, int, int]:
    """Hardware-aligned RGB555 expansion: low three output bits are zero."""
    if type(word) is not int or not 0 <= word <= 0xFFFF:
        raise ValueError("RGB555 must be a 16-bit word")
    return ((word & 31) << 3, ((word >> 5) & 31) << 3,
            ((word >> 10) & 31) << 3)


def read_cram_rgb_private(cram: bytes, mode: int, index: int) -> tuple[tuple[int, int, int], bool]:
    """RGB and MSB special-color-calculation bit from a 4-KiB private dump."""
    if type(cram) is not bytes or len(cram) != VDP2_CRAM_BYTES:
        raise ValueError("VDP2 CRAM snapshot must be exactly 4096 bytes")
    if type(mode) is not int or mode not in (0, 1, 2):
        raise ValueError("VDP2 CRAM mode must be 0, 1 or 2")
    if type(index) is not int or index < 0 or index >= (2048 if mode == 1 else 1024):
        raise ValueError("VDP2 CRAM entry index outside hardware mode")
    if mode == 0:
        # CRAM mode 0 stores the same 1024 entries in both 2-KiB halves.
        word = _word(cram, index * 2)
        return rgb555_to_output8(word), bool(word & 0x8000)
    if mode == 1:
        word = _word(cram, index * 2)
        return rgb555_to_output8(word), bool(word & 0x8000)
    # Mode 2: 32-bit (CC, unused 7 bits, B8, G8, R8), big endian.
    word = int.from_bytes(cram[index*4:index*4+4], "big")
    return (word & 255, (word >> 8) & 255, (word >> 16) & 255), bool(word & 0x80000000)


def _valid_snapshots(vram: bytes, cram: bytes, regs: bytes) -> dict:
    if type(vram) is not bytes or len(vram) != VDP1_VRAM_BYTES:
        raise ValueError("VDP1 VRAM must be a complete 524288-byte dump")
    if type(cram) is not bytes or len(cram) != VDP2_CRAM_BYTES:
        raise ValueError("VDP2 CRAM must be a complete 4096-byte dump")
    return decode_vdp2_registers(regs)


def resolve_pixel_private(kind: str, pixel_code: int | None,
                          cram: bytes, state: dict) -> tuple[str, tuple[int, int, int] | None]:
    """Resolve a *candidate* color. This is not an onscreen composited pixel."""
    if kind in ("zero_transparent", "end_code_transparent", "after_second_end_code"):
        if pixel_code is not None:
            raise ValueError("transparent pixel must have no color code")
        return kind, None
    if type(pixel_code) is not int or not 0 <= pixel_code <= 0xFFFF:
        raise ValueError("invalid private VDP1 pixel code")
    if kind in ("direct_rgb_code", "lookup_rgb_code"):
        if not pixel_code & 0x8000:
            raise ValueError("direct RGB source lacks RGB marker")
        return "preblend_rgb555", rgb555_to_output8(pixel_code)
    if kind == "unsupported_direct_mode_non_rgb_word":
        return "unresolved_non_rgb_direct_code", None
    if kind not in ("color_bank_code", "lookup_color_bank_code"):
        raise ValueError("unknown Stage58 pixel semantic kind")
    sprite_type = state["sprite_type"]
    if sprite_type not in SUPPORTED_PALETTE_TYPES:
        return "unresolved_eight_bit_sprite_type", None
    # VDP2 SPCLMD controls interpretation of framebuffer bit15.
    if state["sprite_palette_and_rgb_mixed"] and pixel_code & 0x8000:
        return "mixed_framebuffer_rgb_candidate", rgb555_to_output8(pixel_code)
    dc_mask = (1 << SUPPORTED_PALETTE_TYPES[sprite_type]) - 1
    dot_data = pixel_code & dc_mask
    mode = state["cram_mode"]
    if mode == 2:
        # VDP2's mode-2 address offset uses different byte addressing;
        # do not guess the SPCAOS translation until independently verified.
        return "unresolved_mode2_sprite_cram_address", None
    idx = (dot_data + state["sprite_color_ram_address_offset"] * 0x200)
    idx &= (0x3FF if mode == 0 else 0x7FF)
    if (mode == 1 and state["cram_coefficient_table_enabled"]
            and idx >= 1024):
        return "unresolved_cram_coefficient_table_partition", None
    rgb, _cc = read_cram_rgb_private(cram, mode, idx)
    # Shadow, priority, special color calculations and compositing still
    # depend on VDP2 state; distinguish this from final RGB.
    return "palette_rgb_candidate_not_composited", rgb


def summarize_private(vram: bytes, cram: bytes, regs: bytes,
                      max_commands: int = 512,
                      max_texels: int = MAX_TEXELS) -> dict:
    state = _valid_snapshots(vram, cram, regs)
    if type(max_commands) is not int or not 1 <= max_commands <= 4096:
        raise ValueError("invalid command budget")
    if type(max_texels) is not int or not 1 <= max_texels <= MAX_TEXELS:
        raise ValueError("invalid private texel budget")
    walk, positions = parse_command_chain(vram, max_commands)
    categories = Counter()
    processed = inspected = malformed = skipped = limited = 0
    for off in sorted(positions):
        ctrl = _word(vram, off)
        if ctrl & 0x8000 or ctrl & 15 not in (0, 1, 2):
            continue
        try:
            desc = decode_sprite_descriptor(vram, off)
        except ValueError:
            malformed += 1
            continue
        if desc["skipped_by_jump_control"]:
            skipped += 1
            continue
        count = desc["width_pixels"] * desc["height_pixels"]
        if count > max_texels - inspected:
            limited += 1
            continue
        rows = interpret_texels_private(vram, desc)
        for row in rows:
            for label, code in row:
                category, _rgb = resolve_pixel_private(label, code, cram, state)
                categories[category] += 1
        inspected += count
        processed += 1
    return {
        "schema_version": 1,
        "stage": "stage59_vdp2_cram_sprite_palette_resolution",
        "command_walk": walk,
        "vdp2_cram_mode": state["cram_mode"],
        "vdp2_cram_entries_per_hardware_mode": state["cram_capacity_entries"],
        "sprite_type": state["sprite_type"],
        "sprite_color_mode_mixed": state["sprite_palette_and_rgb_mixed"],
        "sprite_color_ram_offset_register_nonzero":
            bool(state["sprite_color_ram_address_offset"]),
        "sprites_interpreted": processed,
        "malformed_sprite_records": malformed,
        "skipped_sprite_records": skipped,
        "budget_limited_sprite_records": limited,
        "source_texels_inspected": inspected,
        "candidate_color_categories": dict(sorted(categories.items())),
        "private_vdp2_colors_or_addresses_exported": False,
        "original_emulator_capture_authenticated": False,
        "completed_saturn_frame_compositing": False,
        "game_sprite_restoration_proven": False,
        "limitations": [
            "Palette entries are only candidates; priority, shadow and color calculation may change display.",
            "Mode 2 sprite-address mapping and sprite types 8-F are explicitly unresolved.",
            "VDP2 registers, color RAM and VDP1 VRAM must represent the same instant.",
            "This tool neither authenticates emulator origin nor exports copyrighted pixel bytes.",
        ],
    }


def analyze_private(iso: Path, vram: Path | None = None,
                    cram: Path | None = None, regs: Path | None = None) -> dict:
    if any(x is not None for x in (vram, cram, regs)) and not all(
            x is not None for x in (vram, cram, regs)):
        raise ValueError("supply VDP1 VRAM, VDP2 CRAM and register dump together")
    boot = stage57_verify_iso(iso)
    result = {
        "schema_version": 1,
        "stage": "stage59_vdp2_cram_sprite_palette_resolution",
        "pinned_original_iso_sha256_matches": boot["private_original_iso_sha256_verified"],
        "stage45_46_static_sh2_roles_unique": True,
        "all_three_video_snapshots_supplied": vram is not None,
        "real_emulator_execution_proven": False,
    }
    if vram is not None:
        sizes = ((vram, VDP1_VRAM_BYTES), (cram, VDP2_CRAM_BYTES),
                 (regs, VDP2_REG_BYTES))
        if any(path.stat().st_size != size for path, size in sizes):
            raise ValueError("private video snapshot size mismatch")
        result["untrusted_offline_video_semantics"] = summarize_private(
            vram.read_bytes(), cram.read_bytes(), regs.read_bytes())
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iso-private", required=True, type=Path)
    ap.add_argument("--vdp1-vram-private", type=Path)
    ap.add_argument("--vdp2-cram-private", type=Path)
    ap.add_argument("--vdp2-regs-private", type=Path)
    ap.add_argument("--output-private", type=Path)
    args = ap.parse_args()
    report = analyze_private(args.iso_private, args.vdp1_vram_private,
                             args.vdp2_cram_private, args.vdp2_regs_private)
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output_private is None:
        print(output, end="")
    else:
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(args.output_private, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(output)


if __name__ == "__main__":
    main()
