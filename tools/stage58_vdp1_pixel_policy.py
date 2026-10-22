#!/usr/bin/env python3
"""Stage58: offline VDP1 sprite pixel-policy interpreter, NOT a renderer.

Implements Sega-documented zero transparency, two-end-code-per-scanline
termination, color bank code composition and 16-entry VRAM lookup-table
selection. Output intended for original game material stays private: aggregate
reports never contain pixels, RGB values, lookup-table contents or addresses.
A supplied RAM/VRAM dump is unauthenticated and cannot prove game execution.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path

from stage44_vdp1_vram_audit import COMMAND_BYTES, parse_command_chain
from stage57_vdp1_texture_mode_geometry import (
    VDP1_VRAM_BYTES, decode_sprite_descriptor,
    unpack_texels_private, analyze_private as stage57_private,
)

# Sega VDP1 User's Manual, chapter 6, color mode and ECD/SPD processing.
# 64/128-color modes still use the FULL raw 8-bit end code 0xFF.
END_CODES = {0: 0xF, 1: 0xF, 2: 0xFF, 3: 0xFF, 4: 0xFF, 5: 0x7FFF}
INDEX_MASK = {0: 0xF, 1: 0xF, 2: 0x3F, 3: 0x7F, 4: 0xFF}
MAX_OFFLINE_TEXELS = 262144
REFERENCE_END = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp1/hon/p06_34.htm"
REFERENCE_COLOR = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp1/hon/p06_36.htm"


def _valid_private(vram: bytes, d: dict) -> None:
    if type(vram) is not bytes or len(vram) != VDP1_VRAM_BYTES:
        raise ValueError("a full 524288-byte VDP1 dump is required")
    if type(d) is not dict or d.get("color_mode") not in END_CODES:
        raise ValueError("expected a decoded valid Stage57 VDP1 sprite descriptor")
    # Revalidate directly against the same VRAM, rather than trusting
    # caller-crafted addresses, SPD/ECD flags, dimensions or color fields.
    off = d.get("command_offset_private")
    if type(off) is not int or off < 0 or off % COMMAND_BYTES:
        raise ValueError("invalid private VDP1 command address")
    authentic = decode_sprite_descriptor(vram, off)
    if authentic != d:
        raise ValueError("private descriptor disagrees with supplied VRAM")


def _palette_entry(vram: bytes, address: int, index: int) -> int:
    at = address + index * 2
    if at < 0 or at + 2 > len(vram):
        raise ValueError("VDP1 look-up entry outside VRAM")
    return int.from_bytes(vram[at:at + 2], "big")


def interpret_texels_private(vram: bytes, descriptor: dict) -> tuple[tuple[tuple[str, int | None], ...], ...]:
    """Interpret one private source image, preserving original scanline geometry.

    Pixel tuple is (semantic category, raw framebuffer code or None).
    This is not a 2D sprite renderer: it does not implement flips, scale,
    mesh, clipping, color calculation, VDP2 CRAM or frame-buffer writes.
    Never publish its per-pixel output from an original game's VRAM.
    """
    _valid_private(vram, descriptor)
    values = unpack_texels_private(vram, descriptor)
    mode = descriptor["color_mode"]
    width, height = descriptor["width_pixels"], descriptor["height_pixels"]
    ecd = descriptor["end_code_disabled"]
    spd = descriptor["transparent_pixel_disabled"]
    bank = descriptor["color_bank_or_lut_word_private"]
    lut = descriptor["color_lut_address_private"]
    rows = []
    for y in range(height):
        ends = 0
        line = []
        for val in values[y * width:(y + 1) * width]:
            if ends >= 2:
                line.append(("after_second_end_code", None))
                continue
            if not ecd and val == END_CODES[mode]:
                ends += 1
                line.append(("end_code_transparent", None))
                continue
            if not spd and val == 0:
                line.append(("zero_transparent", None))
                continue
            if mode == 1:
                word = _palette_entry(vram, lut, val)
                label = "lookup_rgb_code" if word & 0x8000 else "lookup_color_bank_code"
                line.append((label, word))
            elif mode == 5:
                # RGB code is only defined for words with bit 15 set. If
                # ECD=1, raw 0x7FFF is not an RGB555 code; do not invent RGB.
                if val & 0x8000:
                    line.append(("direct_rgb_code", val))
                else:
                    line.append(("unsupported_direct_mode_non_rgb_word", val))
            else:
                mask = INDEX_MASK[mode]
                framebuffer_code = (bank & ~mask) | (val & mask)
                line.append(("color_bank_code", framebuffer_code))
        rows.append(tuple(line))
    return tuple(rows)


def summarize_pixel_policy_private(vram: bytes, descriptor: dict) -> dict:
    """Safe aggregate counts, *never* individual pixel codes."""
    pixels = interpret_texels_private(vram, descriptor)
    categories = Counter(label for row in pixels for label, _ in row)
    mode = descriptor["color_mode"]
    return {
        "color_mode": mode,
        "texels_inspected": descriptor["width_pixels"] * descriptor["height_pixels"],
        "pixel_policy_categories": dict(sorted(categories.items())),
        "scanlines_with_two_end_codes":
            sum(sum(label == "end_code_transparent" for label, _ in row) >= 2
                for row in pixels),
        "unsupported_ecd0_spd1_combination":
            not descriptor["end_code_disabled"] and descriptor["transparent_pixel_disabled"],
        "lookup_table_used": mode == 1,
        "color_bank_codes_require_external_vdp2_palette": mode in (0, 2, 3, 4),
        "rgb_image_rendered": False,
    }


def analyze_vram_pixel_policy(vram: bytes, max_commands: int = 1024,
                              max_texels: int = MAX_OFFLINE_TEXELS) -> dict:
    if type(vram) is not bytes or len(vram) != VDP1_VRAM_BYTES:
        raise ValueError("complete private VDP1 VRAM dump required")
    if type(max_texels) is not int or not 1 <= max_texels <= MAX_OFFLINE_TEXELS:
        raise ValueError("invalid private offline texel budget")
    chain, positions = parse_command_chain(vram, max_commands)
    cats = Counter()
    inspected = 0
    valid = invalid = skipped = budget_skipped = lookup = 0
    incompatible_flags = two_end_rows = 0
    for off in sorted(positions):
        ctrl = int.from_bytes(vram[off:off + 2], "big")
        if ctrl & 0x8000 or ctrl & 0xF not in (0, 1, 2):
            continue
        try:
            d = decode_sprite_descriptor(vram, off)
        except ValueError:
            invalid += 1
            continue
        if d["skipped_by_jump_control"]:
            skipped += 1
            continue
        n = d["width_pixels"] * d["height_pixels"]
        if n > max_texels - inspected:
            budget_skipped += 1
            continue
        record = summarize_pixel_policy_private(vram, d)
        valid += 1
        inspected += n
        cats.update(record["pixel_policy_categories"])
        two_end_rows += record["scanlines_with_two_end_codes"]
        incompatible_flags += record["unsupported_ecd0_spd1_combination"]
        lookup += record["lookup_table_used"]
    return {
        "schema_version": 1,
        "stage": "stage58_vdp1_pixel_policy",
        "command_walk_aggregate": chain,
        "sprite_commands_interpreted_within_texel_budget": valid,
        "malformed_sprite_descriptors": invalid,
        "skipped_sprite_descriptors": skipped,
        "sprite_descriptors_not_interpreted_due_to_budget": budget_skipped,
        "source_texels_inspected": inspected,
        "pixel_policy_categories": dict(sorted(cats.items())),
        "scanlines_with_two_end_codes": two_end_rows,
        "commands_using_16color_lookup": lookup,
        "commands_with_unsupported_ecd0_spd1_pair": incompatible_flags,
        "actual_original_saturn_execution_observed": False,
        "vd p2_color_ram_and_palette_mapping_verified".replace(" ", ""): False,
        "rendered_original_sprites": False,
        "raw_private_pixels_or_framebuffer_codes_exported": False,
        "limitations": [
            "Zero transparency and end code operate on raw texture codes, not RGB output.",
            "The two-end-code rule resets for each source scanline.",
            "Color-bank codes need VDP2 CRAM and sprite priority/type configuration before RGB rendering.",
            "No flip, scale, mesh, clipping or color-operation rasterization is performed.",
            "Offline VRAM bytes do not authenticate emulator origin or actual drawing.",
        ],
    }


def run_private(iso: Path, vram: Path | None = None) -> dict:
    base = stage57_private(iso)
    result = {
        "schema_version": 1,
        "stage": "stage58_vdp1_pixel_policy",
        "pinned_private_original_iso_verified": base["private_original_iso_sha256_verified"],
        "static_sh2_copy_and_submit_roles_unique":
            base["original_sh2_vdp1_command_copy_writer_count"] == 1
            and base["original_sh2_submit_gate_count"] == 1,
        "private_vram_supplied": vram is not None,
        "live_vdp1_capture_authenticated": False,
        "rendered_gameplay_graphics": False,
    }
    if vram is not None:
        if vram.stat().st_size != VDP1_VRAM_BYTES:
            raise ValueError("private VRAM must be exactly 524288 bytes")
        result["untrusted_offline_vram_policy"] = analyze_vram_pixel_policy(vram.read_bytes())
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iso-private", required=True, type=Path)
    ap.add_argument("--vdp1-vram-private", type=Path)
    ap.add_argument("--output-private", type=Path)
    args = ap.parse_args()
    output = json.dumps(run_private(args.iso_private, args.vdp1_vram_private),
                        ensure_ascii=False, indent=2) + "\n"
    if args.output_private:
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(args.output_private, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
