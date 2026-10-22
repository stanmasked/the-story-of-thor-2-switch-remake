#!/usr/bin/env python3
"""Stage60: bounded, PRIVATE VDP2 sprite priority/shadow contract audit.

Interprets documented VDP2 SPCTL, SDCTL, PRISx, CCRSx and CCCTL, and
documented 16-bit VDP1 framebuffer sprite types 0-7. This classifies
possible priority, normal shadow, and MSB shadow behavior; it does NOT
render the final framebuffer, prove VDP1 wrote these bits, or authenticate
an emulator capture. RGB/pixel words and private addresses stay offline.
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
from stage59_vdp2_cram_sprite_palette import (
    VDP2_CRAM_BYTES, VDP2_REG_BYTES, MAX_TEXELS, decode_vdp2_registers,
    resolve_pixel_private, analyze_private as stage59_analyze,
)

REFERENCE_BITS = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp2/hon/p15_30.htm"
REFERENCE_TYPES = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp2/hon/p09_10.htm"
REFERENCE_SHADOW = "https://docs.exodusemulator.com/Archives/SSDDV25/segahtml/info/hon/stn25.htm"

# Sprite type: (dot-color width, color-calc selector width,
#               priority selector width, SD field present at bit15).
# Type diagrams are in Sega VDP2 User's Manual Figure 9.1.
TYPE_LAYOUTS = {
    0: (11, 3, 2, False),
    1: (11, 2, 3, False),
    2: (11, 3, 1, True),
    3: (11, 2, 2, True),
    4: (10, 3, 2, True),
    5: (11, 1, 3, True),
    6: (10, 2, 3, True),
    7: (9, 3, 3, True),
}
SHADOW_TARGET_NAMES = ("NBG0", "NBG1", "NBG2", "NBG3", "RBG0", "BACK")


def _word(raw: bytes, off: int) -> int:
    return int.from_bytes(raw[off:off + 2], "big")


def decode_compositor_registers(regs: bytes) -> dict:
    """Private register-only state; no source pixels or original addresses."""
    base = decode_vdp2_registers(regs)
    spctl, sdctl, ccctl = (_word(regs, 0xE0), _word(regs, 0xE2),
                            _word(regs, 0xEC))
    priorities = []
    ratios = []
    for pair in range(4):
        pr = _word(regs, 0xF0 + pair * 2)
        cr = _word(regs, 0x100 + pair * 2)
        priorities.extend((pr & 7, (pr >> 8) & 7))
        ratios.extend((cr & 31, (cr >> 8) & 31))
    state = {
        **base,
        "sprite_window_enabled": bool(spctl & 0x10),
        "sprite_color_calculation_enabled": bool(ccctl & 0x40),
        "sprite_color_calculation_ratio_mode_second_layer": bool(ccctl & 0x200),
        "sprite_color_calculation_mode_add": bool(ccctl & 0x100),
        "shadow_targets_enabled": tuple(
            name for bit, name in enumerate(SHADOW_TARGET_NAMES)
            if sdctl & (1 << bit)
        ),
        "transparent_msb_shadow_selected": bool(sdctl & 0x100),
        "sprite_priorities": tuple(priorities),
        "sprite_color_ratios": tuple(ratios),
        "msb_shadow_possible_from_registers":
            2 <= base["sprite_type"] <= 7
            and not bool(spctl & 0x10)
            and not base["sprite_palette_and_rgb_mixed"],
    }
    return state


def decode_sprite_control_bits(code: int, sprite_type: int) -> dict:
    """One original-specific FRAMEBUFFER word, private-only output."""
    if type(code) is not int or not 0 <= code <= 0xFFFF:
        raise ValueError("sprite code must be a 16-bit unsigned integer")
    if type(sprite_type) is not int or not 0 <= sprite_type <= 15:
        raise ValueError("invalid sprite type")
    if sprite_type not in TYPE_LAYOUTS:
        return {
            "layout_supported": False, "priority_selector": None,
            "color_ratio_selector": None, "shadow_flag": None,
            "normal_shadow_reserved_code": None,
        }
    color_width, ratio_width, pri_width, sd_present = TYPE_LAYOUTS[sprite_type]
    if color_width + ratio_width + pri_width + int(sd_present) != 16:
        raise ValueError("invalid VDP2 type bit-width contract")
    dot_mask = (1 << color_width) - 1
    return {
        "layout_supported": True,
        "priority_selector": (code >> (color_width + ratio_width))
                             & ((1 << pri_width) - 1),
        "color_ratio_selector": (code >> color_width)
                               & ((1 << ratio_width) - 1),
        "shadow_flag": bool(code & 0x8000) if sd_present else None,
        "normal_shadow_reserved_code": (
            (code & dot_mask) == (dot_mask & ~1)),
    }


def classify_pixel_private(kind: str, code: int | None, state: dict) -> dict:
    """Partial compositor attributes, NEVER a rendered pixel."""
    if kind in ("zero_transparent", "end_code_transparent",
                "after_second_end_code"):
        if code is not None:
            raise ValueError("transparent texel must not carry a color word")
        return {"classification": "source_transparent",
                "priority_selector": None, "priority_number": None,
                "color_ratio_selector": None, "selected_color_ratio": None}
    if type(code) is not int or not 0 <= code <= 0xFFFF:
        raise ValueError("unsupported pixel code")
    if kind in ("direct_rgb_code", "lookup_rgb_code"):
        if not code & 0x8000:
            raise ValueError("direct RGB must have bit15 set")
        return {"classification": "rgb_candidate_priority_register_zero",
                "priority_selector": 0,
                "priority_number": state["sprite_priorities"][0],
                "color_ratio_selector": 0,
                "selected_color_ratio": state["sprite_color_ratios"][0]}
    if kind == "unsupported_direct_mode_non_rgb_word":
        return {"classification": "unsupported_direct_mode_word",
                "priority_selector": None, "priority_number": None,
                "color_ratio_selector": None, "selected_color_ratio": None}
    if kind not in ("color_bank_code", "lookup_color_bank_code"):
        raise ValueError("unsupported Stage58 pixel category")
    bits = decode_sprite_control_bits(code, state["sprite_type"])
    if not bits["layout_supported"]:
        return {"classification": "unresolved_eight_bit_sprite_type",
                "priority_selector": None, "priority_number": None,
                "color_ratio_selector": None, "selected_color_ratio": None}
    pi, ri = bits["priority_selector"], bits["color_ratio_selector"]
    category = "palette_priority_candidate"
    if bits["normal_shadow_reserved_code"]:
        category = ("normal_shadow_reserved_code_targets_enabled" if
                    state["shadow_targets_enabled"] else
                    "normal_shadow_reserved_code_targets_disabled")
    elif bits["shadow_flag"]:
        if state["msb_shadow_possible_from_registers"]:
            if code == 0x8000:
                category = ("transparent_msb_shadow_candidate" if
                            state["transparent_msb_shadow_selected"] else
                            "transparent_msb_shadow_not_selected")
                # Sega notes transparent MSB shadow uses sprite PRISA register 0.
                pi = 0
            else:
                category = "opaque_msb_shadow_candidate"
        else:
            category = "bit15_set_but_msb_shadow_configuration_ineligible"
    return {
        "classification": category,
        "priority_selector": pi,
        "priority_number": state["sprite_priorities"][pi],
        "color_ratio_selector": ri,
        "selected_color_ratio": state["sprite_color_ratios"][ri],
    }


def audit_offline(vram: bytes, cram: bytes, regs: bytes,
                  max_commands: int = 512, max_texels: int = MAX_TEXELS) -> dict:
    """Read offline snapshots together; return privacy-safe counters only."""
    if type(vram) is not bytes or len(vram) != VDP1_VRAM_BYTES:
        raise ValueError("exact 512-KiB VDP1 VRAM snapshot required")
    if type(cram) is not bytes or len(cram) != VDP2_CRAM_BYTES:
        raise ValueError("exact 4096-byte VDP2 CRAM snapshot required")
    if type(max_commands) is not int or not 1 <= max_commands <= 4096:
        raise ValueError("invalid command budget")
    if type(max_texels) is not int or not 1 <= max_texels <= MAX_TEXELS:
        raise ValueError("invalid texel budget")
    state = decode_compositor_registers(regs)
    chain, positions = parse_command_chain(vram, max_commands)
    kinds = Counter()
    priority_values = Counter()
    zero_priority = no_selection = malformed = skipped = limited = count = 0
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
        size = desc["width_pixels"] * desc["height_pixels"]
        if size > max_texels - count:
            limited += 1
            continue
        for line in interpret_texels_private(vram, desc):
            for kind, code in line:
                # Ensure Stage59 interprets the same supplied CRAM and
                # register mode, but do not export the candidate color.
                resolve_pixel_private(kind, code, cram, state)
                detail = classify_pixel_private(kind, code, state)
                kinds[detail["classification"]] += 1
                priority = detail["priority_number"]
                if priority is None:
                    no_selection += 1
                else:
                    priority_values[str(priority)] += 1
                    zero_priority += priority == 0
        count += size
    return {
        "schema_version": 1,
        "stage": "stage60_vdp2_sprite_priority_shadow_contract",
        "command_chain_aggregate": chain,
        "sprite_type": state["sprite_type"],
        "sprite_priorities_declared": list(state["sprite_priorities"]),
        "sprite_color_ratios_declared": list(state["sprite_color_ratios"]),
        "shadow_targets_declared": list(state["shadow_targets_enabled"]),
        "transparent_msb_shadow_selected": state["transparent_msb_shadow_selected"],
        "msb_shadow_possible_from_registers": state["msb_shadow_possible_from_registers"],
        "sprite_color_calculation_enabled": state["sprite_color_calculation_enabled"],
        "sprites_malformed": malformed,
        "sprites_skipped": skipped,
        "sprites_skipped_due_to_budget": limited,
        "source_texels_inspected": count,
        "pixel_classes": dict(sorted(kinds.items())),
        "priority_value_counts_in_selected_registers": dict(sorted(priority_values.items())),
        "pixels_with_priority_zero_candidate": zero_priority,
        "pixels_without_priority_selector": no_selection,
        "authenticated_original_saturn_frame": False,
        "vd p1_framebuffer_write_events_verified".replace(" ", ""): False,
        "vdp2_full_shadow_and_color_calculation_rendered": False,
        "rendered_original_game_pixels": False,
        "private_pixel_words_or_addresses_exported": False,
        "limitations": [
            "Input textures are not verified framebuffer output; type-dependent interpretation is conditional.",
            "MSB shadow classifications are candidates, not proof that VDP1 set its MSBON bit.",
            "Normal shadow reserved codes are not normal palette colors even if targets are disabled.",
            "Priority 0 is a candidate transparent pixel under VDP2; full screen priority tie-break is absent.",
            "No background screen, window, color calculation, mesh or shadow darkening is rendered.",
            "Untrusted snapshots are not authenticated as from a running Saturn emulator.",
        ],
    }


def run_private(iso: Path, vram: Path | None = None,
                cram: Path | None = None, regs: Path | None = None) -> dict:
    if any(x is not None for x in (vram, cram, regs)) and not all(
            x is not None for x in (vram, cram, regs)):
        raise ValueError("provide the three private VDP1/VDP2 files together")
    check = stage59_analyze(iso)
    result = {
        "schema_version": 1,
        "stage": "stage60_vdp2_sprite_priority_shadow_contract",
        "original_iso_pinned_sha256_verified": check["pinned_original_iso_sha256_matches"],
        "static_sh2_writer_and_submit_gate_unique": check["stage45_46_static_sh2_roles_unique"],
        "private_video_snapshots_supplied": vram is not None,
        "actual_emulator_execution_observed": False,
    }
    if vram is not None:
        if (vram.stat().st_size != VDP1_VRAM_BYTES or
                cram.stat().st_size != VDP2_CRAM_BYTES or
                regs.stat().st_size != VDP2_REG_BYTES):
            raise ValueError("private VDP1/VDP2 snapshot size mismatch")
        result["untrusted_offline_priority_shadow"] = audit_offline(
            vram.read_bytes(), cram.read_bytes(), regs.read_bytes())
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-private", required=True, type=Path)
    p.add_argument("--vdp1-vram-private", type=Path)
    p.add_argument("--vdp2-cram-private", type=Path)
    p.add_argument("--vdp2-regs-private", type=Path)
    p.add_argument("--output-private", type=Path)
    a = p.parse_args()
    encoded = json.dumps(run_private(a.iso_private, a.vdp1_vram_private,
                                      a.vdp2_cram_private, a.vdp2_regs_private),
                         indent=2, ensure_ascii=False) + "\n"
    if a.output_private:
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(a.output_private, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
