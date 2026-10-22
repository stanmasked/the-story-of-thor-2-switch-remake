#!/usr/bin/env python3
"""Stage61: bounded, private VDP1 draw-framebuffer mode and pixel-class audit.

A VDP1 draw framebuffer is 256 KiB; the other display framebuffer is not
CPU-accessible through the same address. A dump of the CPU-accessible buffer
must NOT be advertised as an actual visible game frame.

TVMR/FBCR are write-only VDP1 registers. This tool requires an emulator
REGISTER MIRROR of their values, NOT an arbitrary memory read of write-only
registers. It does not authenticate the mirror or emulator provenance.

No raw pixel values, addresses, RGB words or copyrighted data appear in
public-safe aggregate JSON. No image rendering, compositing or GPU execution.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from stage59_vdp2_cram_sprite_palette import analyze_private as check_private_iso

DRAW_FRAME_BYTES = 256 * 1024
REGISTER_MIRROR_BYTES = 32
FRAME_MODES = {
    0: (512, 256, 16, "standard_16bpp"),
    1: (1024, 256, 8, "high_resolution_8bpp"),
    2: (512, 256, 16, "rotation_16bpp"),
    3: (512, 512, 8, "rotation_8bpp"),
    4: (512, 256, 16, "hdtv_16bpp"),
}
MANUAL_TVMR = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp1/hon/p04_11.htm"
MANUAL_FBCR = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp1/hon/p04_12.htm"
MANUAL_BUFFER = "https://www.infochunk.com/saturn/segahtml_en/hard/vdp1/hon/p02_11.htm"


def parse_register_mirror(mirror: bytes) -> dict:
    if type(mirror) is not bytes or len(mirror) != REGISTER_MIRROR_BYTES:
        raise ValueError("exact 32-byte emulator VDP1 register mirror required")
    tvmr = int.from_bytes(mirror[0:2], "big")
    fbcr = int.from_bytes(mirror[2:4], "big")
    if tvmr & ~0x000F or fbcr & ~0x001F:
        raise ValueError("reserved TVMR/FBCR bits set")
    mode = tvmr & 7
    if mode not in FRAME_MODES:
        raise ValueError("TVMR mode is not a supported Saturn framebuffer mode")
    width, height, bits, label = FRAME_MODES[mode]
    vbe, fcm, fct = bool(tvmr & 8), bool(fbcr & 2), bool(fbcr & 1)
    dil, die, eos = bool(fbcr & 4), bool(fbcr & 8), bool(fbcr & 16)
    if ((vbe and not (fcm and fct)) or
            (not vbe and not fcm and fct) or
            (mode in (2, 3, 4) and die)):
        raise ValueError("prohibited TVMR/FBCR framebuffer combination")
    if width * height * bits // 8 != DRAW_FRAME_BYTES:
        raise ValueError("frame geometry must occupy exactly 256 KiB")
    return {
        "mode": mode,
        "mode_label": label,
        "width": width,
        "height": height,
        "bits_per_pixel": bits,
        "vblank_erase_enabled": vbe,
        "manual_switch_mode": fcm,
        "switch_trigger": fct,
        "double_interlace_enabled": die,
        "interlace_draw_line": dil,
        "even_odd_coordinate": eos,
        "buffer_switch_policy": (
            "manual_erase_and_change" if vbe and fcm and fct else
            "auto_change_every_field" if not fcm else
            "manual_change_next_field" if fct else
            "manual_erase_next_field"
        ),
        "register_mirror_is_operator_supplied_unverified": True,
    }


def pixel_class_private(raw: bytes, spec: dict, x: int, y: int) -> tuple[str, int]:
    """One raw framebuffer code, returned ONLY inside private memory."""
    if type(raw) is not bytes or len(raw) != DRAW_FRAME_BYTES:
        raise ValueError("private framebuffer must be exactly 256 KiB")
    if type(x) is not int or type(y) is not int:
        raise ValueError("pixel coordinates must be integers")
    width, height, bpp = spec["width"], spec["height"], spec["bits_per_pixel"]
    if not 0 <= x < width or not 0 <= y < height:
        raise ValueError("pixel outside framebuffer geometry")
    at = (y * width + x) * (bpp // 8)
    if bpp == 8:
        code = raw[at]
        return ("zero_transparent" if code == 0 else "indexed8_or_control_code", code)
    if bpp == 16:
        code = int.from_bytes(raw[at:at + 2], "big")
        return ("zero_transparent" if code == 0 else
                "rgb555_candidate" if code & 0x8000 else
                "palette_or_shadow_control_code", code)
    raise ValueError("not a recognized VDP1 framebuffer format")


def aggregate_framebuffer(frame: bytes, mirror: bytes) -> dict:
    """Count pixel categories; no individual words or origin assertions."""
    spec = parse_register_mirror(mirror)
    if type(frame) is not bytes or len(frame) != DRAW_FRAME_BYTES:
        raise ValueError("exact 262144-byte private framebuffer dump required")
    bpp = spec["bits_per_pixel"]
    counts = {"zero_transparent": 0, "indexed8_or_control_code": 0,
              "rgb555_candidate": 0, "palette_or_shadow_control_code": 0}
    if bpp == 8:
        counts["zero_transparent"] = frame.count(0)
        counts["indexed8_or_control_code"] = DRAW_FRAME_BYTES - counts["zero_transparent"]
    else:
        # Capture content is untrusted: do not interpret as RGB just because
        # a framebuffer word has bit15 set, nor claim compositor state.
        for i in range(0, DRAW_FRAME_BYTES, 2):
            code = int.from_bytes(frame[i:i + 2], "big")
            label = ("zero_transparent" if code == 0 else
                     "rgb555_candidate" if code & 0x8000 else
                     "palette_or_shadow_control_code")
            counts[label] += 1
    return {
        "schema_version": 1,
        "stage": "stage61_vdp1_framebuffer_native_bridge",
        "tvmr_mode": spec["mode"],
        "tvmr_mode_label": spec["mode_label"],
        "framebuffer_width": spec["width"],
        "framebuffer_height": spec["height"],
        "framebuffer_bits_per_pixel": bpp,
        "framebuffer_bytes": DRAW_FRAME_BYTES,
        "switch_policy": spec["buffer_switch_policy"],
        "pixel_classes": {key: value for key, value in counts.items() if value},
        "source_pixel_count": sum(counts.values()),
        "captured_cpu_accessible_buffer_is_drawing_side_only": True,
        "visible_display_framebuffer_captured_or_proven": False,
        "input_register_mirror_authenticated_as_emulator": False,
        "vd p1_framebuffer_pixels_rendered_by_emulator".replace(" ", ""): False,
        "vdp2_composited_frame_recovered": False,
        "private_pixel_values_or_addresses_exported": False,
        "limitations": [
            "Only the VDP1 drawing framebuffer is CPU-accessible; display side remains hidden.",
            "Frame-switch logic is a declared TVMR/FBCR snapshot, not a sequence of field events.",
            "8-bit source codes require VDP2 sprite-type selection; 16-bit codes may be control/shadow.",
            "No VDP2 priorities, CRAM, background planes or actual display frame are rendered.",
            "No real Saturn emulator framebuffer was acquired during this stage.",
        ],
    }


def run_private(iso: Path, frame: Path | None = None,
                regs: Path | None = None) -> dict:
    if (frame is None) != (regs is None):
        raise ValueError("supply framebuffer and VDP1 register mirror together")
    disc = check_private_iso(iso)
    report = {
        "schema_version": 1,
        "stage": "stage61_vdp1_framebuffer_native_bridge",
        "pinned_original_iso_sha256_verified": disc["pinned_original_iso_sha256_matches"],
        "static_sh2_vdp1_writer_and_gate_unique":
            disc["stage45_46_static_sh2_roles_unique"],
        "operator_supplied_framebuffer_and_register_mirror": frame is not None,
        "real_game_framebuffer_observed": False,
    }
    if frame is not None:
        if frame.stat().st_size != DRAW_FRAME_BYTES or regs.stat().st_size != REGISTER_MIRROR_BYTES:
            raise ValueError("private framebuffer/mirror size mismatch")
        report["untrusted_offline_framebuffer"] = aggregate_framebuffer(
            frame.read_bytes(), regs.read_bytes())
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-private", required=True, type=Path)
    p.add_argument("--draw-framebuffer-private", type=Path)
    p.add_argument("--vdp1-register-mirror-private", type=Path)
    p.add_argument("--output-private", type=Path)
    args = p.parse_args()
    text = json.dumps(run_private(args.iso_private, args.draw_framebuffer_private,
                                  args.vdp1_register_mirror_private),
                      indent=2, ensure_ascii=False) + "\n"
    if args.output_private:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(args.output_private, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
