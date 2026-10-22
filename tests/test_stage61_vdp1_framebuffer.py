"""Stage61 ROM-free framebuffer/register mirror and draw-side contract tests."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage61_vdp1_framebuffer import (
    DRAW_FRAME_BYTES, REGISTER_MIRROR_BYTES,
    FRAME_MODES, parse_register_mirror, pixel_class_private,
    aggregate_framebuffer, run_private,
)


def mirror(tvmr=0, fbcr=0):
    return tvmr.to_bytes(2, "big") + fbcr.to_bytes(2, "big") + bytes(28)


def blank():
    return bytes(DRAW_FRAME_BYTES)


def frame_with(mode, points):
    info = parse_register_mirror(mirror(mode))
    array = bytearray(blank())
    for x, y, code in points:
        addr = ((y * info["width"]) + x) * (info["bits_per_pixel"] // 8)
        width = info["bits_per_pixel"] // 8
        array[addr:addr + width] = code.to_bytes(width, "big")
    return bytes(array)


class Stage61FramebufferTests(unittest.TestCase):
    def test_modes_are_exactly_zero_to_four(self):
        self.assertEqual(set(FRAME_MODES), set(range(5)))

    def test_normal_mode_512x256x16(self):
        s = parse_register_mirror(mirror(0))
        self.assertEqual((s["width"], s["height"], s["bits_per_pixel"]), (512,256,16))

    def test_high_resolution_1024x256x8(self):
        s = parse_register_mirror(mirror(1))
        self.assertEqual((s["width"], s["height"], s["bits_per_pixel"]), (1024,256,8))

    def test_rotation_16_512x256(self):
        s = parse_register_mirror(mirror(2))
        self.assertEqual((s["width"], s["height"], s["bits_per_pixel"]), (512,256,16))

    def test_rotation_8_512x512(self):
        s = parse_register_mirror(mirror(3))
        self.assertEqual((s["width"], s["height"], s["bits_per_pixel"]), (512,512,8))

    def test_hdtv_512x256x16(self):
        s = parse_register_mirror(mirror(4))
        self.assertEqual((s["width"], s["height"], s["bits_per_pixel"]), (512,256,16))

    def test_each_mode_is_256_kib(self):
        for m in range(5):
            s = parse_register_mirror(mirror(m))
            self.assertEqual(s["width"] * s["height"] * s["bits_per_pixel"] // 8,
                             DRAW_FRAME_BYTES)

    def test_reject_illegal_modes_five_to_seven(self):
        for m in (5, 6, 7):
            with self.subTest(m=m), self.assertRaises(ValueError):
                parse_register_mirror(mirror(m))

    def test_reject_reserved_tvmr_bits(self):
        with self.assertRaises(ValueError):
            parse_register_mirror(mirror(0x10))

    def test_reject_reserved_fbcr_bits(self):
        with self.assertRaises(ValueError):
            parse_register_mirror(mirror(0,0x20))

    def test_register_mirror_exact_length(self):
        with self.assertRaises(ValueError):
            parse_register_mirror(bytes(16))

    def test_register_mirror_rejects_bytearray(self):
        with self.assertRaises(ValueError):
            parse_register_mirror(bytearray(mirror()))

    def test_vblank_erase_only_in_manual_erase_and_change(self):
        s = parse_register_mirror(mirror(8, 3))
        self.assertTrue(s["vblank_erase_enabled"])
        self.assertEqual(s["buffer_switch_policy"], "manual_erase_and_change")

    def test_vblank_erase_without_manual_mode_rejected(self):
        with self.assertRaises(ValueError):
            parse_register_mirror(mirror(8, 0))

    def test_auto_fct_one_rejected(self):
        with self.assertRaises(ValueError):
            parse_register_mirror(mirror(0, 1))

    def test_automatic_switch_mode(self):
        self.assertEqual(parse_register_mirror(mirror())["buffer_switch_policy"],
                         "auto_change_every_field")

    def test_manual_erase_mode(self):
        self.assertEqual(parse_register_mirror(mirror(0,2))["buffer_switch_policy"],
                         "manual_erase_next_field")

    def test_manual_change_mode(self):
        self.assertEqual(parse_register_mirror(mirror(0,3))["buffer_switch_policy"],
                         "manual_change_next_field")

    def test_rotation_double_interlace_rejected(self):
        for mode in (2, 3):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                parse_register_mirror(mirror(mode,8))

    def test_hdtv_double_interlace_rejected(self):
        with self.assertRaises(ValueError):
            parse_register_mirror(mirror(4,8))

    def test_standard_interlace_bit_allowed(self):
        self.assertTrue(parse_register_mirror(mirror(0,8))["double_interlace_enabled"])

    def test_zero_is_transparent_at_origin(self):
        kind, word = pixel_class_private(blank(), parse_register_mirror(mirror()), 0, 0)
        self.assertEqual((kind, word), ("zero_transparent", 0))

    def test_rgb555_candidate_big_endian(self):
        frame = frame_with(0, [(0,0,0x801f)])
        self.assertEqual(pixel_class_private(frame, parse_register_mirror(mirror()), 0,0),
                         ("rgb555_candidate", 0x801f))

    def test_palette_word_is_not_assumed_rgb(self):
        frame = frame_with(0, [(0,0,0x0420)])
        self.assertEqual(pixel_class_private(frame, parse_register_mirror(mirror()), 0,0),
                         ("palette_or_shadow_control_code", 0x0420))

    def test_last_16bit_pixel(self):
        frame = frame_with(0,[(511,255,0x83e0)])
        self.assertEqual(pixel_class_private(frame,parse_register_mirror(mirror()),511,255),
                         ("rgb555_candidate",0x83e0))

    def test_8bit_palette_class_at_last_pixel(self):
        frame = frame_with(1,[(1023,255,255)])
        self.assertEqual(pixel_class_private(frame,parse_register_mirror(mirror(1)),1023,255),
                         ("indexed8_or_control_code",255))

    def test_rotation_8_second_row_stride(self):
        frame = frame_with(3,[(0,1,23)])
        self.assertEqual(pixel_class_private(frame,parse_register_mirror(mirror(3)),0,1),
                         ("indexed8_or_control_code",23))

    def test_out_of_range_x_rejected(self):
        with self.assertRaises(ValueError):
            pixel_class_private(blank(),parse_register_mirror(mirror()),512,0)

    def test_out_of_range_y_rejected(self):
        with self.assertRaises(ValueError):
            pixel_class_private(blank(),parse_register_mirror(mirror()),0,256)

    def test_negative_x_rejected(self):
        with self.assertRaises(ValueError):
            pixel_class_private(blank(),parse_register_mirror(mirror()),-1,0)

    def test_boolean_coordinate_rejected(self):
        with self.assertRaises(ValueError):
            pixel_class_private(blank(),parse_register_mirror(mirror()),False,0)

    def test_wrong_frame_length_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_framebuffer(bytes(10),mirror())

    def test_aggregate_16bit_counts(self):
        f = frame_with(0,[(0,0,0x801f),(1,0,0x420),(511,255,0x8000)])
        r = aggregate_framebuffer(f,mirror())
        self.assertEqual(r["pixel_classes"]["rgb555_candidate"],2)
        self.assertEqual(r["pixel_classes"]["palette_or_shadow_control_code"],1)
        self.assertEqual(r["source_pixel_count"],131072)

    def test_aggregate_8bit_counts(self):
        f = frame_with(1,[(0,0,0x12),(1023,255,0xff)])
        r = aggregate_framebuffer(f,mirror(1))
        self.assertEqual(r["pixel_classes"]["indexed8_or_control_code"],2)
        self.assertEqual(r["source_pixel_count"],262144)

    def test_aggregate_rotation8_pixel_count(self):
        r=aggregate_framebuffer(blank(),mirror(3))
        self.assertEqual(r["source_pixel_count"],262144)

    def test_aggregate_no_emulator_attestation(self):
        r=aggregate_framebuffer(blank(),mirror())
        self.assertFalse(r["visible_display_framebuffer_captured_or_proven"])
        self.assertFalse(r["input_register_mirror_authenticated_as_emulator"])
        self.assertFalse(r["vdp2_composited_frame_recovered"])

    def test_aggregate_never_exports_private_pixel_values(self):
        r=aggregate_framebuffer(frame_with(0,[(0,0,0x8567)]),mirror())
        encoded=json.dumps(r)
        for forbidden in ('"raw_code"','"private_framebuffer_address"',
                          '"raw_pixels"','"framebuffer_contents"'):
            self.assertNotIn(forbidden,encoded)
        self.assertFalse(r["private_pixel_values_or_addresses_exported"])

    def test_display_buffer_not_same_as_cpu_draw_buffer(self):
        self.assertTrue(aggregate_framebuffer(blank(),mirror())[
            "captured_cpu_accessible_buffer_is_drawing_side_only"])

    def test_private_incomplete_pair_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            img=Path(td)/"synthetic.iso"
            img.write_bytes(b"not original")
            with self.assertRaises(ValueError):
                run_private(img,frame=Path(td)/"frame")

    def test_private_iso_requires_pinned_hash(self):
        with tempfile.TemporaryDirectory() as td:
            img=Path(td)/"synthetic.iso"
            img.write_bytes(b"not original")
            with self.assertRaises(ValueError):
                run_private(img)


if __name__ == "__main__":
    unittest.main()
