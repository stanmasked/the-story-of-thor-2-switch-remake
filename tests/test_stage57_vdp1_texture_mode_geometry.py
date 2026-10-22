"""Stage57 synthetic-only VDP1 sprite geometry and raw texel decoding tests."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage10_dimension_palette_probe import dimension_candidates
from stage57_vdp1_texture_mode_geometry import (
    COLOR_MODES, VDP1_VRAM_BYTES, decode_sprite_descriptor,
    unpack_texels_private, analyze_vram_geometry, analyze_private,
)

SRC = 0x1000
WIDTH, HEIGHT = 16, 4


def putword(vram: bytearray, offset: int, value: int) -> None:
    vram[offset:offset + 2] = value.to_bytes(2, "big")


def synthetic_vram(*, mode=0, width=WIDTH, height=HEIGHT, source=SRC,
                   ctrl=0, lut=0x1800, reserved=0, second=False):
    ram = bytearray(VDP1_VRAM_BYTES)
    def write_sprite(at, mode, w, h, src, ctrl):
        putword(ram, at, ctrl)
        putword(ram, at + 4, mode << 3)
        putword(ram, at + 6, lut // 8)
        putword(ram, at + 8, src // 8)
        putword(ram, at + 10, reserved | (w // 8 << 8) | h)
    write_sprite(0, mode, width, height, source, ctrl)
    if second:
        write_sprite(32, 5, 8, 4, 0x2000, 0)
        putword(ram, 64, 0x8000)
    else:
        putword(ram, 32, 0x8000)
    return bytes(ram)


class Stage57VDP1GeometryTests(unittest.TestCase):
    def test_color_mode_map_has_six_modes(self):
        self.assertEqual(len(COLOR_MODES), 6)
        self.assertEqual([COLOR_MODES[i][1] for i in range(6)], [4, 4, 8, 8, 8, 16])

    def test_4bpp_bank_geometry(self):
        r = decode_sprite_descriptor(synthetic_vram(), 0)
        self.assertEqual((r["width_pixels"], r["height_pixels"]), (16, 4))
        self.assertEqual(r["texture_bytes"], 32)
        self.assertEqual(r["bits_per_pixel"], 4)

    def test_4bpp_lookup_geometry(self):
        r = decode_sprite_descriptor(synthetic_vram(mode=1), 0)
        self.assertEqual(r["texture_bytes"], 32)
        self.assertEqual(r["color_lut_address_private"], 0x1800)

    def test_8bpp_modes_two_three_four(self):
        for mode in (2, 3, 4):
            with self.subTest(mode=mode):
                r = decode_sprite_descriptor(synthetic_vram(mode=mode), 0)
                self.assertEqual(r["texture_bytes"], 64)
                self.assertEqual(r["bits_per_pixel"], 8)

    def test_16bpp_rgb_geometry(self):
        r = decode_sprite_descriptor(synthetic_vram(mode=5), 0)
        self.assertEqual(r["texture_bytes"], 128)
        self.assertEqual(r["bits_per_pixel"], 16)

    def test_texture_address_unit_eight(self):
        r = decode_sprite_descriptor(synthetic_vram(source=SRC), 0)
        self.assertEqual(r["texture_address_private"], SRC)
        self.assertEqual(r["texture_end_private"], SRC + 32)

    def test_size_width_unit_eight(self):
        r = decode_sprite_descriptor(synthetic_vram(width=24, height=11), 0)
        self.assertEqual((r["width_pixels"], r["height_pixels"]), (24, 11))

    def test_raw_4bpp_nibble_order_high_first(self):
        ram = bytearray(synthetic_vram())
        ram[SRC:SRC + 4] = bytes([0xAB, 0xC0, 0x1F, 0x89])
        raw = bytes(ram)
        pixels = unpack_texels_private(raw, decode_sprite_descriptor(raw, 0))
        self.assertEqual(pixels[:8], (10, 11, 12, 0, 1, 15, 8, 9))
        self.assertEqual(len(pixels), WIDTH * HEIGHT)

    def test_raw_8bpp_indices(self):
        ram = bytearray(synthetic_vram(mode=4))
        ram[SRC:SRC + 4] = b"\x10\xF2\x03\x9A"
        raw = bytes(ram)
        pixels = unpack_texels_private(raw, decode_sprite_descriptor(raw, 0))
        self.assertEqual(pixels[:4], (16, 242, 3, 154))
        self.assertEqual(len(pixels), WIDTH * HEIGHT)

    def test_raw_16bpp_big_endian_words(self):
        ram = bytearray(synthetic_vram(mode=5))
        ram[SRC:SRC + 4] = b"\x80\x1F\xFF\x00"
        raw = bytes(ram)
        pixels = unpack_texels_private(raw, decode_sprite_descriptor(raw, 0))
        self.assertEqual(pixels[:2], (0x801F, 0xFF00))
        self.assertEqual(len(pixels), WIDTH * HEIGHT)

    def test_raw_bpp_decoder_not_a_color_renderer(self):
        r = decode_sprite_descriptor(synthetic_vram(mode=0), 0)
        self.assertEqual(r["color_mode_name"], "4bpp_color_bank_16")
        self.assertFalse(r["transparent_pixel_disabled"])

    def test_zero_width_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(width=0), 0)

    def test_zero_height_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(height=0), 0)

    def test_reserved_size_bits_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(reserved=0x4000), 0)

    def test_invalid_color_modes_rejected(self):
        for mode in (6, 7):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                decode_sprite_descriptor(synthetic_vram(mode=mode), 0)

    def test_non_sprite_polygon_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(ctrl=4), 0)

    def test_end_bit_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(ctrl=0x8000), 0)

    def test_unaligned_position_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(), 2)

    def test_out_of_range_position_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(), VDP1_VRAM_BYTES)

    def test_incorrect_vram_snapshot_size_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(bytes(1024), 0)

    def test_texture_read_overrun_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(source=0x7FFF8), 0)

    def test_lookup_table_read_overrun_rejected(self):
        with self.assertRaises(ValueError):
            decode_sprite_descriptor(synthetic_vram(mode=1, lut=0x7FFF8), 0)

    def test_end_of_vram_exactly_fits(self):
        r = decode_sprite_descriptor(synthetic_vram(mode=0, width=8, height=2,
                                                    source=0x7FFF8), 0)
        self.assertEqual(r["texture_end_private"], VDP1_VRAM_BYTES)

    def test_color_bank_is_not_lookup_pointer(self):
        r = decode_sprite_descriptor(synthetic_vram(mode=0, lut=0x7FFF8), 0)
        self.assertIsNone(r["color_lut_address_private"])

    def test_skipped_sprite_not_counted_as_draw(self):
        r = analyze_vram_geometry(synthetic_vram(ctrl=0x4000))
        self.assertEqual(r["skipped_sprite_records_not_counted_as_draws"], 1)
        self.assertEqual(r["visited_sprite_records_with_valid_mode_and_bounds"], 0)

    def test_chain_two_valid_sprites(self):
        r = analyze_vram_geometry(synthetic_vram(second=True))
        self.assertEqual(r["visited_sprite_records_with_valid_mode_and_bounds"], 2)
        self.assertEqual(r["sprite_entries_by_bits_per_pixel"], {"4": 1, "16": 1})
        self.assertTrue(r["vdp1_chain"]["end_bit_reached"])

    def test_chain_one_malformed_sprite(self):
        r = analyze_vram_geometry(synthetic_vram(mode=6))
        self.assertEqual(r["malformed_or_out_of_bounds_sprite_records"], 1)
        self.assertFalse(r["pixel_format_disambiguated_by_command_metadata"])

    def test_chain_non_sprite_polygon_ignored(self):
        r = analyze_vram_geometry(synthetic_vram(ctrl=4))
        self.assertEqual(r["visited_sprite_records_with_valid_mode_and_bounds"], 0)

    def test_chain_lut_entry_count(self):
        r = analyze_vram_geometry(synthetic_vram(mode=1))
        self.assertEqual(r["lut_sprite_entries_with_in_bounds_16color_table"], 1)

    def test_chain_overlapping_own_slot_reported(self):
        r = analyze_vram_geometry(synthetic_vram(source=0))
        self.assertEqual(r["sprite_texture_source_overlaps_own_command_slot_candidates"], 1)

    def test_stage10_block_size_remains_ambiguous_without_command(self):
        # Exactly 32 texture bytes also admit 8x8 at 4bpp, among other sizes.
        options = dimension_candidates(32, 4)
        self.assertIn((8, 8), options)
        self.assertIn((16, 4), options)
        self.assertGreater(len(options), 1)
        r = decode_sprite_descriptor(synthetic_vram(), 0)
        self.assertEqual((r["width_pixels"], r["height_pixels"]), (16, 4))

    def test_public_report_never_exports_texture_address_or_pixels(self):
        report = analyze_vram_geometry(synthetic_vram())
        encoded = json.dumps(report)
        for forbidden in ('"texture_address_private"', '"command_offset_private"',
                          '"pixels"', '"color_bank_or_lut_word_private"'):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(report["raw_pixel_values_or_private_vram_addresses_exported"])

    def test_public_report_does_not_claim_live_execution(self):
        report = analyze_vram_geometry(synthetic_vram())
        self.assertFalse(report["source_snapshot_authenticated_as_live_emulator"])
        self.assertFalse(report["rendered_sprite_pixels_confirmed"])
        self.assertFalse(report["disc_resource_block_to_vdp1_source_mapping_proven"])

    def test_invalid_texel_descriptor_span_rejected(self):
        raw = synthetic_vram()
        desc = decode_sprite_descriptor(raw, 0)
        desc["texture_end_private"] += 1
        with self.assertRaises(ValueError):
            unpack_texels_private(raw, desc)

    def test_private_iso_pin_rejects_synthetic_image(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "fake.iso"
            fake.write_bytes(b"synthetic")
            with self.assertRaises(ValueError):
                analyze_private(fake)


if __name__ == "__main__":
    unittest.main()
