"""Stage58 ROM-free, synthetic-only VDP1 end-code, transparency, LUT tests."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage57_vdp1_texture_mode_geometry import synthetic_vram, putword, SRC
from stage57_vdp1_texture_mode_geometry import decode_sprite_descriptor
from stage58_vdp1_pixel_policy import (
    END_CODES, INDEX_MASK, interpret_texels_private,
    summarize_pixel_policy_private, analyze_vram_pixel_policy, run_private,
)

def build(mode=0, width=8, height=2, spd=False, ecd=False, pixels=b"",
          bank=0x2400, lut_words=None, ctrl=0, second=False):
    raw = bytearray(synthetic_vram(
        mode=mode, width=width, height=height, source=SRC,
        lut=0x1800, ctrl=ctrl, second=second))
    pmod = (mode << 3) | (0x40 if spd else 0) | (0x80 if ecd else 0)
    putword(raw, 4, pmod)
    if mode == 1:
        putword(raw, 6, 0x1800 // 8)
        lut_words = lut_words if lut_words is not None else [0x8000 + i for i in range(16)]
        for index, word in enumerate(lut_words):
            putword(raw, 0x1800 + 2*index, word)
    else:
        putword(raw, 6, bank)
    if pixels:
        raw[SRC:SRC + len(pixels)] = pixels
    return bytes(raw)

def decode(raw):
    return interpret_texels_private(raw, decode_sprite_descriptor(raw, 0))

def labels(row):
    return [item[0] for item in row]


class Stage58PolicyTests(unittest.TestCase):
    def test_end_codes_by_modes(self):
        self.assertEqual(END_CODES, {0:15,1:15,2:255,3:255,4:255,5:32767})

    def test_color_masks_by_modes(self):
        self.assertEqual(INDEX_MASK, {0:15,1:15,2:63,3:127,4:255})

    def test_4bpp_zero_transparent(self):
        self.assertEqual(decode(build(pixels=b"\x01"))[0][0], ("zero_transparent", None))

    def test_4bpp_zero_opaque_when_spd_enabled(self):
        self.assertEqual(decode(build(spd=True, ecd=True, pixels=b"\x01"))[0][0],
                         ("color_bank_code", 0x2400))

    def test_4bpp_bank_code_combines_four_bits(self):
        row = decode(build(ecd=True, pixels=b"\xAB"))[0]
        self.assertEqual(row[:2], (("color_bank_code", 0x240A),
                                    ("color_bank_code", 0x240B)))

    def test_4bpp_bank_low_bits_replaced_not_or_reused(self):
        row = decode(build(ecd=True, bank=0x24FF, pixels=b"\x25"))[0]
        self.assertEqual(row[:2], (("color_bank_code", 0x24F2),
                                    ("color_bank_code", 0x24F5)))

    def test_4bpp_first_end_code_transparent(self):
        row = decode(build(pixels=b"\xF1"))[0]
        self.assertEqual(row[:2], (("end_code_transparent",None),
                                    ("color_bank_code",0x2401)))

    def test_second_end_code_terminates_row(self):
        row = decode(build(pixels=b"\xF1\xF2\x34\x56"))[0]
        self.assertEqual(labels(row)[:4],
                         ["end_code_transparent","color_bank_code",
                          "end_code_transparent","after_second_end_code"])
        self.assertTrue(all(x == "after_second_end_code" for x in labels(row)[3:]))

    def test_two_end_codes_reset_at_next_row(self):
        row0 = b"\xFF\x12\x34\x56"
        row1 = b"\x21\x34\x56\x78"
        rows = decode(build(pixels=row0+row1))
        self.assertEqual(rows[0][2][0], "after_second_end_code")
        self.assertEqual(rows[1][0], ("color_bank_code", 0x2402))

    def test_end_code_disabled_f_renders_as_bank_value(self):
        self.assertEqual(decode(build(ecd=True, pixels=b"\xF1"))[0][0],
                         ("color_bank_code", 0x240F))

    def test_end_code_and_spd_independent_flags(self):
        row = decode(build(ecd=False, spd=True, pixels=b"\x0F\x10"))[0]
        self.assertEqual(row[0], ("color_bank_code",0x2400))
        self.assertEqual(row[1], ("end_code_transparent",None))

    def test_unsupported_ecd0_spd1_reported(self):
        raw = build(spd=True, ecd=False)
        desc = decode_sprite_descriptor(raw, 0)
        self.assertTrue(summarize_pixel_policy_private(raw, desc)[
            "unsupported_ecd0_spd1_combination"])

    def test_ecd1_spd1_not_flagged(self):
        raw = build(spd=True, ecd=True)
        self.assertFalse(summarize_pixel_policy_private(raw, decode_sprite_descriptor(raw,0))[
            "unsupported_ecd0_spd1_combination"])

    def test_mode2_ff_end_not_3f(self):
        raw = build(mode=2,pixels=b"\x3f\xff\x40")
        row = decode(raw)[0]
        self.assertEqual(row[0], ("color_bank_code", 0x243F))
        self.assertEqual(row[1], ("end_code_transparent", None))

    def test_mode2_masks_upper_two_bits(self):
        self.assertEqual(decode(build(mode=2, ecd=True, pixels=b"\xFF"))[0][0],
                         ("color_bank_code", 0x243F))

    def test_mode3_ff_end_not_7f(self):
        row = decode(build(mode=3, pixels=b"\x7f\xff"))[0]
        self.assertEqual(row[0], ("color_bank_code", 0x247F))
        self.assertEqual(row[1], ("end_code_transparent", None))

    def test_mode3_masks_upper_bit(self):
        self.assertEqual(decode(build(mode=3,ecd=True,pixels=b"\x81"))[0][0],
                         ("color_bank_code", 0x2401))

    def test_mode4_index_uses_all_bits(self):
        self.assertEqual(decode(build(mode=4,ecd=True,pixels=b"\xF1"))[0][0],
                         ("color_bank_code", 0x24F1))

    def test_8bpp_zero_transparent(self):
        self.assertEqual(decode(build(mode=2,pixels=b"\x00"))[0][0],
                         ("zero_transparent", None))

    def test_lookup_rgb_code_preserves_msb(self):
        raw=build(mode=1,pixels=b"\x10")
        self.assertEqual(decode(raw)[0][0], ("lookup_rgb_code",0x8001))

    def test_lookup_bank_code_not_rgb(self):
        lut=[0x8000+i for i in range(16)]
        lut[2]=0x0C22
        raw=build(mode=1,pixels=b"\x20",lut_words=lut)
        self.assertEqual(decode(raw)[0][0], ("lookup_color_bank_code",0x0C22))

    def test_lookup_zero_transparent_even_if_lut_nonzero(self):
        raw=build(mode=1,pixels=b"\x01")
        self.assertEqual(decode(raw)[0][0], ("zero_transparent",None))

    def test_lookup_spd_override(self):
        raw=build(mode=1, spd=True, ecd=True, pixels=b"\x01")
        self.assertEqual(decode(raw)[0][0], ("lookup_rgb_code",0x8000))

    def test_lookup_f_end_code_precedes_lut(self):
        raw=build(mode=1, pixels=b"\xF1")
        self.assertEqual(decode(raw)[0][0], ("end_code_transparent",None))

    def test_lookup_f_when_ecd_disabled_references_index15(self):
        raw=build(mode=1,ecd=True,pixels=b"\xF1")
        self.assertEqual(decode(raw)[0][0], ("lookup_rgb_code",0x800F))

    def test_rgb_valid_word_unmodified(self):
        raw=build(mode=5,pixels=b"\x83\x1F")
        self.assertEqual(decode(raw)[0][0], ("direct_rgb_code",0x831F))

    def test_rgb_zero_transparent(self):
        self.assertEqual(decode(build(mode=5,pixels=b"\x00\x00"))[0][0],
                         ("zero_transparent",None))

    def test_rgb_end_code_7fff(self):
        self.assertEqual(decode(build(mode=5,pixels=b"\x7f\xff"))[0][0],
                         ("end_code_transparent",None))

    def test_rgb_non_rgb_word_explicitly_unsupported(self):
        raw=build(mode=5,spd=True,ecd=True,pixels=b"\x01\x12")
        self.assertEqual(decode(raw)[0][0],
                         ("unsupported_direct_mode_non_rgb_word",0x0112))

    def test_rgb_disabled_end_code_not_claimed_rgb(self):
        raw=build(mode=5,ecd=True,pixels=b"\x7F\xFF")
        self.assertEqual(decode(raw)[0][0],
                         ("unsupported_direct_mode_non_rgb_word",0x7FFF))

    def test_independent_scanline_end_counters_rgb(self):
        first=b"\x7F\xFF\x7F\xFF"+bytes(12)
        second=b"\x80\x10"+bytes(14)
        rows=decode(build(mode=5,pixels=first+second))
        self.assertEqual(rows[0][2][0],"after_second_end_code")
        self.assertEqual(rows[1][0],("direct_rgb_code",0x8010))

    def test_two_end_lines_counted(self):
        raw=build(pixels=b"\xFF\x12\x34\x56")
        agg=summarize_pixel_policy_private(raw,decode_sprite_descriptor(raw,0))
        self.assertEqual(agg["scanlines_with_two_end_codes"],1)
        self.assertEqual(agg["texels_inspected"],16)

    def test_source_descriptor_cannot_be_forged(self):
        raw=build()
        desc=decode_sprite_descriptor(raw,0)
        desc["color_mode"]=4
        with self.assertRaises(ValueError):
            interpret_texels_private(raw,desc)

    def test_descriptor_wrong_private_texture_address_rejected(self):
        raw=build()
        desc=decode_sprite_descriptor(raw,0)
        desc["texture_address_private"]+=32
        with self.assertRaises(ValueError):
            interpret_texels_private(raw,desc)

    def test_snapshot_size_must_be_complete(self):
        raw=build()
        d=decode_sprite_descriptor(raw,0)
        with self.assertRaises(ValueError):
            interpret_texels_private(raw[:-1],d)

    def test_aggregate_omits_private_colors_and_pcs(self):
        raw=build(pixels=b"\xAB",ecd=True,bank=0x2F00)
        report=analyze_vram_pixel_policy(raw)
        text=json.dumps(report)
        for forbidden in ('"raw_pixels"', '"command_offset_private"',
                          '"color_bank_or_lut_word_private"', '"lookup_rgb_word"',
                          '"texture_address_private"'):
            self.assertNotIn(forbidden,text)
        self.assertFalse(report["raw_private_pixels_or_framebuffer_codes_exported"])

    def test_aggregate_one_sprite(self):
        report=analyze_vram_pixel_policy(build(pixels=b"\xF1"))
        self.assertEqual(report["sprite_commands_interpreted_within_texel_budget"],1)
        self.assertEqual(report["source_texels_inspected"],16)

    def test_aggregate_budget_skips_oversize_command(self):
        report=analyze_vram_pixel_policy(build(),max_texels=8)
        self.assertEqual(report["sprite_descriptors_not_interpreted_due_to_budget"],1)

    def test_aggregate_16color_lookup_count(self):
        report=analyze_vram_pixel_policy(build(mode=1))
        self.assertEqual(report["commands_using_16color_lookup"],1)

    def test_aggregate_no_emulator_attestation(self):
        r=analyze_vram_pixel_policy(build())
        self.assertFalse(r["actual_original_saturn_execution_observed"])
        self.assertFalse(r["rendered_original_sprites"])

    def test_none_format_invalid(self):
        with self.assertRaises(ValueError):
            analyze_vram_pixel_policy(b"X")

    def test_bool_budget_rejected(self):
        with self.assertRaises(ValueError):
            analyze_vram_pixel_policy(build(),max_texels=True)

    def test_invalid_budget_over_cap(self):
        with self.assertRaises(ValueError):
            analyze_vram_pixel_policy(build(),max_texels=300000)

    def test_private_iso_checksum_blocks_synthetic(self):
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)/"synthetic.iso"
            fake.write_bytes(b"not the original")
            with self.assertRaises(ValueError):
                run_private(fake)


if __name__ == "__main__":
    unittest.main()
