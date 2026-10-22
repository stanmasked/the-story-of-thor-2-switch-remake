"""Stage59 synthetic-only tests for VDP2 CRAM and sprite palette semantics."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage58_vdp1_pixel_policy import build
from stage59_vdp2_cram_sprite_palette import (
    VDP2_CRAM_BYTES, VDP2_REG_BYTES, SUPPORTED_PALETTE_TYPES,
    decode_vdp2_registers, read_cram_rgb_private, rgb555_to_output8,
    resolve_pixel_private, summarize_private, analyze_private,
)

def fake_regs(mode=1, sprtype=0, mixed=False, offset=0, coeff=False):
    mem=bytearray(VDP2_REG_BYTES)
    ramctl=mode << 12 | (0x8000 if coeff else 0)
    mem[0x0E:0x10]=ramctl.to_bytes(2,"big")
    spctl=sprtype | (0x20 if mixed else 0)
    mem[0xE0:0xE2]=spctl.to_bytes(2,"big")
    mem[0xE6:0xE8]=(offset << 4).to_bytes(2,"big")
    return bytes(mem)

def fake_cram(indices=None):
    buf=bytearray(VDP2_CRAM_BYTES)
    for index,value in (indices or {}).items():
        buf[index*2:index*2+2]=value.to_bytes(2,"big")
    return bytes(buf)

def state(**kwargs):
    return decode_vdp2_registers(fake_regs(**kwargs))


class Stage59VDP2PaletteTests(unittest.TestCase):
    def test_register_mode0(self):
        s=state(mode=0)
        self.assertEqual(s["cram_mode"],0)
        self.assertEqual(s["cram_capacity_entries"],1024)

    def test_register_mode1(self):
        self.assertEqual(state(mode=1)["cram_capacity_entries"],2048)

    def test_register_mode2(self):
        self.assertEqual(state(mode=2)["cram_capacity_entries"],1024)

    def test_reserved_mode3_rejected(self):
        with self.assertRaises(ValueError):
            state(mode=3)

    def test_register_size_checked(self):
        with self.assertRaises(ValueError):
            decode_vdp2_registers(bytes(256))

    def test_register_bytearray_rejected(self):
        with self.assertRaises(ValueError):
            decode_vdp2_registers(bytearray(VDP2_REG_BYTES))

    def test_sprite_type_all_low_four_bits(self):
        self.assertEqual(state(sprtype=7)["sprite_type"],7)

    def test_sprite_mixed_mode_bit5(self):
        self.assertTrue(state(mixed=True)["sprite_palette_and_rgb_mixed"])

    def test_sprite_cram_offset_bits6_to4(self):
        self.assertEqual(state(offset=5)["sprite_color_ram_address_offset"],5)

    def test_coefficient_partition_from_bit15(self):
        self.assertTrue(state(coeff=True)["cram_coefficient_table_enabled"])

    def test_rgb555_5_to_8_is_left_shift_only(self):
        self.assertEqual(rgb555_to_output8(0x7FFF),(248,248,248))

    def test_rgb555_channel_order(self):
        self.assertEqual(rgb555_to_output8(0x001F),(248,0,0))
        self.assertEqual(rgb555_to_output8(0x03E0),(0,248,0))
        self.assertEqual(rgb555_to_output8(0x7C00),(0,0,248))

    def test_rgb555_invalid_range(self):
        for word in (-1,0x10000,False):
            with self.subTest(word=word),self.assertRaises(ValueError):
                rgb555_to_output8(word)

    def test_cram_mode1_2048th_entry(self):
        c=fake_cram({2047:0x801F})
        self.assertEqual(read_cram_rgb_private(c,1,2047),((248,0,0),True))

    def test_mode0_1024th_index_rejected(self):
        with self.assertRaises(ValueError):
            read_cram_rgb_private(bytes(4096),0,1024)

    def test_mode0_duplicate_bank_uses_first_half(self):
        data=bytearray(fake_cram({10:0x03E0}))
        data[2048+20:2048+22]=(0x7C00).to_bytes(2,"big")
        self.assertEqual(read_cram_rgb_private(bytes(data),0,10)[0],(0,248,0))

    def test_mode2_big_endian_bgr_fields(self):
        c=bytearray(VDP2_CRAM_BYTES)
        c[4*9:4*9+4]=bytes([0x80,0xA1,0xB2,0xC3])
        self.assertEqual(read_cram_rgb_private(bytes(c),2,9),((195,178,161),True))

    def test_mode2_1024_entry_limit(self):
        with self.assertRaises(ValueError):
            read_cram_rgb_private(bytes(4096),2,1024)

    def test_cram_bad_size(self):
        with self.assertRaises(ValueError):
            read_cram_rgb_private(bytes(2048),1,0)

    def test_invalid_cram_mode(self):
        with self.assertRaises(ValueError):
            read_cram_rgb_private(bytes(4096),3,0)

    def test_transparent_texel_no_palette_lookup(self):
        kind,rgb=resolve_pixel_private("zero_transparent",None,bytes(4096),state())
        self.assertEqual((kind,rgb),("zero_transparent",None))

    def test_transparent_non_null_word_rejected(self):
        with self.assertRaises(ValueError):
            resolve_pixel_private("zero_transparent",1,bytes(4096),state())

    def test_direct_rgb_bypasses_palette(self):
        result=resolve_pixel_private("direct_rgb_code",0x801F,bytes(4096),state())
        self.assertEqual(result,("preblend_rgb555",(248,0,0)))

    def test_lookup_rgb_bypasses_palette(self):
        result=resolve_pixel_private("lookup_rgb_code",0x83E0,bytes(4096),state())
        self.assertEqual(result,("preblend_rgb555",(0,248,0)))

    def test_direct_rgb_marker_required(self):
        with self.assertRaises(ValueError):
            resolve_pixel_private("direct_rgb_code",0x001F,bytes(4096),state())

    def test_non_rgb_16bit_explicitly_unresolved(self):
        self.assertEqual(resolve_pixel_private("unsupported_direct_mode_non_rgb_word",
                                              0x7FFF,bytes(4096),state())[0],
                         "unresolved_non_rgb_direct_code")

    def test_mode1_sprite_type0_11bit_address(self):
        # 0x2402 low 11 bits = 0x402; no SPCAOS.
        c=fake_cram({0x402:0x801F})
        x=resolve_pixel_private("color_bank_code",0x2402,c,state(mode=1))
        self.assertEqual(x,("palette_rgb_candidate_not_composited",(248,0,0)))

    def test_offset_adds_0x200_entries_mode1(self):
        c=fake_cram({0x402+0x200:0x03E0})
        x=resolve_pixel_private("color_bank_code",0x2402,c,state(mode=1,offset=1))
        self.assertEqual(x[1],(0,248,0))

    def test_offset_wraps_11bit_address_mode1(self):
        c=fake_cram({0x402:0x7C00})
        x=resolve_pixel_private("color_bank_code",0x2402,c,state(mode=1,offset=4))
        self.assertEqual(x[1],(0,0,248))

    def test_mode0_masks_top_address_bit(self):
        c=fake_cram({0x002:0x7C00})
        x=resolve_pixel_private("color_bank_code",0x2402,c,state(mode=0))
        self.assertEqual(x[1],(0,0,248))

    def test_type4_10bit_palette_mask(self):
        self.assertEqual(SUPPORTED_PALETTE_TYPES[4],10)
        c=fake_cram({0x003:0x001F})
        x=resolve_pixel_private("color_bank_code",0xFC03,c,state(mode=1,sprtype=4))
        self.assertEqual(x[1],(248,0,0))

    def test_type7_9bit_palette_mask(self):
        self.assertEqual(SUPPORTED_PALETTE_TYPES[7],9)
        c=fake_cram({0x001:0x03E0})
        x=resolve_pixel_private("color_bank_code",0x6E01,c,state(mode=1,sprtype=7))
        self.assertEqual(x[1],(0,248,0))

    def test_8bit_sprite_types_not_guessed(self):
        r=resolve_pixel_private("color_bank_code",0x0031,bytes(4096),state(sprtype=8))
        self.assertEqual(r,("unresolved_eight_bit_sprite_type",None))

    def test_mode2_palette_mapping_not_guessed(self):
        r=resolve_pixel_private("color_bank_code",0x0031,bytes(4096),state(mode=2))
        self.assertEqual(r,("unresolved_mode2_sprite_cram_address",None))

    def test_mixed_bit15_rgb_candidate(self):
        r=resolve_pixel_private("color_bank_code",0x83E0,bytes(4096),state(mixed=True))
        self.assertEqual(r,("mixed_framebuffer_rgb_candidate",(0,248,0)))

    def test_no_mixed_bit15_palette_lookup(self):
        c=fake_cram({0x000:0x001F})
        r=resolve_pixel_private("color_bank_code",0x8000,c,state(mode=1,mixed=False))
        self.assertEqual(r[0],"palette_rgb_candidate_not_composited")

    def test_coefficient_table_partition_detected(self):
        r=resolve_pixel_private("color_bank_code",0x0400,bytes(4096),
                                state(mode=1,coeff=True))
        self.assertEqual(r,("unresolved_cram_coefficient_table_partition",None))

    def test_bad_framebuffer_word_refused(self):
        with self.assertRaises(ValueError):
            resolve_pixel_private("color_bank_code",65536,bytes(4096),state())

    def test_unknown_category_refused(self):
        with self.assertRaises(ValueError):
            resolve_pixel_private("unknown",1,bytes(4096),state())

    def test_aggregate_synthetic_one_sprite(self):
        vram=build(mode=0,ecd=True,pixels=b"\x21",bank=0x2400)
        c=fake_cram({0x402:0x801F,0x401:0x03E0})
        r=summarize_private(vram,c,fake_regs(mode=1))
        self.assertEqual(r["sprites_interpreted"],1)
        self.assertGreater(r["candidate_color_categories"].get(
            "palette_rgb_candidate_not_composited",0),0)

    def test_aggregate_has_no_private_rgb_values(self):
        vram=build(mode=0,ecd=True,pixels=b"\x21",bank=0x2400)
        r=summarize_private(vram,fake_cram({0x402:0x801F}),fake_regs())
        text=json.dumps(r)
        for keyword in ('"rgb"', '"private_pixel"', '"cram_address"',
                        '"color_bank_or_lut_word_private"'):
            self.assertNotIn(keyword,text)
        self.assertFalse(r["private_vdp2_colors_or_addresses_exported"])

    def test_aggregate_never_authenticates_emulator(self):
        r=summarize_private(build(),bytes(4096),fake_regs())
        self.assertFalse(r["original_emulator_capture_authenticated"])
        self.assertFalse(r["game_sprite_restoration_proven"])

    def test_aggregate_bad_cram_bytes(self):
        with self.assertRaises(ValueError):
            summarize_private(build(),bytes(10),fake_regs())

    def test_aggregate_bad_regs_bytes(self):
        with self.assertRaises(ValueError):
            summarize_private(build(),bytes(4096),bytes(1))

    def test_aggregate_budget_rejects_bool(self):
        with self.assertRaises(ValueError):
            summarize_private(build(),bytes(4096),fake_regs(),max_texels=True)

    def test_aggregate_budget_skips_sprite(self):
        r=summarize_private(build(),bytes(4096),fake_regs(),max_texels=8)
        self.assertEqual(r["budget_limited_sprite_records"],1)

    def test_private_all_three_snapshots_required(self):
        with tempfile.TemporaryDirectory() as td:
            image=Path(td)/"fake.iso"
            image.write_bytes(b"x")
            with self.assertRaises(ValueError):
                analyze_private(image,vram=Path(td)/"ram")

    def test_original_iso_pin_rejects_synthetic(self):
        with tempfile.TemporaryDirectory() as td:
            image=Path(td)/"fake.iso"
            image.write_bytes(b"x")
            with self.assertRaises(ValueError):
                analyze_private(image)


if __name__ == "__main__":
    unittest.main()
