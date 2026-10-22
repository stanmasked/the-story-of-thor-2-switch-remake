"""Stage60 ROM-free tests for documented VDP2 sprite priority/shadow fields."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage58_vdp1_pixel_policy import build
from test_stage59_vdp2_cram_sprite_palette import fake_regs, fake_cram
from stage60_vdp2_sprite_priority_shadow import (
    TYPE_LAYOUTS, SHADOW_TARGET_NAMES,
    decode_compositor_registers, decode_sprite_control_bits,
    classify_pixel_private, audit_offline, run_private,
)


def regs(*, typ=0, mixed=False, window=False, shadow=0, tsp=False,
         pr=None, cc=None, calc=False):
    raw=bytearray(fake_regs(mode=1,sprtype=typ,mixed=mixed))
    if window:
        raw[0xE1] |= 0x10
    raw[0xE2:0xE4] = (shadow | (0x100 if tsp else 0)).to_bytes(2,"big")
    raw[0xEC:0xEE] = (0x40 if calc else 0).to_bytes(2,"big")
    for pair in range(4):
        p0,p1=(pr or tuple(range(8)))[pair*2:pair*2+2]
        c0,c1=(cc or tuple(range(8)))[pair*2:pair*2+2]
        raw[0xF0+pair*2:0xF2+pair*2]=(p0 | p1<<8).to_bytes(2,"big")
        raw[0x100+pair*2:0x102+pair*2]=(c0 | c1<<8).to_bytes(2,"big")
    return bytes(raw)


def state(**kwargs):
    return decode_compositor_registers(regs(**kwargs))


class Stage60CompositorContracts(unittest.TestCase):
    def test_eight_16bit_sprite_type_layouts(self):
        self.assertEqual(len(TYPE_LAYOUTS),8)
        for t,(dc,cc,pr,sd) in TYPE_LAYOUTS.items():
            with self.subTest(sprite=t):
                self.assertEqual(dc+cc+pr+int(sd),16)

    def test_type0_two_priority_bits_at_14(self):
        r=decode_sprite_control_bits(2<<14,0)
        self.assertEqual(r["priority_selector"],2)

    def test_type1_three_priority_bits_at_13(self):
        self.assertEqual(decode_sprite_control_bits(5<<13,1)["priority_selector"],5)

    def test_type2_one_priority_bit_at_14(self):
        self.assertEqual(decode_sprite_control_bits(1<<14,2)["priority_selector"],1)

    def test_type3_two_priority_bits_at_13(self):
        self.assertEqual(decode_sprite_control_bits(3<<13,3)["priority_selector"],3)

    def test_type4_two_priority_bits_at_13(self):
        self.assertEqual(decode_sprite_control_bits(2<<13,4)["priority_selector"],2)

    def test_type5_three_priority_bits_at_12(self):
        self.assertEqual(decode_sprite_control_bits(7<<12,5)["priority_selector"],7)

    def test_type6_three_priority_bits_at_12(self):
        self.assertEqual(decode_sprite_control_bits(5<<12,6)["priority_selector"],5)

    def test_type7_three_priority_bits_at_12(self):
        self.assertEqual(decode_sprite_control_bits(6<<12,7)["priority_selector"],6)

    def test_type0_three_color_ratio_bits_at_11(self):
        self.assertEqual(decode_sprite_control_bits(6<<11,0)["color_ratio_selector"],6)

    def test_type1_two_color_ratio_bits_at_11(self):
        self.assertEqual(decode_sprite_control_bits(3<<11,1)["color_ratio_selector"],3)

    def test_type5_one_color_ratio_bit_at_11(self):
        self.assertEqual(decode_sprite_control_bits(1<<11,5)["color_ratio_selector"],1)

    def test_type7_three_color_ratio_bits_at_9(self):
        self.assertEqual(decode_sprite_control_bits(5<<9,7)["color_ratio_selector"],5)

    def test_type2_shadow_bit15(self):
        self.assertTrue(decode_sprite_control_bits(0x8000,2)["shadow_flag"])

    def test_type0_does_not_have_sd_field(self):
        self.assertIsNone(decode_sprite_control_bits(0x8000,0)["shadow_flag"])

    def test_type0_normal_shadow_reserved_0x7fe(self):
        self.assertTrue(decode_sprite_control_bits(0x07FE,0)["normal_shadow_reserved_code"])
        self.assertFalse(decode_sprite_control_bits(0x07FF,0)["normal_shadow_reserved_code"])

    def test_type4_normal_shadow_0x3fe(self):
        self.assertTrue(decode_sprite_control_bits(0x03FE,4)["normal_shadow_reserved_code"])

    def test_type7_normal_shadow_0x1fe(self):
        self.assertTrue(decode_sprite_control_bits(0x01FE,7)["normal_shadow_reserved_code"])

    def test_types8_through15_deliberately_unresolved(self):
        for t in range(8,16):
            self.assertFalse(decode_sprite_control_bits(0x3F,t)["layout_supported"])

    def test_invalid_negative_code(self):
        with self.assertRaises(ValueError):
            decode_sprite_control_bits(-1,0)

    def test_invalid_bool_code(self):
        with self.assertRaises(ValueError):
            decode_sprite_control_bits(True,0)

    def test_invalid_sprite_type(self):
        with self.assertRaises(ValueError):
            decode_sprite_control_bits(1,16)

    def test_registers_have_eight_priority_numbers(self):
        s=state()
        self.assertEqual(s["sprite_priorities"],tuple(range(8)))

    def test_registers_have_eight_color_ratios(self):
        s=state()
        self.assertEqual(s["sprite_color_ratios"],tuple(range(8)))

    def test_register_priority_masks_three_bits(self):
        s=state(pr=[15]*8)
        self.assertEqual(s["sprite_priorities"],(7,)*8)

    def test_color_ratio_masks_five_bits(self):
        s=state(cc=[255]*8)
        self.assertEqual(s["sprite_color_ratios"],(31,)*8)

    def test_shadow_target_labels(self):
        self.assertEqual(len(SHADOW_TARGET_NAMES),6)
        s=state(shadow=0x29)
        self.assertEqual(s["shadow_targets_enabled"],("NBG0","NBG3","BACK"))

    def test_transparent_shadow_bit8(self):
        self.assertTrue(state(tsp=True)["transparent_msb_shadow_selected"])

    def test_type2_eligible_for_msb_shadow(self):
        self.assertTrue(state(typ=2)["msb_shadow_possible_from_registers"])

    def test_type1_ineligible_for_msb_shadow(self):
        self.assertFalse(state(typ=1)["msb_shadow_possible_from_registers"])

    def test_sprite_window_disables_msb_shadow(self):
        self.assertFalse(state(typ=2,window=True)["msb_shadow_possible_from_registers"])

    def test_rgb_mixed_disables_msb_shadow(self):
        self.assertFalse(state(typ=2,mixed=True)["msb_shadow_possible_from_registers"])

    def test_normal_shadow_reserved_even_when_disabled(self):
        d=classify_pixel_private("color_bank_code",0x07FE,state(typ=0))
        self.assertEqual(d["classification"],"normal_shadow_reserved_code_targets_disabled")

    def test_normal_shadow_target_enabled(self):
        d=classify_pixel_private("color_bank_code",0x07FE,state(typ=0,shadow=1))
        self.assertEqual(d["classification"],"normal_shadow_reserved_code_targets_enabled")

    def test_transparent_msb_shadow_uses_register_zero(self):
        d=classify_pixel_private("color_bank_code",0x8000,
                                 state(typ=2,tsp=True))
        self.assertEqual(d["classification"],"transparent_msb_shadow_candidate")
        self.assertEqual(d["priority_selector"],0)

    def test_transparent_msb_shadow_not_selected(self):
        d=classify_pixel_private("color_bank_code",0x8000,
                                 state(typ=2,tsp=False))
        self.assertEqual(d["classification"],"transparent_msb_shadow_not_selected")

    def test_opaque_msb_shadow_candidate_not_final_render(self):
        d=classify_pixel_private("color_bank_code",0x8001,
                                 state(typ=2,tsp=True))
        self.assertEqual(d["classification"],"opaque_msb_shadow_candidate")

    def test_bit15_without_configured_msb_shadow_not_assumed(self):
        d=classify_pixel_private("color_bank_code",0x8001,
                                 state(typ=2,mixed=True))
        self.assertEqual(d["classification"],
                         "bit15_set_but_msb_shadow_configuration_ineligible")

    def test_rgb_priority_always_register_zero(self):
        d=classify_pixel_private("direct_rgb_code",0x801F,state())
        self.assertEqual((d["priority_selector"],d["priority_number"]),(0,0))

    def test_rgb_color_ratio_register_zero(self):
        d=classify_pixel_private("lookup_rgb_code",0x801F,state(cc=(13,)*8))
        self.assertEqual((d["color_ratio_selector"],d["selected_color_ratio"]),(0,13))

    def test_palette_register_selection_separate_from_value(self):
        # Type0, index 2, register2 contains priority6.
        selected=classify_pixel_private("color_bank_code",0x8001,
                                       state(typ=0,pr=(1,2,6,4,5,6,7,0)))
        self.assertEqual(selected["priority_selector"],2)
        self.assertEqual(selected["priority_number"],6)

    def test_unmapped_eight_bit_type_not_invented(self):
        d=classify_pixel_private("color_bank_code",0x0021,state(typ=8))
        self.assertIsNone(d["priority_number"])
        self.assertEqual(d["classification"],"unresolved_eight_bit_sprite_type")

    def test_transparent_without_code(self):
        d=classify_pixel_private("zero_transparent",None,state())
        self.assertIsNone(d["priority_selector"])

    def test_transparent_with_code_rejected(self):
        with self.assertRaises(ValueError):
            classify_pixel_private("zero_transparent",0,state())

    def test_invalid_kind_rejected(self):
        with self.assertRaises(ValueError):
            classify_pixel_private("not_a_pixel_type",1,state())

    def test_direct_rgb_requires_marker(self):
        with self.assertRaises(ValueError):
            classify_pixel_private("direct_rgb_code",1,state())

    def test_aggregate_no_authenticated_execution(self):
        d=audit_offline(build(pixels=b"\x21",ecd=True),
                        fake_cram(),regs())
        self.assertFalse(d["authenticated_original_saturn_frame"])
        self.assertFalse(d["rendered_original_game_pixels"])

    def test_aggregate_safe_count_of_candidate_priorities(self):
        d=audit_offline(build(pixels=b"\x21",ecd=True),
                        fake_cram(),regs())
        self.assertEqual(d["source_texels_inspected"],16)
        self.assertTrue(d["priority_value_counts_in_selected_registers"])

    def test_aggregate_no_raw_code_or_pixel_address_leak(self):
        d=audit_offline(build(pixels=b"\x21",ecd=True),
                        fake_cram(),regs())
        s=json.dumps(d)
        for item in ('"texture_address_private"','"pixel_code"','"rgb"',
                     '"command_offset_private"'):
            self.assertNotIn(item,s)
        self.assertFalse(d["private_pixel_words_or_addresses_exported"])

    def test_aggregate_budget_skips_an_oversize_sprite(self):
        d=audit_offline(build(),fake_cram(),regs(),max_texels=8)
        self.assertEqual(d["sprites_skipped_due_to_budget"],1)

    def test_aggregate_rejects_bad_vdp2_regs(self):
        with self.assertRaises(ValueError):
            audit_offline(build(),fake_cram(),bytes(128))

    def test_aggregate_rejects_bad_cram(self):
        with self.assertRaises(ValueError):
            audit_offline(build(),bytes(20),regs())

    def test_aggregate_rejects_bool_budget(self):
        with self.assertRaises(ValueError):
            audit_offline(build(),fake_cram(),regs(),max_texels=True)

    def test_original_iso_pin_rejects_synthetic(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"fake.iso"
            p.write_bytes(b"synthetic only")
            with self.assertRaises(ValueError):
                run_private(p)


if __name__=="__main__":
    unittest.main()
