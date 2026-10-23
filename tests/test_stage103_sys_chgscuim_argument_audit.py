import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage103_sys_chgscuim_argument_audit import (
    _constant_at_call,
    _constant_before,
    _pair_category,
    _summarize_calls,
)


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


class Stage103SysChgscuimArgumentTests(unittest.TestCase):
    def test_signed_immediate_argument_is_resolved(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0xE503)  # MOV #3,R5
        self.assertEqual(_constant_before(bytes(data), 0x12, 5), (3, "immediate"))

    def test_pc_relative_word_mask_is_sign_extended(self):
        data = bytearray(0x80)
        put16(data, 0x10, 0x9416)  # MOV.W @(disp,PC),R4 -> literal at 0x40
        put16(data, 0x40, 0xF7FF)
        self.assertEqual(
            _constant_before(bytes(data), 0x12, 4),
            (-2049, "pc_relative_word"),
        )

    def test_register_copy_provenance_resolves_zero_argument(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0xEE00)  # MOV #0,R14
        put16(data, 0x12, 0x65E3)  # MOV R14,R5
        self.assertEqual(
            _constant_before(bytes(data), 0x14, 5),
            (0, "register_copy"),
        )

    def test_call_delay_slot_overrides_r4_argument(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0xE503)  # MOV #3,R5
        put16(data, 0x12, 0x420B)  # JSR @R2
        put16(data, 0x14, 0xE4FF)  # MOV #-1,R4 in delay slot
        self.assertEqual(_constant_at_call(bytes(data), 0x12, 4), (-1, "delay_immediate"))
        self.assertEqual(_constant_at_call(bytes(data), 0x12, 5), (3, "immediate"))

    def test_zero_r5_delay_slot_and_pc_relative_r4_pair(self):
        data = bytearray(0x80)
        put16(data, 0x10, 0x9416)  # R4 from a PC-relative word
        put16(data, 0x12, 0x420B)
        put16(data, 0x14, 0xE500)  # MOV #0,R5 in delay slot
        put16(data, 0x40, 0xFF7F)
        self.assertEqual(_constant_at_call(bytes(data), 0x12, 4), (-129, "pc_relative_word"))
        self.assertEqual(_constant_at_call(bytes(data), 0x12, 5), (0, "delay_immediate"))

    def test_unrecognized_memory_load_does_not_invent_a_constant(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0x6522)  # MOV.L @R2,R5: dynamic value
        self.assertEqual(_constant_before(bytes(data), 0x12, 5), (None, "other_write"))

    def test_pair_categories_match_mask_argument_shape_without_values(self):
        self.assertEqual(_pair_category(-1, 3), "negative_r4_small_nonzero_r5")
        self.assertEqual(_pair_category(-4, 0), "negative_r4_zero_r5")
        self.assertEqual(_pair_category(None, 0), "unresolved")
        self.assertEqual(_pair_category(7, 2), "other_resolved_pair")

    def test_summary_emits_counts_not_locations_or_raw_values(self):
        data = bytearray(0x80)
        put16(data, 0x10, 0xE503)
        put16(data, 0x12, 0x420B)
        put16(data, 0x14, 0xE4FF)
        put16(data, 0x20, 0x940E)
        put16(data, 0x22, 0x420B)
        put16(data, 0x24, 0xE500)
        put16(data, 0x40, 0xFF7F)
        summary = _summarize_calls(bytes(data), [0x12, 0x22])
        self.assertEqual(summary["slot_call_pattern_count"], 2)
        self.assertEqual(summary["argument_pairs_resolved_in_bounded_linear_windows"], 2)
        self.assertEqual(summary["calls_with_negative_r4_and_zero_r5"], 1)
        self.assertEqual(summary["calls_with_negative_r4_and_small_nonzero_r5"], 1)
        self.assertFalse(any("offset" in key or "address" in key or "raw" in key for key in summary))


if __name__ == "__main__":
    unittest.main()
