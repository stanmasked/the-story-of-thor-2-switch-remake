import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage89_leaf_entry_shape_audit import (
    classify_target_entry,
    summarize_layer,
)


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | delta // 4)
    put32(data, literal_pos, value)


def simple_prologue(data, pos):
    put16(data, pos, 0x2FE6)
    put16(data, pos + 2, 0x4F22)


def layer_fixture(call_count=1):
    data = bytearray(0x300)
    simple_prologue(data, 0x20)
    simple_prologue(data, 0xC0)
    literal_load(data, 0x24, 3, 0x200, CODE_LOAD_ADDRESS + 0xC0)
    put16(data, 0x26, 0x0009)
    put16(data, 0x28, 0x430B)
    put16(data, 0x2A, 0x0009)
    if call_count > 1:
        literal_load(data, 0x3A, 2, 0x204, CODE_LOAD_ADDRESS + 0xC0)
        put16(data, 0x3C, 0x0009)
        put16(data, 0x3E, 0x420B)
        put16(data, 0x40, 0x0009)
    return data


class Stage89LeafEntryShapeTests(unittest.TestCase):
    def test_straight_line_leaf_return_recognized(self):
        data = bytearray(0x200)
        put16(data, 0x40, 0x6043)
        put16(data, 0x42, 0x6343)
        put16(data, 0x44, 0x000B)
        self.assertEqual(
            classify_target_entry(data, CODE_LOAD_ADDRESS + 0x40),
            "straight_line_leaf_return",
        )

    def test_conditional_early_return_recognized(self):
        data = bytearray(0x200)
        put16(data, 0x40, 0x2668)
        put16(data, 0x42, 0x8F02)  # BF/S with an early-return fallthrough
        put16(data, 0x44, 0x6753)
        put16(data, 0x46, 0x000B)
        self.assertEqual(
            classify_target_entry(data, CODE_LOAD_ADDRESS + 0x40),
            "conditional_early_return",
        )

    def test_frame_prologue_takes_precedence(self):
        data = bytearray(0x200)
        simple_prologue(data, 0x40)
        put16(data, 0x44, 0x000B)
        self.assertEqual(
            classify_target_entry(data, CODE_LOAD_ADDRESS + 0x40),
            "frame_prologue",
        )

    def test_call_before_return_is_not_a_pure_leaf(self):
        data = bytearray(0x200)
        put16(data, 0x40, 0x430B)
        put16(data, 0x42, 0x0009)
        put16(data, 0x44, 0x000B)
        self.assertEqual(
            classify_target_entry(data, CODE_LOAD_ADDRESS + 0x40),
            "early_return_after_call",
        )

    def test_no_early_return_is_unknown(self):
        data = bytearray(0x200)
        put16(data, 0x40, 0x6043)
        put16(data, 0x42, 0x6343)
        self.assertEqual(
            classify_target_entry(data, CODE_LOAD_ADDRESS + 0x40),
            "no_early_rts",
        )

    def test_out_of_range_target_fails_closed(self):
        data = bytearray(0x200)
        self.assertEqual(
            classify_target_entry(data, CODE_LOAD_ADDRESS + len(data) + 2),
            "outside_main_executable",
        )

    def test_literal_backed_call_target_is_classified(self):
        data = layer_fixture()
        result = summarize_layer(data, 0x20, 0x80)
        self.assertEqual(result["jsr_like_sites"], 1)
        self.assertEqual(result["jsr_sites_with_resolved_literal_targets"], 1)
        self.assertEqual(result["unique_targets"], 1)
        self.assertEqual(result["unique_targets_with_frame_prologue"], 1)
        self.assertTrue(result["all_jsr_targets_resolved"])

    def test_duplicate_calls_share_one_unique_target(self):
        data = layer_fixture(call_count=2)
        result = summarize_layer(data, 0x20, 0x80)
        self.assertEqual(result["jsr_like_sites"], 2)
        self.assertEqual(result["unique_targets"], 1)

    def test_empty_call_layer_fails_closed(self):
        result = summarize_layer(bytes(0x200), 0x20, 0x80)
        self.assertEqual(result["jsr_like_sites"], 0)
        self.assertFalse(result["all_jsr_targets_resolved"])
        self.assertFalse(result["target_classification_is_runtime_proof"])

    def test_summary_redacts_addresses_and_offsets(self):
        result = summarize_layer(layer_fixture(), 0x20, 0x80)
        rendered = json.dumps(result)
        for value in ("0x20", "0x28", "0xC0", hex(CODE_LOAD_ADDRESS)):
            self.assertNotIn(value, rendered)


if __name__ == "__main__":
    unittest.main()
