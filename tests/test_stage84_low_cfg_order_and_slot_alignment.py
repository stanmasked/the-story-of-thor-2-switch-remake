import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage84_low_cfg_order_and_slot_alignment import (
    _cfg_pair_order,
    _later_writer_pairs,
    _raw_alignment_summary,
)

CALLBACK = 0x0600444E
SLOT_A = 0x06000300


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


class Stage84LowCFGOrderTests(unittest.TestCase):
    def test_callback_before_writer_path(self):
        data = bytearray(0x100)
        result = _cfg_pair_order(data, 0x10, 0x80, 0x30, 0x40)
        self.assertTrue(result["callback_reached_without_writer_already_seen"])
        self.assertTrue(result["writer_reached_after_callback_on_a_direct_path"])
        self.assertFalse(result["callback_reached_with_writer_already_seen"])

    def test_writer_before_callback_path(self):
        data = bytearray(0x100)
        result = _cfg_pair_order(data, 0x10, 0x80, 0x40, 0x20)
        self.assertTrue(result["callback_reached_with_writer_already_seen"])
        self.assertFalse(result["callback_reached_without_writer_already_seen"])

    def test_conditional_branch_exposes_both_orders(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x8B0E)  # BF to 0x30; fallthrough passes writer
        result = _cfg_pair_order(data, 0x10, 0x80, 0x30, 0x20)
        self.assertEqual(result["callback_reachability_states"], 2)
        self.assertTrue(result["callback_reached_without_writer_already_seen"])
        self.assertTrue(result["callback_reached_with_writer_already_seen"])
        self.assertFalse(result["callback_reached_on_all_paths_with_writer_already_seen"])
        self.assertFalse(result["callback_reached_on_all_paths_without_writer_already_seen"])

    def test_writer_not_reachable_in_bound(self):
        data = bytearray(0x100)
        result = _cfg_pair_order(data, 0x10, 0x30, 0x40, 0x50)
        self.assertEqual(result["callback_reachability_states"], 0)
        self.assertEqual(result["writer_reachability_states"], 0)

    def test_later_writer_interval_detected(self):
        data = bytearray(0x100)
        self.assertEqual(
            _later_writer_pairs(data, [0x40, 0x70], [0x60], [0x10, 0x80]),
            [(0x10, 0x80, 0x40, 0x60)],
        )

    def test_odd_raw_address_occurrence_is_not_aligned_pointer(self):
        data = bytearray(0x100)
        data[0x21:0x25] = SLOT_A.to_bytes(4, "big")
        result = _raw_alignment_summary(data, SLOT_A)
        self.assertEqual(result["raw_big_endian_occurrences"], 1)
        self.assertEqual(result["occurrences_aligned_to_halfword"], 0)
        self.assertEqual(result["occurrences_aligned_to_longword"], 0)
        self.assertEqual(result["occurrences_used_as_pc_literal_pool_words"], 0)

    def test_aligned_raw_occurrence_is_still_not_proof_of_table(self):
        data = bytearray(0x100)
        put32(data, 0x30, SLOT_A)
        result = _raw_alignment_summary(data, SLOT_A)
        self.assertEqual(result["occurrences_aligned_to_longword"], 1)
        self.assertFalse(result["raw_occurrences_prove_pointer_table"])

    def test_literal_pool_occurrence_is_identified_separately(self):
        data = bytearray(0x100)
        literal_load(data, 0x10, 2, 0x30, SLOT_A)
        result = _raw_alignment_summary(data, SLOT_A)
        self.assertEqual(result["occurrences_used_as_pc_literal_pool_words"], 1)

    def test_aggregate_cfg_output_redacts_sites(self):
        result = _cfg_pair_order(bytearray(0x100), 0x10, 0x80, 0x30, 0x40)
        rendered = json.dumps(result)
        for value in ("0x10", "0x30", "0x40", hex(CALLBACK)):
            self.assertNotIn(value, rendered)
        self.assertFalse(result["indirect_callee_memory_effects_modeled"])

    def test_no_literal_offsets_are_returned_by_alignment_summary(self):
        data = bytearray(0x100)
        put32(data, 0x30, SLOT_A)
        result = _raw_alignment_summary(data, SLOT_A)
        rendered = json.dumps(result)
        self.assertNotIn("0x30", rendered)
        self.assertNotIn(hex(SLOT_A), rendered)


if __name__ == "__main__":
    unittest.main()
