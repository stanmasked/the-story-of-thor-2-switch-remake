import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage95_dispatch_slot_cross_module_audit import DISPATCH_SLOT
from stage96_dispatch_slot_writer_alias_census import (
    POINTER_RADIUS,
    SCAN_WINDOW_INSTRUCTIONS,
    _raw_occurrence_summary,
    _summarize_payload,
    summarize_payloads,
)


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def put_literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | (delta // 4))
    put32(data, literal_pos, value)


class Stage96DispatchSlotWriterAliasTests(unittest.TestCase):
    def test_exact_slot_pointer_followed_by_longword_store_is_found(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x2122)  # MOV.L R2,@R1
        result = _summarize_payload("TEST.BIN", bytes(data))
        self.assertEqual(result["exact_dispatch_slot_pc_literal_reference_count"], 1)
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 1)
        self.assertEqual(result["bounded_store_candidates_by_mode"], {"indirect": 1})
        self.assertEqual(result["store_candidates_using_alias_or_pointer_arithmetic"], 0)

    def test_nearby_base_plus_add_alias_is_found(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT - 0x6C)
        put16(data, 0x12, 0x716C)  # ADD #0x6C,R1
        put16(data, 0x14, 0x2122)  # MOV.L R2,@R1
        result = _summarize_payload("TEST.BIN", bytes(data))
        self.assertEqual(result["exact_dispatch_slot_pc_literal_reference_count"], 0)
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 1)
        self.assertEqual(result["bounded_store_candidates_by_mode"], {"indirect": 1})
        self.assertEqual(result["store_candidates_using_alias_or_pointer_arithmetic"], 1)

    def test_displacement_store_to_slot_is_found(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT - 0x2C)
        put16(data, 0x12, 0x112B)  # MOV.L R2,@(0x2C,R1)
        result = _summarize_payload("TEST.BIN", bytes(data))
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 1)
        self.assertEqual(result["bounded_store_candidates_by_mode"], {"displacement_long": 1})

    def test_predecrement_store_to_slot_is_found(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT + 4)
        put16(data, 0x12, 0x2126)  # MOV.L R2,@-R1
        result = _summarize_payload("TEST.BIN", bytes(data))
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 1)
        self.assertEqual(result["bounded_store_candidates_by_mode"], {"predecrement": 1})

    def test_wrong_base_register_does_not_count_as_target_store(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x2322)  # MOV.L R2,@R3, not @R1
        result = _summarize_payload("TEST.BIN", bytes(data))
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 0)

    def test_scan_stops_at_control_transfer_except_delay_slot(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0xA004)  # BRA away
        put16(data, 0x14, 0x2122)  # store in branch delay slot: still inspected
        put16(data, 0x16, 0x2122)  # after branch: not inspected
        result = _summarize_payload("TEST.BIN", bytes(data))
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 1)

    def test_unknown_r0_index_is_reported_as_unresolved_not_a_writer(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 2, 0x80, DISPATCH_SLOT - 0x29)
        put16(data, 0x12, 0x0234)  # MOV.B R3,@(R0,R2), R0 is unknown
        result = _summarize_payload("MONS.BIN", bytes(data))
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 0)
        self.assertEqual(result["unresolved_indexed_store_candidate_count"], 1)

    def test_raw_occurrences_are_not_equated_with_pc_literal_references(self):
        data = bytearray(0x100)
        put32(data, 0x20, DISPATCH_SLOT)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT)
        summary = _raw_occurrence_summary(bytes(data), DISPATCH_SLOT)
        self.assertGreaterEqual(summary["raw_big_endian_occurrence_count"], 2)
        self.assertGreaterEqual(summary["occurrences_matching_pc_literal_pool_words"], 1)

    def test_payload_summary_keeps_root_module_counts_separate(self):
        first = bytearray(0x100)
        second = bytearray(0x100)
        put_literal_load(first, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(first, 0x12, 0x2122)
        result = summarize_payloads({"A.BIN": bytes(first), "B.BIN": bytes(second)})
        self.assertEqual(result["root_modules_scanned"], 2)
        self.assertEqual(result["per_module"]["B.BIN"]["generic_stack_prologue_candidate_count"], 0)
        self.assertEqual(result["bounded_exact_target_store_candidate_count"], 1)
        self.assertEqual(result["store_candidates_by_root_module"], {"A.BIN": 1})
        self.assertFalse(result["all_store_writers_resolved"])
        self.assertEqual(result["pointer_radius_bytes"], POINTER_RADIUS)
        self.assertEqual(result["scan_window_instructions_after_literal_load"], SCAN_WINDOW_INSTRUCTIONS)


if __name__ == "__main__":
    unittest.main()
