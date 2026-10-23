import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage92_set07_guard_predicate_audit import (
    _delay_aware_cfg,
    _dominators,
    _find_guard_predicates,
    _loader_result_summary,
    _snapshot_summary,
    _r14_indirect_word_load_dominates_r4_guard,
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


def branch(opbase, pos, target):
    delta = (target - (pos + 4)) // 2
    assert (target - (pos + 4)) % 2 == 0
    return opbase | (delta & 0xFF)


class Stage92Set07GuardPredicateTests(unittest.TestCase):
    def test_delayed_conditional_executes_slot_before_both_successors(self):
        data = bytearray(0x20)
        put16(data, 0x00, branch(0x8D00, 0x00, 0x0A))  # BT/S -> 0x0A
        put16(data, 0x02, 0x64E1)  # delay slot
        put16(data, 0x04, 0x0009)
        put16(data, 0x06, 0x0009)
        put16(data, 0x08, 0x0009)
        put16(data, 0x0A, 0x000B)  # RTS
        cfg = _delay_aware_cfg(bytes(data), 0, len(data))
        self.assertIn(0x02, cfg["delay_slots"])
        self.assertTrue({0x00, 0x02, 0x04, 0x06, 0x08, 0x0A}.issubset(cfg["nodes"]))

    def test_delayed_unconditional_branch_does_not_fall_through(self):
        data = bytearray(0x30)
        put16(data, 0x00, 0xA006)  # BRA -> 0x10
        put16(data, 0x02, 0x0009)  # delay slot
        put16(data, 0x04, 0x0009)  # unreachable fallthrough
        put16(data, 0x10, 0x000B)
        cfg = _delay_aware_cfg(bytes(data), 0, len(data))
        self.assertIn(0x02, cfg["nodes"])
        self.assertIn(0x10, cfg["nodes"])
        self.assertNotIn(0x04, cfg["nodes"])

    def test_guard_predicates_decode_exact_values_and_mask_polarity(self):
        data = bytearray(0x180)
        name_pos = 0x100
        continuation = name_pos + 14
        put16(data, 0x20, 0x6031)
        put16(data, 0x22, 0x8860)
        put16(data, 0x24, branch(0x8B00, 0x24, continuation))
        put16(data, 0x30, 0x6053)
        put16(data, 0x32, 0x8806)
        put16(data, 0x34, branch(0x8B00, 0x34, continuation))
        put16(data, 0x40, 0x604F)
        put16(data, 0x42, 0x880F)
        put16(data, 0x44, branch(0x8B00, 0x44, continuation))
        put16(data, 0x50, 0x6031)
        put16(data, 0x52, 0xC860)
        put16(data, 0x54, branch(0x8D00, 0x54, continuation))
        put16(data, 0x56, 0x64E1)
        put16(data, 0x60, 0x6031)
        put16(data, 0x62, 0xC810)
        put16(data, 0x64, branch(0x8B00, 0x64, 0x80))
        result = _find_guard_predicates(bytes(data), name_pos, continuation)
        self.assertTrue(result["global_state_word_equals_0x60_guard_found"])
        self.assertTrue(result["r5_equals_6_guard_found"])
        self.assertTrue(result["r4_equals_15_guard_found"])
        self.assertTrue(result["tst_0x60_branch_skips_entry_when_mask_is_zero"])
        self.assertTrue(result["tst_0x60_fallthrough_requires_nonzero_mask"])
        self.assertTrue(result["mask_guard_delay_slot_loads_word_from_r14_into_r4"])
        self.assertTrue(result["tst_0x10_nonzero_selects_alternate_path"])
        self.assertEqual(result["three_value_guard_count"], 1)

    def test_guard_scan_does_not_invent_conditions(self):
        result = _find_guard_predicates(bytes(0x100), 0x80, 0x8E)
        self.assertFalse(result["global_state_word_equals_0x60_guard_found"])
        self.assertFalse(result["r5_equals_6_guard_found"])
        self.assertFalse(result["r4_equals_15_guard_found"])
        self.assertFalse(result["tst_0x60_fallthrough_requires_nonzero_mask"])
        self.assertEqual(result["three_value_guard_count"], 0)

    def test_loader_return_is_not_checked_between_load_and_entry(self):
        data = bytearray(0x100)
        name_pos = 0x20
        buffer = 0x060D8000
        put16(data, name_pos + 4, 0x420B)  # JSR @R2
        put16(data, name_pos + 6, 0x0009)  # delay slot
        put_literal_load(data, name_pos + 8, 3, 0x80, buffer)
        put16(data, name_pos + 10, 0x430B)  # JSR @R3
        put16(data, name_pos + 12, 0x0009)
        result = _loader_result_summary(bytes(data), name_pos, buffer)
        self.assertTrue(result["load_call_to_entry_shape_matches"])
        self.assertFalse(result["loader_result_explicitly_checked_before_entry"])
        self.assertTrue(result["entry_call_uses_same_destination_buffer"])
        self.assertTrue(result["only_intervening_instruction_loads_entry_target"])

    def test_loader_result_claim_is_withheld_when_shape_does_not_match(self):
        data = bytearray(0x100)
        name_pos = 0x20
        put16(data, name_pos + 4, 0x420B)
        put16(data, name_pos + 6, 0x0009)
        put_literal_load(data, name_pos + 8, 3, 0x80, 0x060D8000)
        put16(data, name_pos + 10, 0x430B)
        put16(data, name_pos + 12, 0x0009)
        result = _loader_result_summary(bytes(data), name_pos, 0x060D9000)
        self.assertFalse(result["load_call_to_entry_shape_matches"])
        self.assertIsNone(result["loader_result_explicitly_checked_before_entry"])

    def test_indirect_word_load_is_proven_when_it_dominates_r4_guard(self):
        data = bytearray(0x100)
        name_pos = 0x70
        continuation = name_pos + 14
        put16(data, 0x10, 0x6031)
        put16(data, 0x12, 0xC860)
        put16(data, 0x14, branch(0x8D00, 0x14, continuation))
        put16(data, 0x16, 0x64E1)
        put16(data, 0x20, 0x604F)
        put16(data, 0x22, 0x880F)
        put16(data, 0x24, branch(0x8B00, 0x24, continuation))
        cfg = _delay_aware_cfg(bytes(data), 0x10, len(data))
        self.assertTrue(_r14_indirect_word_load_dominates_r4_guard(bytes(data), cfg, 0x10, name_pos, continuation))

    def test_indirect_word_load_is_not_proven_when_r4_guard_has_bypass(self):
        data = bytearray(0x100)
        name_pos = 0x70
        continuation = name_pos + 14
        put16(data, 0x10, branch(0x8900, 0x10, 0x20))  # BT can bypass mask sequence
        put16(data, 0x12, 0x0009)
        put16(data, 0x14, 0x6031)
        put16(data, 0x16, 0xC860)
        put16(data, 0x18, branch(0x8D00, 0x18, continuation))
        put16(data, 0x1A, 0x64E1)
        put16(data, 0x20, 0x604F)
        put16(data, 0x22, 0x880F)
        put16(data, 0x24, branch(0x8B00, 0x24, continuation))
        cfg = _delay_aware_cfg(bytes(data), 0x10, len(data))
        self.assertFalse(_r14_indirect_word_load_dominates_r4_guard(bytes(data), cfg, 0x10, name_pos, continuation))

    def test_adjacent_global_words_are_traced_through_local_snapshot_slots(self):
        data = bytearray(0x180)
        name_pos = 0x100
        put_literal_load(data, 0x10, 13, 0xA0, 0x002FDF34)
        put16(data, 0x12, 0x7FFC)
        put_literal_load(data, 0x20, 14, 0xA4, 0x002FDF36)
        put_literal_load(data, 0x30, 1, 0xA8, 0x06096A4A)
        put16(data, 0x32, 0x2230)
        put16(data, 0x34, 0x6311)
        put16(data, 0x36, 0x2D31)
        put_literal_load(data, 0x40, 0, 0xAC, 0x06096A4C)
        put16(data, 0x42, 0x6301)
        put16(data, 0x44, 0xBDD1)
        put16(data, 0x46, 0x2E31)
        put16(data, 0x50, 0x65D1)
        put16(data, 0x52, 0x64E1)
        result = _snapshot_summary(bytes(data), name_pos, name_pos + 14)
        self.assertTrue(result["r13_slot_populated_from_global_word_pattern_found"])
        self.assertTrue(result["r14_slot_populated_from_global_word_pattern_found"])
        self.assertTrue(result["r5_reloaded_from_r13_word_slot_pattern_found"])
        self.assertTrue(result["r4_loaded_from_r14_word_slot_pattern_found"])
        self.assertTrue(result["local_word_slots_are_adjacent"])
        self.assertTrue(result["source_global_words_are_adjacent"])

    def test_dominator_analysis_does_not_claim_optional_delay_slot_is_mandatory(self):
        nodes = {0, 2, 4, 6}
        edges = {0: {2, 4}, 2: {4}, 4: {6}, 6: set()}
        dom = _dominators(0, nodes, edges)
        self.assertNotIn(2, dom[6])


if __name__ == "__main__":
    unittest.main()
