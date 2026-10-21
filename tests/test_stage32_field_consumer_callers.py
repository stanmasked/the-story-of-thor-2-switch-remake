"""Synthetic-only Stage32 BSR/JSR callsite and delay-slot tests."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage31_entry_guard_audit import fixture as stage31_fixture, put
from stage32_field_consumer_callers import (
    LOAD_BASE, bsr_destination, movl_pc_literal, direct_call_sites,
    indirect_call_sites, matched_consumer_entries, summarize_callers,
)

TARGETS = (0x100, 0x300, 0x500)
BSR_POSITIONS = (0xC0, 0x2A0)
LITERAL_BLOCKS = tuple(0x5E0 + i * 0x20 for i in range(8))


def fixture(mutate=None, last_variant=True, first_direct=True, second_direct=True):
    data = bytearray(stage31_fixture())
    for active, pos, target in zip(
            (first_direct, second_direct), BSR_POSITIONS, TARGETS):
        if active:
            put(data, pos, 0xB000 | (((target - pos - 4) // 2) & 0xFFF))
            put(data, pos + 2, 0x64E3)
    for i, pos in enumerate(LITERAL_BLOCKS):
        is_last = i == 7 and last_variant
        reg = 2 if i == 4 else 3
        put(data, pos, 0xD000 | (reg << 8) | 1)  # literal at PC+8
        if is_last:
            put(data, pos + 2, 0x7FFC)
            put(data, pos + 4, 0x2F46)
            put(data, pos + 6, 0x400B | (reg << 8))
            put(data, pos + 8, LOAD_BASE >> 16)  # overwritten below
            # Last call's delay slot must be at +8, so keep literal at +12.
            put(data, pos, 0xD000 | (reg << 8) | 2)
            put(data, pos + 8, 0xE502)
            data[pos + 12:pos + 16] = (LOAD_BASE + TARGETS[2]).to_bytes(4, "big")
        else:
            put(data, pos + 2, 0x400B | (reg << 8))
            put(data, pos + 4, 0x64E3)
            data[pos + 8:pos + 12] = (LOAD_BASE + TARGETS[2]).to_bytes(4, "big")
    if mutate:
        put(data, *mutate)
    return bytes(data)


class Stage32CallsiteTests(unittest.TestCase):
    def report(self, *args, **kwargs):
        return summarize_callers(fixture(*args, **kwargs))

    def test_stage31_targets(self):
        self.assertEqual([x["entry"] for x in matched_consumer_entries(fixture())], list(TARGETS))

    def test_direct_bsr_counts(self):
        self.assertEqual(self.report()["direct_bsr_calls_by_consumer"], [1, 1, 0])

    def test_indirect_jsr_counts(self):
        self.assertEqual(self.report()["pc_literal_linked_jsr_calls_by_consumer"], [0, 0, 8])

    def test_r14_argument_delay_slots(self):
        self.assertEqual(self.report()["direct_bsr_delay_slots_passing_r14_as_r4"], [1, 1, 0])
        self.assertEqual(self.report()["indirect_jsr_delay_slots_passing_r14_as_r4"], [0, 0, 7])

    def test_last_call_sets_r5_two(self):
        self.assertEqual(self.report()["indirect_jsr_delay_slots_setting_r5_to_two"], [0, 0, 1])

    def test_indirect_load_distance(self):
        self.assertEqual(self.report()["indirect_load_to_jsr_distances_bytes"][2], [2]*7+[6])

    def test_totals(self):
        self.assertEqual(self.report()["totals"], {
            "direct_bsr": 2, "resolved_indirect_jsr": 8,
            "calls_passing_r14_to_r4_in_delay_slot": 9,
            "indirect_calls_setting_r5_to_two_in_delay_slot": 1,
        })

    def test_bsr_signed_target(self):
        pos = 0x200
        self.assertEqual(bsr_destination(pos, 0xBFFE), pos)
        self.assertIsNone(bsr_destination(pos, 0xA000))

    def test_pc_literal_register_and_value(self):
        value = movl_pc_literal(fixture(), LITERAL_BLOCKS[0])
        self.assertEqual((value["register"], value["value"]), (3, LOAD_BASE + 0x500))

    def test_pc_literal_aligned(self):
        self.assertIsNone(movl_pc_literal(fixture(), LITERAL_BLOCKS[0] + 1))

    def test_first_direct_missing(self):
        self.assertEqual(self.report(first_direct=False)["direct_bsr_calls_by_consumer"], [0, 1, 0])

    def test_second_direct_missing(self):
        self.assertEqual(self.report(second_direct=False)["direct_bsr_calls_by_consumer"], [1, 0, 0])

    def test_direct_delay_mutation(self):
        self.assertEqual(self.report(mutate=(0xC2, 0x0009))[
            "direct_bsr_delay_slots_passing_r14_as_r4"], [0, 1, 0])

    def test_direct_wrong_target(self):
        self.assertEqual(self.report(mutate=(0xC0, 0xB000))[
            "direct_bsr_calls_by_consumer"], [0, 1, 0])

    def test_indirect_wrong_literal(self):
        pos = LITERAL_BLOCKS[0]
        self.assertEqual(self.report(mutate=(pos+8, 0x1111))[
            "pc_literal_linked_jsr_calls_by_consumer"], [0, 0, 7])

    def test_indirect_wrong_jsr_register(self):
        pos = LITERAL_BLOCKS[1]
        self.assertEqual(self.report(mutate=(pos+2, 0x420B))[
            "pc_literal_linked_jsr_calls_by_consumer"], [0, 0, 7])

    def test_indirect_wrong_delay_argument(self):
        pos = LITERAL_BLOCKS[2]
        self.assertEqual(self.report(mutate=(pos+4, 0x0009))[
            "indirect_jsr_delay_slots_passing_r14_as_r4"], [0, 0, 6])

    def test_last_jsr_extra_save_required(self):
        pos = LITERAL_BLOCKS[7]
        self.assertEqual(self.report(mutate=(pos+4, 0x0009))[
            "pc_literal_linked_jsr_calls_by_consumer"], [0, 0, 7])

    def test_last_jsr_r5_delay_required(self):
        pos = LITERAL_BLOCKS[7]
        self.assertEqual(self.report(mutate=(pos+8, 0x0009))[
            "indirect_jsr_delay_slots_setting_r5_to_two"], [0, 0, 0])

    def test_last_jsr_literal_rejected_if_wrong_target(self):
        pos = LITERAL_BLOCKS[7]
        self.assertEqual(self.report(mutate=(pos+12, 0x0000))[
            "pc_literal_linked_jsr_calls_by_consumer"], [0, 0, 7])

    def test_missing_complete_entry_reduces_count(self):
        self.assertEqual(len(direct_call_sites(fixture(), 0x100)), 1)
        self.assertEqual(len(direct_call_sites(fixture(), 0x180)), 0)

    def test_empty_input(self):
        self.assertEqual(summarize_callers(b"")["stage31_consumer_entries_examined"], 0)

    def test_output_hides_original_positions(self):
        report = self.report()
        for key in ("entry", "position", "literal_pos", "jsr_pos", "binary_offset"):
            self.assertNotIn(key, report)


if __name__ == "__main__":
    unittest.main()
