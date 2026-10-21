"""Stage37 synthetic-only tests; original executable is never uploaded to CI."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage36_dispatch_index_audit import (
    fixture as stage36_fixture, put, BASE, CELL
)
from stage37_index_writer_type_guard import (
    zero_type_guard, type_switch_1_to_6, indexed_word_store_pairs,
    dispatch_locations, inspect_local_guards
)

BASE_ZERO = BASE - 130
CELL_ZERO = CELL - 80
CELL_SWITCH = CELL - 70
STORE_R14 = 0xC50
STORE_R4 = 0xC60


def fixture(mutation=None, guards=True, writers=True, dispatch_corrupt=None):
    data = bytearray(stage36_fixture(corrupt=dispatch_corrupt))
    if guards:
        for start in (BASE_ZERO, CELL_ZERO):
            for delta, code in ((0,0xE01E), (2,0x02EC),
                                (4,0x2228), (6,0x8904)):
                put(data, start+delta, code)
        for delta, code in (
            (0, 0xE01E), (2, 0x00EC), (4, 0x8801), (6, 0x8D05),
            (8, 0xE503), (10, 0x8802), (12, 0x8909),
            (14, 0x8803), (16, 0x8909), (18, 0x8804),
            (20, 0x8909), (22, 0x8805), (24, 0x8909),
            (26, 0x8806), (28, 0x8909),
        ):
            put(data, CELL_SWITCH+delta, code)
    if writers:
        for p, op in ((STORE_R14,0x0E35),(STORE_R4,0x0435)):
            put(data,p,0xE07E)
            put(data,p+2,op)
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage37Tests(unittest.TestCase):
    def report(self, *args, **kwargs):
        return inspect_local_guards(fixture(*args, **kwargs))

    def test_dispatches_linked_to_stage36(self):
        self.assertEqual(self.report()["linked_signed_word_dispatches"],2)

    def test_base_and_cell_anchors(self):
        self.assertEqual({x["anchor"] for x in dispatch_locations(fixture())},
                         {"table_start","selected_cell"})

    def test_two_zero_tests_of_other_field(self):
        self.assertEqual(self.report()[
            "zero_tests_of_separate_type_byte_R14_plus_30"],2)

    def test_one_type_switch(self):
        self.assertEqual(self.report()[
            "comparisons_of_type_byte_against_1_through_6"],1)

    def test_both_dispatches_have_type_checks(self):
        self.assertEqual(self.report()["dispatch_paths_with_type_byte_tests"],2)

    def test_no_in_prefix_index_store_pair(self):
        self.assertEqual(self.report()[
            "dispatch_paths_with_direct_index_store_pairs_in_observed_prefix"],0)

    def test_separate_byte_and_word_offsets(self):
        r=self.report()
        self.assertEqual(r["type_byte_field_offset"],30)
        self.assertEqual(r["index_word_field_offset"],126)

    def test_type_guard_not_an_index_guard(self):
        self.assertFalse(self.report()["type_guard_is_index_bounds_guard"])

    def test_candidate_writes_not_proven_identity(self):
        self.assertFalse(self.report()["index_writer_identity_verified"])

    def test_synthetic_r14_candidate_store(self):
        self.assertIn(STORE_R14,indexed_word_store_pairs(fixture(),14))

    def test_synthetic_r4_candidate_store(self):
        self.assertIn(STORE_R4,indexed_word_store_pairs(fixture(),4))

    def test_writer_pair_counts_increase_when_added(self):
        a=inspect_local_guards(fixture(writers=False))
        b=self.report()
        self.assertEqual(b["candidate_direct_word_store_pairs_R14_plus_126"] -
                         a["candidate_direct_word_store_pairs_R14_plus_126"],1)
        self.assertEqual(b["candidate_direct_word_store_pairs_R4_plus_126"] -
                         a["candidate_direct_word_store_pairs_R4_plus_126"],1)

    def test_bad_type_field_displacement(self):
        self.assertFalse(zero_type_guard(fixture(mutation=(BASE_ZERO,0xE01F)),
                                         BASE_ZERO))

    def test_bad_type_zero_load(self):
        self.assertEqual(self.report(mutation=(CELL_ZERO+2,0x04EC))[
            "zero_tests_of_separate_type_byte_R14_plus_30"],1)

    def test_bad_type_zero_test(self):
        self.assertEqual(self.report(mutation=(BASE_ZERO+4,0x2229))[
            "zero_tests_of_separate_type_byte_R14_plus_30"],1)

    def test_invalid_zero_conditional_branch(self):
        self.assertEqual(self.report(mutation=(BASE_ZERO+6,0x8B04))[
            "zero_tests_of_separate_type_byte_R14_plus_30"],1)

    def test_type_switch_source_byte_is_r14(self):
        self.assertFalse(type_switch_1_to_6(
            fixture(mutation=(CELL_SWITCH+2,0x04EC)),CELL_SWITCH))

    def test_type_switch_initial_value_one_required(self):
        self.assertFalse(type_switch_1_to_6(
            fixture(mutation=(CELL_SWITCH+4,0x8800)),CELL_SWITCH))

    def test_type_switch_bt_s_required(self):
        self.assertFalse(type_switch_1_to_6(
            fixture(mutation=(CELL_SWITCH+6,0x8905)),CELL_SWITCH))

    def test_type_switch_all_six_values_required(self):
        for offset in (10,14,18,22,26):
            self.assertEqual(self.report(
                mutation=(CELL_SWITCH+offset,0x8807))[
                "comparisons_of_type_byte_against_1_through_6"],0)

    def test_type_switch_branch_codes_required(self):
        self.assertEqual(self.report(
            mutation=(CELL_SWITCH+28,0x8B09))[
            "comparisons_of_type_byte_against_1_through_6"],0)

    def test_writer_immediate_required(self):
        a=indexed_word_store_pairs(fixture(),14)
        b=indexed_word_store_pairs(
            fixture(mutation=(STORE_R14,0xE07D)),14)
        self.assertEqual(len(a)-len(b),1)

    def test_writer_word_width_required(self):
        a=indexed_word_store_pairs(fixture(),4)
        b=indexed_word_store_pairs(
            fixture(mutation=(STORE_R4+2,0x0434)),4)
        self.assertEqual(len(a)-len(b),1)

    def test_writer_base_register_required(self):
        a=indexed_word_store_pairs(fixture(),14)
        b=indexed_word_store_pairs(
            fixture(mutation=(STORE_R14+2,0x0435)),14)
        self.assertEqual(len(a)-len(b),1)

    def test_invalid_writer_register_rejected(self):
        with self.assertRaises(ValueError):
            indexed_word_store_pairs(b"\x00"*8,16)

    def test_zero_guard_out_of_bounds(self):
        self.assertFalse(zero_type_guard(b"",0))
        self.assertFalse(zero_type_guard(b"\x00"*8,1))

    def test_switch_guard_out_of_bounds(self):
        self.assertFalse(type_switch_1_to_6(b"",0))
        self.assertFalse(type_switch_1_to_6(b"\x00"*32,1))

    def test_corrupt_dispatch_excludes_one_context(self):
        self.assertEqual(self.report(
            dispatch_corrupt=(CELL+8,0x0009))[
            "linked_signed_word_dispatches"],1)

    def test_no_private_program_positions_in_report(self):
        result=self.report()
        for key in ("program_offset","literal_pos","table_start",
                    "raw_bytes","candidate_positions","instruction_position"):
            self.assertNotIn(key,result)

    def test_empty_binary(self):
        report=inspect_local_guards(b"")
        self.assertEqual(report["linked_signed_word_dispatches"],0)
        self.assertEqual(report["candidate_direct_word_store_pairs_R14_plus_126"],0)


if __name__=="__main__":
    unittest.main()
