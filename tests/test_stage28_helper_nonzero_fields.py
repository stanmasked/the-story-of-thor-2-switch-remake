"""Stage28 tests use only synthetic SH-2 instruction fixtures, no game data."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage27_helper_zero_clear import fixture as base_fixture, ENTRY, put
from stage28_helper_nonzero_fields import (
    NORMAL_PATH, CALL_OFFSETS, pc_relative_movw_literal,
    branch_destination, verify_nonzero_fields, summarize_nonzero_fields,
)


def fixture(mutate=None, broken_sentinel=False, distinct_literal=False,
            detached=False, broken_zero_arm=False, wrong_movw_reg=False):
    data = bytearray(base_fixture(disable_call=detached))
    data.extend(bytes(0x200))
    for relative, opcode in NORMAL_PATH.items():
        put(data, ENTRY + relative, opcode)
    for rel, code in (
        (0x6E, 0x8D06), (0x7A, 0xA007),
        (0xB4, 0x890D), (0xDA, 0x891B),
        (0xAC, 0x928F), (0xD4, 0x927B),
    ):
        put(data, ENTRY + rel, code)
    for rel in CALL_OFFSETS:
        put(data, ENTRY + rel, 0x4D0B)  # JSR @R13
    # Both PC-relative word loads point to the same synthetic word.
    put(data, ENTRY + 0x1CE, 257 if broken_sentinel else 256)
    if distinct_literal:
        put(data, ENTRY + 0xD4, 0x927A)
    if wrong_movw_reg:
        put(data, ENTRY + 0xAC, 0x918F)
    if broken_zero_arm:
        put(data, ENTRY + 0x48, 0x0009)
    if mutate:
        rel, opcode = mutate
        put(data, ENTRY + rel, opcode)
    return bytes(data)


class Stage28NonzeroPathTests(unittest.TestCase):
    def test_complete_signature(self):
        self.assertEqual(summarize_nonzero_fields(fixture())[
            "complete_nonzero_field_processing_matches"], 1)

    def test_signed_type_three_swaps_first_two_fields(self):
        result = summarize_nonzero_fields(fixture())
        self.assertEqual(result["first_two_field_write_order_for_type_three"], [32, 31])
        self.assertEqual(result["first_two_field_write_order_for_other_types"], [31, 32])

    def test_two_guarded_conversion_groups(self):
        groups = summarize_nonzero_fields(fixture())["conditionally_processed_field_groups"]
        self.assertEqual(groups[0]["fields"], [31, 32])
        self.assertEqual(groups[0]["source_word_offset"], 88)
        self.assertEqual(groups[0]["conversion_jsr_sites"], 2)
        self.assertEqual(groups[1]["fields"], [33, 34, 35, 36])
        self.assertEqual(groups[1]["source_word_offset"], 90)
        self.assertEqual(groups[1]["conversion_jsr_sites"], 4)

    def test_shared_sentinel(self):
        groups = summarize_nonzero_fields(fixture())["conditionally_processed_field_groups"]
        self.assertEqual([g["sentinel"] for g in groups], [256, 256])

    def test_scaled_fields(self):
        result = summarize_nonzero_fields(fixture())
        self.assertTrue(result["source_byte_before_shift_doubled_for_field_35"])
        self.assertTrue(result["source_byte_before_shift_doubled_for_word_36_37"])

    def test_bts_branch_requires_exact_target(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0x6E, 0x8D07)), ENTRY))

    def test_bts_delay_add_must_be_present(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0x70, 0x0009)), ENTRY))

    def test_generic_bra_requires_exact_merge(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0x7A, 0xA006)), ENTRY))

    def test_signed_type_check_required(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0x6C, 0x8804)), ENTRY))

    def test_first_byte_storage_required(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0x76, 0x0009)), ENTRY))

    def test_field_35_shift_required(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0xA0, 0x0009)), ENTRY))

    def test_field_36_word_write_required(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0xAA, 0x0E24)), ENTRY))

    def test_first_guard_target(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0xB4, 0x890E)), ENTRY))

    def test_second_guard_target(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0xDA, 0x891A)), ENTRY))

    def test_first_indirect_conversion_call_required(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0xBA, 0x0009)), ENTRY))

    def test_last_indirect_conversion_call_required(self):
        self.assertIsNone(verify_nonzero_fields(fixture(mutate=(0x10A, 0x0009)), ENTRY))

    def test_sentinel_exactly_256(self):
        self.assertIsNone(verify_nonzero_fields(fixture(broken_sentinel=True), ENTRY))

    def test_both_literal_loads_same_slot(self):
        self.assertIsNone(verify_nonzero_fields(fixture(distinct_literal=True), ENTRY))

    def test_movw_literal_destination_register(self):
        self.assertIsNone(verify_nonzero_fields(fixture(wrong_movw_reg=True), ENTRY))

    def test_fallback_arm_necessary_for_linkage(self):
        self.assertIsNone(verify_nonzero_fields(fixture(broken_zero_arm=True), ENTRY))

    def test_unlinked_helper_not_reported(self):
        self.assertEqual(summarize_nonzero_fields(fixture(detached=True))[
            "complete_nonzero_field_processing_matches"], 0)

    def test_literal_and_branch_math(self):
        d = fixture()
        p, val = pc_relative_movw_literal(d, ENTRY + 0xAC)
        self.assertEqual(p, ENTRY + 0x1CE)
        self.assertEqual(val, 256)
        self.assertEqual(branch_destination(ENTRY + 0x6E, 0x8D06), ENTRY + 0x7E)
        self.assertEqual(branch_destination(ENTRY + 0x7A, 0xA007), ENTRY + 0x8C)
        self.assertIsNone(branch_destination(ENTRY + 0x7A, 0x0009))

    def test_no_program_positions_in_summary(self):
        result = summarize_nonzero_fields(fixture())
        for key in ("helper_entry", "program_offset", "source_bytes", "branch_positions"):
            self.assertNotIn(key, result)

    def test_empty_input(self):
        self.assertEqual(summarize_nonzero_fields(b"")[
            "stage25_helper_targets_examined"], 0)


if __name__ == "__main__":
    unittest.main()
