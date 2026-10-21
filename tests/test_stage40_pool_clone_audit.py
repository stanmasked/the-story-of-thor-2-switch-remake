"""Synthetic-only Stage40 tests for pool slot selection and structure copying."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from test_stage39_writer_function_dispatch import (
    fixture as stage39_fixture, put, ENTRY,
)
from stage40_pool_clone_audit import (
    POOL_OPS, COPY_OPS, movw_pc_literal, check_pool_slot_selector,
    check_copy_helper, inspect_writer_clone, summarize_clone,
)

POOL = 0x1200
COPY = 0x1400


def fixture(mutation=None, with_pool=True, with_copy=True,
            with_writer_arg=True, with_links=True):
    data = bytearray(stage39_fixture())
    if with_links:
        data[0xE00:0xE04] = (0x06004000 + POOL).to_bytes(4, "big")
        data[0xE04:0xE08] = (0x06004000 + COPY).to_bytes(4, "big")
    if with_pool:
        put(data, POOL, 0xD529)
        for off, op in POOL_OPS.items():
            put(data, POOL + off, op)
        put(data, POOL + 0x0E, 0x9044)
        put(data, POOL + 0x18, 0x9340)
        put(data, POOL + 0x9C, 276)
        put(data, POOL + 0x9A, 128)
        data[POOL + 0xA8:POOL + 0xAC] = (0x06080000).to_bytes(4, "big")
    if with_copy:
        for i, op in enumerate(COPY_OPS):
            put(data, COPY + 2 * i, op)
    if with_writer_arg:
        put(data, ENTRY + 0x66, 0x945E)
        put(data, ENTRY + 0x126, 240)
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage40Tests(unittest.TestCase):
    def report(self, **kwargs):
        return summarize_clone(fixture(**kwargs))

    def test_full_signature(self):
        self.assertEqual(self.report()["complete_pool_copy_writer_chains"], 1)

    def test_pool_size(self):
        self.assertEqual(self.report()["pool_capacity_slots"], 43)

    def test_slot_stride(self):
        self.assertEqual(self.report()["slot_stride_bytes"], 276)

    def test_copy_word_count(self):
        self.assertEqual(self.report()["copy_words"], 69)

    def test_copy_byte_count(self):
        self.assertEqual(self.report()["copy_bytes"], 276)

    def test_copy_loop_count(self):
        self.assertEqual(self.report()["copy_iterations"], 23)

    def test_equal_stride_and_copy(self):
        self.assertTrue(self.report()["copy_size_equals_slot_stride"])

    def test_zero_marker(self):
        self.assertTrue(self.report()["free_slot_first_word_zero_test"])

    def test_minus_one_marker(self):
        self.assertTrue(self.report()["selected_slot_marked_minus_one_before_copy"])

    def test_initializer_field(self):
        self.assertEqual(self.report()["selected_slot_initial_word_field_offset"], 128)

    def test_null_return_when_full(self):
        self.assertTrue(self.report()["null_return_when_no_slot"])

    def test_allocator_argument(self):
        self.assertEqual(self.report()["initial_allocator_argument_value"], 240)

    def test_source_is_saved_input(self):
        self.assertEqual(self.report()["copy_source"], "saved_original_R13")

    def test_destination_is_result_pointer(self):
        self.assertEqual(self.report()["copy_destination"], "new_slot_R14_from_nonzero_R0")

    def test_clone_index_is_thirty_eight(self):
        self.assertEqual(self.report()["copied_object_index_updated_to"], 38)

    def test_runtime_execution_not_claimed(self):
        self.assertFalse(self.report()["runtime_execution_verified"])

    def test_alias_not_claimed(self):
        self.assertFalse(self.report()["writer_and_later_dispatcher_alias_verified"])

    def test_pool_helper_independently(self):
        self.assertEqual(check_pool_slot_selector(fixture(), POOL)["slot_capacity"], 43)

    def test_copy_helper_independently(self):
        self.assertEqual(check_copy_helper(fixture(), COPY)["long_words_copied"], 69)

    def test_writer_links_both_helpers(self):
        self.assertIsNotNone(inspect_writer_clone(fixture(), ENTRY))

    def test_missing_pool(self):
        self.assertEqual(self.report(with_pool=False)["complete_pool_copy_writer_chains"], 0)

    def test_missing_copy(self):
        self.assertEqual(self.report(with_copy=False)["complete_pool_copy_writer_chains"], 0)

    def test_missing_writer_literal(self):
        self.assertEqual(self.report(with_writer_arg=False)["complete_pool_copy_writer_chains"], 0)

    def test_pool_target_corrupted(self):
        self.assertEqual(self.report(mutation=(0xE00, 0))["complete_pool_copy_writer_chains"], 0)

    def test_copy_target_corrupted(self):
        self.assertEqual(self.report(mutation=(0xE04, 0))["complete_pool_copy_writer_chains"], 0)

    def test_capacity_opcode_corrupted(self):
        self.assertEqual(self.report(mutation=(POOL+4, 0xE62C))["complete_pool_copy_writer_chains"], 0)

    def test_return_pointer_register_corrupted(self):
        self.assertEqual(self.report(mutation=(POOL+0x14, 0x6153))["complete_pool_copy_writer_chains"], 0)

    def test_stride_literal_corrupted(self):
        self.assertEqual(self.report(mutation=(POOL+0x9C, 280))["complete_pool_copy_writer_chains"], 0)

    def test_initializer_word_displacement(self):
        self.assertEqual(self.report(mutation=(POOL+0x9A, 130))["selected_slot_initial_word_field_offset"], 130)

    def test_pool_loop_stride_corrupted(self):
        self.assertEqual(self.report(mutation=(POOL+0x1E, 0x3538))["complete_pool_copy_writer_chains"], 0)

    def test_copy_word_count_corrupted(self):
        self.assertEqual(self.report(mutation=(COPY+2, 0xE544))["complete_pool_copy_writer_chains"], 0)

    def test_source_post_increment_corrupted(self):
        self.assertEqual(self.report(mutation=(COPY+6, 0x6242))["complete_pool_copy_writer_chains"], 0)

    def test_copy_branch_delay_corrupted(self):
        self.assertEqual(self.report(mutation=(COPY+0x1A, 0x0009))["complete_pool_copy_writer_chains"], 0)

    def test_copy_branch_predicate_corrupted(self):
        self.assertEqual(self.report(mutation=(COPY+0x18, 0x8BF4))["complete_pool_copy_writer_chains"], 0)

    def test_wrong_source_argument(self):
        self.assertEqual(self.report(mutation=(ENTRY+0x7E, 0x64E3))["complete_pool_copy_writer_chains"], 0)

    def test_misaligned_word_literal_rejected(self):
        self.assertIsNone(movw_pc_literal(fixture(), ENTRY+0x67))

    def test_empty_binary(self):
        self.assertEqual(summarize_clone(b"")["complete_pool_copy_writer_chains"], 0)

    def test_aggregate_only_output(self):
        for key in ("entry","pool_address","copy_offset","program_position",
                    "slot_pointer","raw_bytes"):
            self.assertNotIn(key, self.report())


if __name__ == "__main__":
    unittest.main()
