"""Stage 16 tests use synthetic SH-2 descriptor-writer instructions."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage15_vdp1_callsite_probe import (
    BUFFER_POINTER_SLOT_ADDRESS,
    DESCRIPTOR_BUFFER_ADDRESS,
    TOTAL_RECORD_COUNT_ADDRESS,
)
from stage16_vdp1_descriptor_writer_probe import summarize_writer_analysis


def put16(data, offset, value):
    data[offset:offset + 2] = value.to_bytes(2, "big")


def put32(data, offset, value):
    data[offset:offset + 4] = value.to_bytes(4, "big")


def make_fixture(remove_source_store=False, wrong_counter=False, wrong_capacity=False):
    data = bytearray(0x180)
    # Counter read, capacity check (512), and conditional skip.
    put16(data, 0x00, 0xD33F)  # count literal at 0x100
    put16(data, 0x02, 0x6231)
    put16(data, 0x04, 0x917F)  # capacity word at 0x106
    put16(data, 0x06, 0x3213)
    put16(data, 0x08, 0x8908)
    put16(data, 0x0A, 0x6382)  # load current buffer pointer
    put16(data, 0x0C, 0x4208)
    put16(data, 0x0E, 0x4200)
    put16(data, 0x10, 0x321C)
    put16(data, 0x12, 0x0009 if remove_source_store else 0x2322)
    put16(data, 0x14, 0x6243)  # copy argument
    put16(data, 0x16, 0x6382)
    put16(data, 0x18, 0x4221)
    put16(data, 0x1A, 0x85F8)
    put16(data, 0x1C, 0x7304)
    put16(data, 0x1E, 0x2301)
    put16(data, 0x20, 0x4221)
    put16(data, 0x22, 0x6382)
    put16(data, 0x24, 0x4221)
    put16(data, 0x26, 0x7306)
    put16(data, 0x28, 0x2321)
    put16(data, 0x2A, 0xD337)  # second counter literal at 0x108
    put16(data, 0x2C, 0x6131)
    put16(data, 0x2E, 0x7101)
    put16(data, 0x30, 0x2311)
    put16(data, 0x32, 0x6382)
    put16(data, 0x34, 0x7308)
    put16(data, 0x36, 0x2832)
    put32(data, 0x100, 0xDEADBEEF if wrong_counter else TOTAL_RECORD_COUNT_ADDRESS)
    put16(data, 0x106, 0x0100 if wrong_capacity else 0x0200)
    put32(data, 0x108, TOTAL_RECORD_COUNT_ADDRESS)
    # Include the related runtime addresses as inert literal-pool values.
    put32(data, 0x10C, BUFFER_POINTER_SLOT_ADDRESS)
    put32(data, 0x110, DESCRIPTOR_BUFFER_ADDRESS)
    return bytes(data)


class Stage16VDP1DescriptorWriterTests(unittest.TestCase):
    def test_detects_complete_descriptor_writer_pattern(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertEqual(result["descriptor_writer_candidate_count"], 1)

    def test_requires_source_address_store(self):
        result = summarize_writer_analysis(make_fixture(remove_source_store=True))
        self.assertEqual(result["descriptor_writer_candidate_count"], 0)

    def test_requires_correct_counter_global(self):
        result = summarize_writer_analysis(make_fixture(wrong_counter=True))
        self.assertEqual(result["descriptor_writer_candidate_count"], 0)

    def test_requires_512_entry_capacity_guard(self):
        result = summarize_writer_analysis(make_fixture(wrong_capacity=True))
        self.assertEqual(result["descriptor_writer_candidate_count"], 0)

    def test_reports_capacity_and_descriptor_size(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertEqual(result["descriptor_capacity_entries"], 512)
        self.assertEqual(result["descriptor_entry_size_bytes"], 8)

    def test_reports_field_offsets(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertEqual(result["descriptor_field_offsets_bytes"], [0, 4, 6])

    def test_detects_base_plus_index_times_eight_source(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertTrue(result["source_address_uses_base_plus_index_times_eight"])

    def test_detects_r5_shifted_right_by_three(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertTrue(result["per_source_count_is_r5_value_shifted_right_by_three"])

    def test_detects_single_global_increment_and_eight_byte_advance(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertTrue(result["global_budget_incremented_once_per_descriptor"])
        self.assertTrue(result["buffer_pointer_advanced_by_eight_bytes"])

    def test_flags_accounting_for_caller_validation(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertTrue(result["accounting_invariant_needs_r5_dataflow_validation"])

    def test_output_does_not_include_source_offsets_or_bytes(self):
        result = summarize_writer_analysis(make_fixture())
        self.assertNotIn("source_store_offset", result)
        self.assertNotIn("raw_bytes", result)
        self.assertNotIn("matches", result)


if __name__ == "__main__":
    unittest.main()
