"""Stage 11 tests use synthetic data only."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage11_exception_container_probe import (
    byte_statistics,
    profile_14_byte_tail_markers,
    profile_indexed_records,
)


def make_record(size, first_word=0):
    record = bytearray(size)
    record[:2] = first_word.to_bytes(2, "big")
    return bytes(record)


class Stage11ExceptionContainerTests(unittest.TestCase):
    def test_empty_byte_statistics(self):
        result = byte_statistics(b"")
        self.assertEqual(result["size_bytes"], 0)
        self.assertIsNone(result["entropy_bits_per_byte"])

    def test_constant_byte_statistics(self):
        result = byte_statistics(bytes(64))
        self.assertEqual(result["unique_byte_values"], 1)
        self.assertEqual(result["zero_fraction"], 1)
        self.assertEqual(result["entropy_bits_per_byte"], 0)

    def test_byte_entropy_is_bounded(self):
        result = byte_statistics(bytes(range(256)))
        self.assertGreaterEqual(result["entropy_bits_per_byte"], 0)
        self.assertLessEqual(result["entropy_bits_per_byte"], 8)

    def test_empty_record_profile(self):
        result = profile_indexed_records([])
        self.assertEqual(result["record_count"], 0)
        self.assertIsNone(result["record_size_min"])

    def test_record_shape_and_counter_are_separate_checks(self):
        records = [
            make_record(22, 1),  # 6 + 8*2; expected counter is 1
            make_record(30, 0),  # 6 + 8*3; expected counter is 2
            make_record(38, 3),  # 6 + 8*4; expected counter is 3
        ]
        result = profile_indexed_records(records)
        self.assertEqual(result["records_with_6_plus_8n_shape"], 3)
        self.assertEqual(result["records_matching_stage04_header_counter"], 2)

    def test_record_size_histogram(self):
        result = profile_indexed_records([make_record(22), make_record(22), make_record(30)])
        self.assertEqual(result["record_size_min"], 22)
        self.assertEqual(result["record_size_max"], 30)
        self.assertEqual(result["record_size_histogram"], [
            {"size_bytes": 22, "count": 2},
            {"size_bytes": 30, "count": 1},
        ])

    def test_record_zero_header_and_tail_marker_counts(self):
        record_a = bytearray(make_record(22, 0))
        record_b = bytearray(make_record(22, 1))
        record_b[-2:] = b"\x7f\xff"
        result = profile_indexed_records([bytes(record_a), bytes(record_b)])
        self.assertEqual(result["records_with_zero_first_word"], 1)
        self.assertEqual(result["records_ending_in_7fff"], 1)

    def test_one_14_byte_tail_marker(self):
        record = bytes(12) + b"\x7f\xff"
        result = profile_14_byte_tail_markers(record)
        self.assertEqual(result["word_7fff_count"], 1)
        self.assertEqual(result["candidate_14_byte_tail_marker_count"], 1)
        self.assertEqual(result["unique_candidate_14_byte_record_count"], 1)
        self.assertEqual(result["candidate_records_at_14_byte_grid_count"], 1)

    def test_marker_scan_does_not_assume_contiguous_records(self):
        section = (bytes(12) + b"\x7f\xff") + bytes(2) + (bytes(12) + b"\x7f\xff")
        result = profile_14_byte_tail_markers(section)
        self.assertEqual(result["candidate_14_byte_tail_marker_count"], 2)
        self.assertEqual(result["candidate_records_with_14_byte_successor_count"], 0)

    def test_no_marker(self):
        result = profile_14_byte_tail_markers(bytes(64))
        self.assertEqual(result["word_7fff_count"], 0)
        self.assertEqual(result["candidate_14_byte_tail_marker_count"], 0)

    def test_profile_contains_no_payload(self):
        result = profile_14_byte_tail_markers(bytes(14))
        self.assertNotIn("raw_bytes", result)
        self.assertNotIn("offsets", result)
        self.assertNotIn("records", result)


if __name__ == "__main__":
    unittest.main()
