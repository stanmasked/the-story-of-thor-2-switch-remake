"""Tests use synthetic bytes only; no original Sega assets are needed."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage03_index_tables import inspect_counted_table


def table(offsets, payload_len):
    count = len(offsets) - 1
    return count.to_bytes(2, 'big') + b''.join(v.to_bytes(2, 'big') for v in offsets) + bytes(payload_len)


class Stage03Tests(unittest.TestCase):
    def test_detects_six_byte_records(self):
        report = inspect_counted_table(table([10, 16, 22, 28], 24))
        self.assertTrue(report['six_byte_record_chain_candidate'])
        self.assertEqual(report['indexed_slots'], 4)
        self.assertEqual(report['gap_count'], 3)

    def test_zero_slot_is_missing(self):
        report = inspect_counted_table(table([10, 0, 16, 22], 18))
        self.assertEqual(report['missing_zero'], 1)
        self.assertTrue(report['six_byte_record_chain_candidate'])

    def test_ffff_slot_is_missing(self):
        report = inspect_counted_table(table([10, 65535, 16, 22], 18))
        self.assertEqual(report['missing_ffff'], 1)
        self.assertTrue(report['six_byte_record_chain_candidate'])

    def test_rejects_bad_first_offset(self):
        self.assertIsNone(inspect_counted_table(table([12, 16, 22, 28], 24)))

    def test_rejects_out_of_bounds_offset(self):
        self.assertIsNone(inspect_counted_table(table([10, 16, 999, 28], 24)))

    def test_rejects_reverse_offsets(self):
        self.assertIsNone(inspect_counted_table(table([10, 22, 16, 28], 24)))

    def test_rejects_odd_offset(self):
        self.assertIsNone(inspect_counted_table(table([10, 17, 22, 28], 24)))

    def test_rejects_truncated_header(self):
        self.assertIsNone(inspect_counted_table(b'\0\4\0\12'))

    def test_rejects_zero_count(self):
        self.assertIsNone(inspect_counted_table(b'\0\0\0\4' + bytes(8)))

    def test_variable_record_lengths(self):
        report = inspect_counted_table(table([10, 24, 40, 54], 50))
        self.assertIsNotNone(report)
        self.assertFalse(report['six_byte_record_chain_candidate'])

    def test_duplicate_offset_recognized(self):
        report = inspect_counted_table(table([10, 16, 16, 22], 18))
        self.assertEqual(report['duplicate_offsets'], 1)


if __name__ == '__main__':
    unittest.main()
