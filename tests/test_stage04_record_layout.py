"""Stage04 tests with entirely synthetic test records (no Sega assets)."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage04_record_layout import indexed_records, inspect_record_layout


def item_record(n):
    return (n - 1).to_bytes(2, 'big') + bytes(4) + bytes(8*n)


def synthetic_section(records, markers=()):
    markers = set(markers)
    if len(records) + len(markers) == 1:
        markers.add(1)  # counted table parser requires at least two index slots
    count = len(records) + len(markers) - 1
    current = 2 + 2*(count+1)
    offsets = []
    payload = b''
    records_iter = iter(records)
    for i in range(count+1):
        if i in markers:
            offsets.append(0 if i % 2 else 0xffff)
        else:
            record = next(records_iter)
            offsets.append(current)
            current += len(record)
            payload += record
    return count.to_bytes(2, 'big') + b''.join(x.to_bytes(2, 'big') for x in offsets) + payload


class Stage04Tests(unittest.TestCase):
    def test_single_record(self):
        result = inspect_record_layout(synthetic_section([item_record(1)]))
        self.assertTrue(result['fully_validated'])
        self.assertEqual(result['record_count'], 1)

    def test_variable_records(self):
        result = inspect_record_layout(synthetic_section([item_record(1), item_record(2), item_record(16)]))
        self.assertTrue(result['fully_validated'])
        self.assertEqual((result['min_item_count'], result['max_item_count']), (1, 16))

    def test_zero_missing_marker(self):
        result = inspect_record_layout(synthetic_section([item_record(2), item_record(4)], markers=(1,)))
        self.assertTrue(result['fully_validated'])
        self.assertEqual(result['record_count'], 2)

    def test_ffff_leading_marker_rejected(self):
        result = inspect_record_layout(synthetic_section([item_record(2), item_record(3)], markers=(0,)))
        self.assertIsNone(result)

    def test_bad_header_counter(self):
        bad = bytes(6) + bytes(16)
        result = inspect_record_layout(synthetic_section([bad]))
        self.assertFalse(result['fully_validated'])
        self.assertEqual(result['unmatched_count'], 1)

    def test_wrong_record_size(self):
        result = inspect_record_layout(synthetic_section([bytes(6)+bytes(9)]))
        self.assertFalse(result['fully_validated'])

    def test_zero_item_record_rejected(self):
        result = inspect_record_layout(synthetic_section([bytes(6)]))
        self.assertFalse(result['fully_validated'])

    def test_histogram(self):
        result = inspect_record_layout(synthetic_section([item_record(3), item_record(3), item_record(2)]))
        self.assertEqual(result['item_count_histogram'], {'2': 1, '3': 2})

    def test_duplicate_indices_rejected(self):
        good = synthetic_section([item_record(2), item_record(3)])
        bad = good[:4] + good[2:4] + good[6:]
        self.assertIsNone(indexed_records(bad))

    def test_reverse_indices_rejected(self):
        good = synthetic_section([item_record(2), item_record(3)])
        bad = good[:2] + good[4:6] + good[2:4] + good[6:]
        self.assertIsNone(indexed_records(bad))

    def test_truncated_table_rejected(self):
        self.assertIsNone(indexed_records(b'\0\5\0\10'))

    def test_metadata_does_not_export_records(self):
        result = inspect_record_layout(synthetic_section([item_record(2)]))
        for key in ('records', 'data', 'offsets'):
            self.assertNotIn(key, result)


if __name__ == '__main__':
    unittest.main()
