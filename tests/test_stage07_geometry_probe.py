"""Stage07 tests use synthetic data only; no original game payload is needed."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage07_geometry_probe import (
    geometry_table_profile,
    is_triangle_like_record,
    signed16,
    texture_pointer_profile,
)


def make_record(x1, y1, x2, y2, x3, y3):
    words = (x1, y1, x2, y2, x3, y3, 0x7FFF)
    return b''.join((word & 0xFFFF).to_bytes(2, 'big') for word in words)


class Stage07GeometryProbeTests(unittest.TestCase):
    def test_signed16(self):
        self.assertEqual(signed16(0x0009), 9)
        self.assertEqual(signed16(0xFFF8), -8)
        self.assertEqual(signed16(0x8000), -32768)

    def test_triangle_like_marker(self):
        section = bytes(8) + make_record(-8, 9, -34, 0, -16, 14)
        self.assertTrue(is_triangle_like_record(section, 8))
        self.assertFalse(is_triangle_like_record(section, 9))
        self.assertFalse(is_triangle_like_record(section, len(section) - 8))

    def test_texture_pointer_alignment_and_gaps(self):
        items = [
            bytes((0, 4, 0, 0, 0, 0, 0, 0)),
            bytes((0, 8, 0, 0, 0, 0, 0, 0)),
            bytes((0, 12, 0, 0, 0, 0, 0, 0)),
        ]
        result = texture_pointer_profile(items, section_size=512)
        self.assertEqual(result['non_null_pointer_occurrences'], 3)
        self.assertEqual(result['unique_non_null_offsets'], 3)
        self.assertTrue(result['all_non_null_offsets_32_byte_aligned'])
        self.assertEqual(result['gaps_multiple_of_32_count'], 2)

    def test_texture_null_pointer_is_ignored_for_alignment(self):
        items = [bytes(8), bytes((0, 4, 0, 0, 0, 0, 0, 0))]
        result = texture_pointer_profile(items, section_size=64)
        self.assertEqual(result['null_pointer_count'], 1)
        self.assertEqual(result['non_null_pointer_occurrences'], 1)
        self.assertEqual(result['minimum_32_byte_window_in_bounds_count'], 1)

    def test_geometry_table_detects_valid_prefix(self):
        section = bytearray(256)
        for i, target in enumerate((64, 78, 92, 106)):
            section[16 + i * 2:18 + i * 2] = target.to_bytes(2, 'big')
            section[target:target + 14] = make_record(i, i + 1, i + 2, i + 3, i + 4, i + 5)
        item = bytes(2) + (16).to_bytes(2, 'big') + bytes(4)
        result = geometry_table_profile([item], bytes(section))
        self.assertEqual(result['candidate_table_prefix_count'], 1)
        self.assertEqual(result['valid_nonzero_entries_across_candidate_prefixes'], 4)
        self.assertEqual(result['unique_triangle_like_record_offsets'], 4)
        self.assertEqual(result['signed_coordinate_word_min'], 0)
        self.assertEqual(result['signed_coordinate_word_max'], 8)

    def test_duplicate_table_pointer_is_counted_once(self):
        section = bytearray(256)
        for i, target in enumerate((64, 78, 92, 106)):
            section[16 + i * 2:18 + i * 2] = target.to_bytes(2, 'big')
            section[target:target + 14] = make_record(i, i + 1, i + 2, i + 3, i + 4, i + 5)
        item = bytes(2) + (16).to_bytes(2, 'big') + bytes(4)
        result = geometry_table_profile([item, item], bytes(section))
        self.assertEqual(result['candidate_table_prefix_count'], 1)
        self.assertEqual(result['valid_nonzero_entries_across_candidate_prefixes'], 4)

    def test_geometry_table_rejects_wrong_terminator(self):
        section = bytearray(256)
        for i, target in enumerate((64, 78, 92, 106)):
            section[16 + i * 2:18 + i * 2] = target.to_bytes(2, 'big')
            section[target:target + 14] = make_record(i, i + 1, i + 2, i + 3, i + 4, i + 5)
        section[64 + 12:64 + 14] = b'\x00\x00'
        item = bytes(2) + (16).to_bytes(2, 'big') + bytes(4)
        result = geometry_table_profile([item], bytes(section))
        self.assertEqual(result['candidate_table_prefix_count'], 0)

    def test_geometry_table_rejects_too_few_nonzero_entries(self):
        section = bytearray(256)
        for i, target in enumerate((64, 78, 92)):
            section[16 + i * 2:18 + i * 2] = target.to_bytes(2, 'big')
            section[target:target + 14] = make_record(i, i + 1, i + 2, i + 3, i + 4, i + 5)
        item = bytes(2) + (16).to_bytes(2, 'big') + bytes(4)
        result = geometry_table_profile([item], bytes(section))
        self.assertEqual(result['candidate_table_prefix_count'], 0)

    def test_geometry_table_allows_zero_slots(self):
        section = bytearray(256)
        targets = (64, 0, 78, 0, 92, 106)
        for i, target in enumerate(targets):
            section[16 + i * 2:18 + i * 2] = target.to_bytes(2, 'big')
            if target:
                section[target:target + 14] = make_record(i, i + 1, i + 2, i + 3, i + 4, i + 5)
        item = bytes(2) + (16).to_bytes(2, 'big') + bytes(4)
        result = geometry_table_profile([item], bytes(section))
        self.assertEqual(result['candidate_table_prefix_count'], 1)
        self.assertEqual(result['valid_nonzero_entries_across_candidate_prefixes'], 4)

    def test_out_of_bounds_texture_windows_are_counted(self):
        item = bytes((0xFF, 0xFF, 0, 0, 0, 0, 0, 0))
        result = texture_pointer_profile([item], section_size=128)
        self.assertEqual(result['minimum_32_byte_window_in_bounds_count'], 0)

    def test_report_contains_no_payload_fields(self):
        result = geometry_table_profile([], bytes(32))
        self.assertNotIn('raw_bytes', result)
        self.assertNotIn('images', result)
        self.assertNotIn('records', result)


if __name__ == '__main__':
    unittest.main()
