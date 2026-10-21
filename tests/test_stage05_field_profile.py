"""Stage05 unit tests use synthetic bytes only; no original game assets."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage05_field_profile import byte_profile, word_profile, profile_items, six_byte_table_profile


def make_six_byte_chain(rows):
    count = len(rows) - 1
    table_end = 2 + 2 * (count + 1)
    offsets = [table_end + 6 * i for i in range(len(rows))]
    return count.to_bytes(2, 'big') + b''.join(v.to_bytes(2, 'big') for v in offsets) + b''.join(rows)


class Stage05FieldProfileTests(unittest.TestCase):
    def test_empty_byte_profile(self):
        result = byte_profile(b'')
        self.assertEqual(result['sampled_bytes'], 0)
        self.assertIsNone(result['entropy_bits_per_byte'])

    def test_byte_profile_extremes(self):
        result = byte_profile(bytes(32))
        self.assertEqual(result['unique_values'], 1)
        self.assertEqual(result['entropy_bits_per_byte'], 0)
        self.assertEqual(result['zero_fraction'], 1)

    def test_byte_profile_all_values(self):
        result = byte_profile(bytes(range(256)))
        self.assertEqual(result['unique_values'], 256)
        self.assertEqual(result['entropy_bits_per_byte'], 8)

    def test_word_profile_signed_range(self):
        result = word_profile([0, 0x7fff, 0x8000, 0xffff])
        self.assertEqual(result['min_signed'], -32768)
        self.assertEqual(result['max_signed'], 32767)
        self.assertEqual(result['zero_count'], 1)

    def test_word_profile_alignment(self):
        result = word_profile([8, 16, 17, 24])
        self.assertEqual(result['aligned_to_8_count'], 3)
        self.assertEqual(result['aligned_to_8_fraction'], 0.75)

    def test_candidate_reference_profile(self):
        items = [bytes((0, 1, 0, 16, 0, 32, 255, 240)),
                 bytes((0, 2, 0, 16, 0, 40, 255, 232)),
                 bytes((0, 3, 0, 24, 0, 48, 255, 224))]
        result = profile_items(items, third_size=128)
        candidate = result['candidate_third_section_reference']
        self.assertEqual(candidate['unique_values'], 2)
        self.assertEqual(candidate['in_bounds_with_eight_byte_margin_count'], 3)
        self.assertEqual(candidate['aligned_to_eight_count'], 3)

    def test_candidate_reference_out_of_bounds(self):
        item = bytes((0, 1, 3, 25, 0, 32, 255, 240))
        result = profile_items([item], third_size=800)
        self.assertEqual(result['candidate_third_section_reference']['in_bounds_with_eight_byte_margin_count'], 0)

    def test_item_width_is_checked(self):
        with self.assertRaises(ValueError):
            profile_items([b'bad'], third_size=100)

    def test_six_byte_chain(self):
        rows = [bytes((0, 1, 0, 2, 0, 3)), bytes((0, 4, 0, 5, 0, 6))]
        result = six_byte_table_profile(make_six_byte_chain(rows))
        self.assertTrue(result['six_byte_chain'])
        self.assertEqual(result['record_count'], 2)
        self.assertEqual(result['record_width_bytes'], 6)

    def test_non_six_byte_chain_is_not_accepted(self):
        section = make_six_byte_chain([bytes(6), bytes(6)]) + b'X'
        result = six_byte_table_profile(section)
        self.assertFalse(result['six_byte_chain'])

    def test_missing_index_slot_does_not_break_contiguous_rows(self):
        row_a, row_b = bytes(6), bytes((0, 1, 0, 2, 0, 3))
        section = (2).to_bytes(2, 'big') + (8).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (14).to_bytes(2, 'big') + row_a + row_b
        result = six_byte_table_profile(section)
        self.assertTrue(result['indexed_table_detected'])
        self.assertEqual(result['missing_zero_slots'], 1)
        self.assertTrue(result['six_byte_chain'])
        self.assertEqual(result['record_count'], 2)

    def test_report_does_not_expose_raw_values_or_bytes(self):
        item = bytes((0, 1, 0, 16, 0, 32, 255, 240))
        result = profile_items([item], third_size=128)
        self.assertNotIn('items', result)
        self.assertNotIn('offsets', result)
        self.assertNotIn('raw_bytes', result)
        self.assertNotIn('records', result)


if __name__ == '__main__':
    unittest.main()
