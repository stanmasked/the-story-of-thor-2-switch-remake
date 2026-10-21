"""Stage06 tests use synthetic windows only; no original game data."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage06_target_window_probe import window_profile


class Stage06TargetWindowTests(unittest.TestCase):
    def test_empty_windows(self):
        result = window_profile([])
        self.assertEqual(result['window_count'], 0)
        self.assertIsNone(result['mean_entropy_bits_per_byte'])

    def test_all_zero_windows(self):
        result = window_profile([bytes(8), bytes(8)])
        self.assertEqual(result['unique_window_patterns'], 1)
        self.assertEqual(result['mean_zero_fraction'], 1)
        self.assertEqual(result['mean_entropy_bits_per_byte'], 0)
        self.assertEqual(result['all_zero_window_fraction'], 1)

    def test_unique_pattern_count(self):
        result = window_profile([bytes(8), bytes(8), bytes([1])*8])
        self.assertEqual(result['unique_window_patterns'], 2)

    def test_all_values_entropy(self):
        result = window_profile([bytes(range(8))])
        self.assertEqual(result['mean_entropy_bits_per_byte'], 3)
        self.assertEqual(result['mean_zero_fraction'], 0.125)

    def test_mixed_zero_fraction(self):
        result = window_profile([bytes(4) + bytes([1])*4])
        self.assertEqual(result['mean_zero_fraction'], 0.5)
        self.assertEqual(result['all_zero_window_count'], 0)

    def test_all_windows_must_have_same_length(self):
        with self.assertRaises(ValueError):
            window_profile([bytes(8), bytes(16)])

    def test_empty_window_is_rejected(self):
        with self.assertRaises(ValueError):
            window_profile([b''])

    def test_no_window_contents_are_returned(self):
        result = window_profile([bytes(8)])
        self.assertNotIn('windows', result)
        self.assertNotIn('data', result)
        self.assertNotIn('bytes', result)

    def test_zero_window_fraction(self):
        result = window_profile([bytes(8), bytes([1])*8])
        self.assertEqual(result['all_zero_window_fraction'], 0.5)

    def test_entropy_bounds(self):
        result = window_profile([bytes([7])*16, bytes(range(16))])
        self.assertGreaterEqual(result['mean_entropy_bits_per_byte'], 0)
        self.assertLessEqual(result['mean_entropy_bits_per_byte'], 4)


if __name__ == '__main__':
    unittest.main()
