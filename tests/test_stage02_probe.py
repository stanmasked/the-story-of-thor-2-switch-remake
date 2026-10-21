"""Synthetic only. No copyrighted game data in tests."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage02_probe import offsets_layout, monotonic_be16_prefix, stats

class Stage02Tests(unittest.TestCase):
    def test_root_three_sections(self):
        d = b"".join(x.to_bytes(4, "big") for x in (12, 20, 26)) + bytes(range(20))
        s = offsets_layout(d)
        self.assertEqual(s["table_offset"], 0)
        self.assertEqual(s["section_size_bytes"], [8, 6, 6])

    def test_four_byte_preamble(self):
        d = b"PRE!" + b"".join(x.to_bytes(4, "big") for x in (12, 18, 22)) + bytes(16)
        s = offsets_layout(d)
        self.assertEqual(s["table_offset"], 4)
        self.assertEqual(s["section_size_bytes"], [6, 4, 6])

    def test_backwards_offsets_rejected(self):
        d = b"".join(x.to_bytes(4, "big") for x in (12, 28, 20)) + bytes(30)
        self.assertIsNone(offsets_layout(d))

    def test_out_of_bounds_rejected(self):
        d = b"".join(x.to_bytes(4, "big") for x in (12, 20, 10000)) + bytes(30)
        self.assertIsNone(offsets_layout(d))

    def test_short_header_rejected(self):
        self.assertIsNone(offsets_layout(bytes(12)))

    def test_constant_entropy(self):
        self.assertEqual(stats(bytes(100))["entropy_bits_per_byte"], 0)
        self.assertEqual(stats(bytes(256))["zero_fraction"], 1)

    def test_full_entropy(self):
        self.assertEqual(stats(bytes(range(256)))["entropy_bits_per_byte"], 8)

    def test_monotonic_prefix(self):
        d = b"".join(x.to_bytes(2, "big") for x in (2, 4, 6, 5)) + bytes(24)
        self.assertEqual(monotonic_be16_prefix(d), 3)

if __name__ == "__main__":
    unittest.main()
