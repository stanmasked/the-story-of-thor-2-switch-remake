"""Stage 10 tests use synthetic data only; no game ISO is needed."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage10_dimension_palette_probe import (
    candidate_blocks,
    dimension_candidates,
    dimension_profile,
    direct_dimensions_match,
    is_loose_palette_like,
    palette_window_profile,
    scan_palette_windows,
)


class Stage10DimensionPaletteTests(unittest.TestCase):
    def test_384_byte_block_has_multiple_4bpp_dimensions(self):
        options = dimension_candidates(384, 4)
        self.assertIn((24, 32), options)
        self.assertIn((48, 16), options)
        self.assertGreater(len(options), 1)

    def test_invalid_bpp_is_rejected(self):
        with self.assertRaises(ValueError):
            dimension_candidates(384, 5)

    def test_nonmatching_length_has_no_exact_dimensions(self):
        self.assertEqual(dimension_candidates(33, 4), [])
        self.assertEqual(dimension_candidates(33, 8), [])
        self.assertEqual(dimension_candidates(33, 16), [])

    def test_dimension_profile_reports_ambiguity(self):
        profile = dimension_profile([384])
        self.assertEqual(profile["candidate_block_count"], 1)
        self.assertEqual(profile["blocks_compatible_with_all_three_bpp_hypotheses"], 1)
        self.assertGreater(profile["median_dimension_interpretations_per_block"], 1)

    def test_empty_dimension_profile(self):
        profile = dimension_profile([])
        self.assertEqual(profile["candidate_block_count"], 0)
        self.assertIsNone(profile["median_dimension_interpretations_per_block"])

    def test_palette_window_requires_exact_size(self):
        with self.assertRaises(ValueError):
            palette_window_profile(bytes(31))

    def test_palette_window_profile_uses_synthetic_words(self):
        window = b"".join(value.to_bytes(2, "big") for value in range(1, 17))
        profile = palette_window_profile(window)
        self.assertEqual(profile["unique_rgb555_values"], 16)
        self.assertEqual(profile["nonzero_color_count"], 16)
        self.assertTrue(is_loose_palette_like(profile))

    def test_zero_window_is_not_palette_like(self):
        self.assertFalse(is_loose_palette_like(palette_window_profile(bytes(32))))

    def test_candidate_blocks_use_next_distinct_address_and_size_bounds(self):
        section = bytes(4096)
        items = [
            (64).to_bytes(2, "big") + bytes(6),
            (72).to_bytes(2, "big") + bytes(6),
            (80).to_bytes(2, "big") + bytes(6),
        ]
        blocks = candidate_blocks(items, section)
        self.assertEqual([len(block) for _, block in blocks], [64, 64])

    def test_direct_dimensions_must_match_exact_length(self):
        self.assertTrue(direct_dimensions_match(24, 32, 384, 4))
        self.assertFalse(direct_dimensions_match(24, 32, 384, 8))
        self.assertFalse(direct_dimensions_match(23, 32, 384, 4))

    def test_palette_scan_only_reports_aggregates(self):
        window = b"".join(value.to_bytes(2, "big") for value in range(1, 17))
        result = scan_palette_windows([
            ("A.BIN", "section3", window * 2),
            ("B.BIN", "section3", window),
        ])
        self.assertEqual(result["loose_palette_like_window_count"], 3)
        self.assertEqual(result["candidate_contents_repeated_across_multiple_containers"], 1)
        self.assertNotIn("offsets", result)
        self.assertNotIn("raw_bytes", result)


if __name__ == "__main__":
    unittest.main()
