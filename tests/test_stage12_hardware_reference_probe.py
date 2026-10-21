"""Stage 12 tests use synthetic address literals only."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage12_hardware_reference_probe import (
    count_exact_literal,
    profile_hardware_literals,
)


class Stage12HardwareLiteralTests(unittest.TestCase):
    def test_count_exact_big_endian_literal(self):
        data = bytes.fromhex("25c00000 00000000 25c00000")
        self.assertEqual(count_exact_literal(data, 0x25C00000), 2)

    def test_rejects_out_of_range_literal(self):
        with self.assertRaises(ValueError):
            count_exact_literal(b"", 0x100000000)

    def test_empty_profile_is_zeroed(self):
        profile = profile_hardware_literals(b"")
        self.assertEqual(profile["vdp1_vram_base_literal_count"], 0)
        self.assertEqual(profile["vdp1_register_literal_count"], 0)
        self.assertEqual(profile["vdp2_cram_base_literal_count"], 0)

    def test_profiles_vdp1_vram_and_registers(self):
        data = bytes.fromhex("25c00000 25d00000 25d00002 25d00002")
        profile = profile_hardware_literals(data)
        self.assertEqual(profile["vdp1_vram_base_literal_count"], 1)
        self.assertEqual(profile["vdp1_register_base_literal_count"], 1)
        self.assertEqual(profile["vdp1_register_literal_count"], 3)

    def test_profiles_vdp2_memory_map(self):
        data = bytes.fromhex("25e00000 25f00000 25f80000 25f80004")
        profile = profile_hardware_literals(data)
        self.assertEqual(profile["vdp2_vram_base_literal_count"], 1)
        self.assertEqual(profile["vdp2_cram_base_literal_count"], 1)
        self.assertEqual(profile["vdp2_register_base_literal_count"], 1)
        self.assertEqual(profile["vdp2_register_literal_count"], 2)

    def test_does_not_count_partial_address(self):
        data = bytes.fromhex("00 25c00000 01")
        self.assertEqual(count_exact_literal(data, 0x25C00000), 1)

    def test_profile_contains_no_offsets_or_payload(self):
        profile = profile_hardware_literals(bytes.fromhex("25c00000 25d00000"))
        self.assertNotIn("offsets", profile)
        self.assertNotIn("raw_bytes", profile)

    def test_register_count_matches_per_register_sum(self):
        profile = profile_hardware_literals(bytes.fromhex("25d00000 25d00002 25f80000"))
        self.assertEqual(
            profile["vdp1_register_literal_count"],
            sum(profile["vdp1_register_literal_counts"].values()),
        )
        self.assertEqual(
            profile["vdp2_register_literal_count"],
            sum(profile["vdp2_register_literal_counts"].values()),
        )


if __name__ == "__main__":
    unittest.main()
