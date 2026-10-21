"""Stage09 nibble statistics tests use synthetic bytes only."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage09_nibble_structure_probe import candidate_blocks, profile_candidate_block, summarize_blocks


class Stage09NibbleStructureTests(unittest.TestCase):
    def test_empty_block(self):
        result = profile_candidate_block(b'')
        self.assertEqual(result['block_bytes'], 0)
        self.assertIsNone(result['same_nibble_byte_fraction'])

    def test_repeated_nibbles(self):
        result = profile_candidate_block(bytes((0x00, 0x11, 0x22, 0xFF)))
        self.assertEqual(result['same_nibble_byte_fraction'], 1)
        self.assertEqual(result['unique_nibble_values'], 4)
        self.assertEqual(result['zero_byte_fraction'], 0.25)

    def test_uniform_byte_range_baseline(self):
        result = profile_candidate_block(bytes(range(256)))
        self.assertEqual(result['same_nibble_byte_fraction'], 0.0625)
        self.assertEqual(result['unique_byte_values'], 256)
        self.assertEqual(result['unique_nibble_values'], 16)

    def test_nibble_entropy_is_bounded(self):
        result = profile_candidate_block(bytes(range(256)))
        self.assertGreaterEqual(result['nibble_entropy_bits_per_pixel'], 0)
        self.assertLessEqual(result['nibble_entropy_bits_per_pixel'], 4)

    def test_summarize_empty_blocks(self):
        result = summarize_blocks([])
        self.assertEqual(result['candidate_block_count'], 0)
        self.assertIsNone(result['median_block_bytes'])

    def test_summarize_blocks(self):
        result = summarize_blocks([bytes((0x11,)) * 32, bytes((0x22,)) * 64])
        self.assertEqual(result['candidate_block_count'], 2)
        self.assertEqual(result['candidate_bytes_total'], 96)
        self.assertEqual(result['median_block_bytes'], 48)
        self.assertEqual(result['mean_same_nibble_byte_fraction'], 1)

    def test_candidate_block_boundaries(self):
        section = bytes(4096)
        items = [
            (64).to_bytes(2, 'big') + bytes(6),
            (72).to_bytes(2, 'big') + bytes(6),
            (80).to_bytes(2, 'big') + bytes(6),
        ]
        blocks = candidate_blocks(items, section)
        # Offsets are multiplied by eight: 512, 576, 640; last region exceeds limit.
        self.assertEqual([len(block) for block in blocks], [64, 64])

    def test_candidate_blocks_ignore_small_offsets(self):
        section = bytes(512)
        items = [(1).to_bytes(2, 'big') + bytes(6), (2).to_bytes(2, 'big') + bytes(6)]
        self.assertEqual(candidate_blocks(items, section), [])

    def test_report_does_not_include_payload_bytes(self):
        result = profile_candidate_block(bytes((0x11, 0x22)))
        self.assertNotIn('raw_bytes', result)
        self.assertNotIn('payload', result)
        self.assertNotIn('values', result)


if __name__ == '__main__':
    unittest.main()
