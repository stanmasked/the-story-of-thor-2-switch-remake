"""Stage 13 tests use synthetic SH-2 opcodes and literal pools only."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage13_sh2_literal_reference_probe import (
    scan_sh2_literal_references,
    sh2_movl_pc_literal_target,
)


class Stage13SH2LiteralTests(unittest.TestCase):
    def test_movl_pc_relative_target(self):
        self.assertEqual(sh2_movl_pc_literal_target(0, 0xD002, 64), 12)

    def test_pc_alignment_when_instruction_starts_at_offset_two(self):
        self.assertEqual(sh2_movl_pc_literal_target(2, 0xD001, 64), 8)

    def test_non_movl_opcode_is_ignored(self):
        self.assertIsNone(sh2_movl_pc_literal_target(0, 0x9002, 64))

    def test_unaligned_instruction_offset_is_rejected(self):
        self.assertIsNone(sh2_movl_pc_literal_target(1, 0xD001, 64))

    def test_out_of_bounds_literal_is_rejected(self):
        self.assertIsNone(sh2_movl_pc_literal_target(30, 0xD0FF, 32))

    def test_finds_one_hardware_literal_reference(self):
        data = bytearray(32)
        data[0:2] = (0xD002).to_bytes(2, "big")
        data[12:16] = (0x25C00000).to_bytes(4, "big")
        result = scan_sh2_literal_references(bytes(data))
        self.assertEqual(result["mov_l_pc_relative_instruction_candidates"], 1)
        self.assertEqual(result["hardware_reference_instruction_count"], 1)
        self.assertEqual(result["hardware_references"][0]["name"], "VDP1_VRAM_BASE")

    def test_two_instructions_can_share_one_literal_slot(self):
        data = bytearray(32)
        data[0:2] = (0xD002).to_bytes(2, "big")  # target 12
        data[4:6] = (0xD001).to_bytes(2, "big")  # target 12
        data[12:16] = (0x25C00000).to_bytes(4, "big")
        result = scan_sh2_literal_references(bytes(data))
        ref = result["hardware_references"][0]
        self.assertEqual(ref["instruction_reference_count"], 2)
        self.assertEqual(ref["unique_instruction_count"], 2)
        self.assertEqual(ref["unique_literal_slot_count"], 1)

    def test_unrelated_literal_is_not_reported(self):
        data = bytearray(32)
        data[0:2] = (0xD002).to_bytes(2, "big")
        data[12:16] = (0x12345678).to_bytes(4, "big")
        result = scan_sh2_literal_references(bytes(data))
        self.assertEqual(result["hardware_reference_instruction_count"], 0)
        self.assertEqual(result["hardware_references"], [])

    def test_empty_data(self):
        result = scan_sh2_literal_references(b"")
        self.assertEqual(result["mov_l_pc_relative_instruction_candidates"], 0)
        self.assertEqual(result["hardware_references"], [])

    def test_report_has_counts_not_offsets(self):
        data = bytearray(32)
        data[0:2] = (0xD002).to_bytes(2, "big")
        data[12:16] = (0x25C00000).to_bytes(4, "big")
        result = scan_sh2_literal_references(bytes(data))
        self.assertNotIn("offsets", result)
        self.assertNotIn("raw_bytes", result)
        self.assertNotIn("literal_offsets", result["hardware_references"][0])


if __name__ == "__main__":
    unittest.main()
