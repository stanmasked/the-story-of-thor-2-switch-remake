"""Stage 14 tests use synthetic SH-2 opcodes and a synthetic literal pool."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage14_vdp1_record_copy_probe import (
    ROUTINE_WORDS,
    VDP1_VRAM_BASE,
    matches_vdp1_record_copy_routine,
    mov_l_pc_target,
    scan_vdp1_record_copy_routines,
)


def fixture(start=0, literal_target=128, literal_value=VDP1_VRAM_BASE):
    words = list(ROUTINE_WORDS)
    instruction_offset = start + 4
    aligned_pc = (instruction_offset + 4) & ~3
    delta = literal_target - aligned_pc
    if delta < 0 or delta % 4 or delta // 4 > 255:
        raise ValueError("fixture target must fit a positive MOV.L PC displacement")
    words[2] = 0xD700 | (delta // 4)
    data = bytearray(max(start + len(words) * 2, literal_target + 4))
    for index, word in enumerate(words):
        if word is not None:
            data[start + index * 2:start + index * 2 + 2] = word.to_bytes(2, "big")
    data[literal_target:literal_target + 4] = literal_value.to_bytes(4, "big")
    return bytes(data)


class Stage14VDP1RecordCopyTests(unittest.TestCase):
    def test_known_copy_routine_signature_matches(self):
        self.assertTrue(matches_vdp1_record_copy_routine(fixture(), 0))

    def test_pc_relative_target_uses_aligned_pc(self):
        self.assertEqual(mov_l_pc_target(4, 0xD71E, 256), 128)

    def test_rejects_wrong_hardware_base(self):
        data = fixture(literal_value=0x25E00000)
        self.assertFalse(matches_vdp1_record_copy_routine(data, 0))

    def test_rejects_changed_copy_instruction(self):
        data = bytearray(fixture())
        data[24:26] = (0x2101).to_bytes(2, "big")
        self.assertFalse(matches_vdp1_record_copy_routine(bytes(data), 0))

    def test_rejects_changed_loop_backedge(self):
        data = bytearray(fixture())
        data[60:62] = (0x8BE9).to_bytes(2, "big")
        self.assertFalse(matches_vdp1_record_copy_routine(bytes(data), 0))

    def test_rejects_short_buffer(self):
        self.assertFalse(matches_vdp1_record_copy_routine(bytes(32), 0))

    def test_rejects_unaligned_signature_offset(self):
        self.assertFalse(matches_vdp1_record_copy_routine(fixture(), 1))

    def test_finds_signature_after_prefix(self):
        prefix = bytes(16)
        data = prefix + fixture(start=0, literal_target=144)
        result = scan_vdp1_record_copy_routines(data)
        self.assertEqual(result["matching_routine_count"], 1)

    def test_scanner_counts_multiple_signatures(self):
        first = fixture(start=0, literal_target=128)
        second = fixture(start=160, literal_target=288)
        data = bytearray(320)
        data[:len(first)] = first
        data[160:160 + len(second) - 160] = second[160:]
        result = scan_vdp1_record_copy_routines(bytes(data))
        self.assertEqual(result["matching_routine_count"], 2)

    def test_reports_32_byte_stride_facts(self):
        result = scan_vdp1_record_copy_routines(fixture())
        self.assertEqual(result["longwords_copied_per_iteration"], 8)
        self.assertEqual(result["bytes_copied_per_iteration"], 32)
        self.assertEqual(result["source_stride_bytes"], 32)
        self.assertEqual(result["destination_stride_bytes"], 32)

    def test_report_contains_no_offsets_or_payload(self):
        result = scan_vdp1_record_copy_routines(fixture())
        self.assertNotIn("offsets", result)
        self.assertNotIn("raw_bytes", result)
        self.assertNotIn("matches", result)


if __name__ == "__main__":
    unittest.main()
