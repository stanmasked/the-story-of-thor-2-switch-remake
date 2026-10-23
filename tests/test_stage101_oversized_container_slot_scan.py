import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage101_oversized_container_slot_scan import (
    _pc_literal_reference_count,
    _scan_container,
)


SLOT = 0x06000344


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def put_literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | (delta // 4))
    put32(data, literal_pos, value)


class Stage101OversizedContainerSlotTests(unittest.TestCase):
    def test_pc_relative_literal_reference_is_counted(self):
        data = bytearray(0x80)
        put_literal_load(data, 0x10, 2, 0x40, SLOT)
        self.assertEqual(_pc_literal_reference_count(bytes(data), SLOT), 1)

    def test_raw_bytes_without_pc_literal_instruction_are_not_references(self):
        data = bytearray(0x80)
        put32(data, 0x20, SLOT)
        self.assertEqual(_pc_literal_reference_count(bytes(data), SLOT), 0)

    def test_multiple_independent_pc_literal_references_are_counted(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 2, 0x40, SLOT)
        put_literal_load(data, 0x18, 3, 0x44, SLOT)
        self.assertEqual(_pc_literal_reference_count(bytes(data), SLOT), 2)

    def test_container_scan_reports_aggregates_only(self):
        data = bytearray(0x80)
        put_literal_load(data, 0x10, 2, 0x40, SLOT)
        summary = _scan_container(bytes(data), SLOT)
        self.assertEqual(summary["size_bytes"], len(data))
        self.assertEqual(summary["exact_pointer_byte_sequence_occurrences"], 1)
        self.assertEqual(summary["pc_relative_literal_reference_count"], 1)
        self.assertFalse(summary["full_code_disassembly_performed"])
        self.assertFalse(any("offset" in key or "address" in key or "bytes" in key for key in summary))

    def test_nonmatching_container_has_zero_candidates(self):
        summary = _scan_container(bytes(0x400), SLOT)
        self.assertEqual(summary["exact_pointer_byte_sequence_occurrences"], 0)
        self.assertEqual(summary["pc_relative_literal_reference_count"], 0)

    def test_literal_data_is_not_returned_in_summary(self):
        data = bytearray(0x80)
        put_literal_load(data, 0x10, 2, 0x40, SLOT)
        summary = _scan_container(bytes(data), SLOT)
        rendered = repr(summary)
        self.assertNotIn("06000344", rendered)
        self.assertNotIn("D214", rendered)


if __name__ == "__main__":
    unittest.main()
