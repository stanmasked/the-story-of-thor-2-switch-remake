import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage100_low_memory_service_slot_provenance import _slot_call_pattern_sites
from stage102_sgl_call_pattern_correlation import (
    _callsite_signature,
    _summarize_call_sites,
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


class Stage102SglCallPatternTests(unittest.TestCase):
    def test_r4_setup_and_r5_zero_delay_signature_is_detected(self):
        data = bytearray(0x80)
        put_literal_load(data, 0x10, 3, 0x40, SLOT)
        put16(data, 0x12, 0x6232)  # MOV.L @R3,R2
        put16(data, 0x14, 0x9419)  # MOV.W @(disp,PC),R4
        put16(data, 0x16, 0x420B)  # JSR @R2
        put16(data, 0x18, 0xE500)  # MOV #0,R5 in delay slot
        signature = _callsite_signature(bytes(data), 0x16)
        self.assertTrue(signature["r4_pc_relative_setup_near_call"])
        self.assertTrue(signature["r5_zero_in_call_delay_slot"])
        self.assertTrue(signature["r4_setup_and_r5_zero_delay_signature"])

    def test_r4_immediate_in_delay_slot_is_classified_separately(self):
        data = bytearray(0x40)
        put16(data, 0x0C, 0xE401)  # MOV #1,R4 before call
        put16(data, 0x10, 0x420B)
        put16(data, 0x12, 0xE4FF)  # MOV #-1,R4 in delay slot
        signature = _callsite_signature(bytes(data), 0x10)
        self.assertTrue(signature["r4_immediate_setup_near_call"])
        self.assertTrue(signature["r4_immediate_in_call_delay_slot"])
        self.assertFalse(signature["r5_zero_in_call_delay_slot"])
        self.assertFalse(signature["r4_setup_and_r5_zero_delay_signature"])

    def test_slot_dereference_jsr_callsite_is_recovered(self):
        data = bytearray(0x80)
        put_literal_load(data, 0x10, 3, 0x40, SLOT)
        put16(data, 0x12, 0x6232)
        put16(data, 0x14, 0x9419)
        put16(data, 0x16, 0x420B)
        put16(data, 0x18, 0xE500)
        refs, calls = _slot_call_pattern_sites(bytes(data), SLOT)
        self.assertEqual(refs, 1)
        self.assertEqual(calls, [0x16])

    def test_overwritten_target_register_is_not_classified_as_a_call(self):
        data = bytearray(0x80)
        put_literal_load(data, 0x10, 3, 0x40, SLOT)
        put16(data, 0x12, 0x6232)  # MOV.L @R3,R2
        put16(data, 0x14, 0xE200)  # MOV #0,R2 destroys target provenance
        put16(data, 0x16, 0x420B)  # JSR @R2 must not count
        refs, calls = _slot_call_pattern_sites(bytes(data), SLOT)
        self.assertEqual(refs, 1)
        self.assertEqual(calls, [])

    def test_aggregate_counts_do_not_expose_callsite_locations(self):
        data = bytearray(0x100)
        put16(data, 0x0C, 0x9419)
        put16(data, 0x10, 0x420B)
        put16(data, 0x12, 0xE500)
        put16(data, 0x2C, 0xD401)
        put16(data, 0x30, 0x420B)
        put16(data, 0x32, 0xE500)
        put16(data, 0x3C, 0xE4FF)
        put16(data, 0x40, 0x420B)
        put16(data, 0x42, 0xE4FC)
        summary = _summarize_call_sites(bytes(data), [0x10, 0x30, 0x40])
        self.assertEqual(summary["slot_call_pattern_count"], 3)
        self.assertEqual(summary["calls_with_r4_setup_and_r5_zero_delay"], 2)
        self.assertEqual(summary["calls_with_r4_immediate_in_delay_slot"], 2)
        self.assertFalse(any("offset" in key or "address" in key for key in summary))

    def test_other_delay_slot_register_is_not_misclassified(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0x420B)
        put16(data, 0x12, 0xE300)  # MOV #0,R3
        signature = _callsite_signature(bytes(data), 0x10)
        self.assertFalse(signature["r5_zero_in_call_delay_slot"])
        self.assertFalse(signature["r4_immediate_in_call_delay_slot"])


if __name__ == "__main__":
    unittest.main()
