"""Stage 15 tests use a synthetic SH-2 routine, literal pool, and indirect caller."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage14_vdp1_record_copy_probe import ROUTINE_WORDS, VDP1_VRAM_BASE
from stage15_vdp1_callsite_probe import (
    DESCRIPTOR_BUFFER_ADDRESS,
    SATURN_MAIN_LOAD_BASE,
    TOTAL_RECORD_COUNT_ADDRESS,
    summarize_callsite_analysis,
)


def put16(data, offset, value):
    data[offset:offset + 2] = value.to_bytes(2, "big")


def put32(data, offset, value):
    data[offset:offset + 4] = value.to_bytes(4, "big")


def make_fixture(include_call=True, overwrite_target_register=False):
    data = bytearray(0x180)
    # Guard: MOV.L @(PC),R0; MOV.W @R0,R5; EXTS.W R5,R2; TST R2,R2; BT past call.
    put16(data, 0x00, 0xD01F)  # literal at 0x80
    put16(data, 0x02, 0x6501)
    put16(data, 0x04, 0x625F)
    put16(data, 0x06, 0x2228)
    put16(data, 0x08, 0x8908)  # branch target 0x1C
    put16(data, 0x0A, 0xD41E)  # R4 = descriptor buffer, literal at 0x84
    put16(data, 0x0C, 0xD21E)  # R2 = function pointer, literal at 0x88
    put16(data, 0x0E, 0xE200 if overwrite_target_register else 0x2F42)
    put16(data, 0x10, 0x420B if include_call else 0x0009)
    put16(data, 0x12, 0x0009)
    put16(data, 0x14, 0x63F2)
    put16(data, 0x16, 0xE100)
    put16(data, 0x18, 0xD31D)  # R3 = count address, literal at 0x90
    put16(data, 0x1A, 0x2311)  # MOV.W R1,@R3 (clear count)
    put16(data, 0x1C, 0x000B)
    put16(data, 0x1E, 0x6EF6)
    # Function signature begins at 0xA0; its VDP1 literal is at 0xEC.
    for index, opcode in enumerate(ROUTINE_WORDS):
        if opcode is not None:
            put16(data, 0xA0 + index * 2, opcode)
    put16(data, 0xA4, 0xD711)
    put32(data, 0x80, TOTAL_RECORD_COUNT_ADDRESS)
    put32(data, 0x84, DESCRIPTOR_BUFFER_ADDRESS)
    put32(data, 0x88, SATURN_MAIN_LOAD_BASE + 0xA0)
    put32(data, 0x90, TOTAL_RECORD_COUNT_ADDRESS)
    put32(data, 0xEC, VDP1_VRAM_BASE)
    return bytes(data)


class Stage15VDP1CallsiteTests(unittest.TestCase):
    def test_resolves_indirect_jsr_through_matching_literal_register(self):
        result = summarize_callsite_analysis(make_fixture())
        self.assertEqual(result["routine_signature_match_count"], 1)
        self.assertEqual(result["indirect_jsr_call_site_count"], 1)

    def test_requires_jsr_after_function_pointer_load(self):
        result = summarize_callsite_analysis(make_fixture(include_call=False))
        self.assertEqual(result["indirect_jsr_call_site_count"], 0)

    def test_rejects_call_when_target_register_is_overwritten(self):
        result = summarize_callsite_analysis(make_fixture(overwrite_target_register=True))
        self.assertEqual(result["indirect_jsr_call_site_count"], 0)

    def test_detects_descriptor_pointer_in_r4(self):
        result = summarize_callsite_analysis(make_fixture())
        self.assertTrue(result["descriptor_buffer_passed_in_r4"])

    def test_detects_guarded_total_record_budget(self):
        result = summarize_callsite_analysis(make_fixture())
        self.assertTrue(result["record_budget_loaded_into_r5_and_zero_guarded"])

    def test_detects_budget_clear_after_call(self):
        result = summarize_callsite_analysis(make_fixture())
        self.assertTrue(result["record_budget_cleared_after_call"])

    def test_reports_eight_byte_descriptor_layout(self):
        result = summarize_callsite_analysis(make_fixture())
        self.assertEqual(result["descriptor_bytes_consumed_per_entry"], 8)
        self.assertEqual(
            [field["bytes"] for field in result["descriptor_fields"]],
            [4, 2, 2],
        )
        self.assertEqual(result["copy_unit_bytes"], 32)

    def test_direct_bsr_count_is_zero_for_indirect_call_fixture(self):
        result = summarize_callsite_analysis(make_fixture())
        self.assertEqual(result["direct_relative_bsr_call_count"], 0)

    def test_output_does_not_include_source_offsets_or_bytes(self):
        result = summarize_callsite_analysis(make_fixture())
        self.assertNotIn("call_offset", result)
        self.assertNotIn("routine_offset", result)
        self.assertNotIn("raw_bytes", result)
        self.assertNotIn("matches", result)


if __name__ == "__main__":
    unittest.main()
