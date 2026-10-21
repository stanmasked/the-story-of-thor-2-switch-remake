"""Stage29 tests use synthetic SH-2 opcodes and a synthetic image, never game bytes."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage28_helper_nonzero_fields import fixture as stage28_fixture, ENTRY, put
from stage29_sh2_q8_converter import (
    CODE_LOAD_BASE, SCALE_SIGNATURE, signed16, model_signed_q8_mul,
    movl_pc_literal, inspect_converter, summarize_converter,
)


def fixture(broken_converter=None, wrong_pointer=False, wrong_r13_load=False,
            bad_scale_first=False, bad_scale_second=False, bad_first_call=False,
            bad_second_call=False, detached=False, bad_stage28_guard=False):
    data = bytearray(stage28_fixture(detached=detached,
                                    broken_sentinel=bad_stage28_guard))
    converter = 0x6C
    for i, word in enumerate(SCALE_SIGNATURE):
        if broken_converter == i:
            word ^= 1
        put(data, converter + i * 2, word)
    address = CODE_LOAD_BASE + (0x100000 if wrong_pointer else converter)
    data[ENTRY + 0x1DC:ENTRY + 0x1E0] = address.to_bytes(4, "big")
    if wrong_r13_load:
        put(data, ENTRY + 0x90, 0xDC52)  # PC relative R12, not R13
    if bad_scale_first:
        put(data, ENTRY + 0xB0, 0x0C8D)
    if bad_scale_second:
        put(data, ENTRY + 0xDC, 0x64C3)
    if bad_first_call:
        put(data, ENTRY + 0xBA, 0x0009)
    if bad_second_call:
        put(data, ENTRY + 0x10A, 0x0009)
    return bytes(data)


class Stage29Q8ConverterTests(unittest.TestCase):
    def test_full_converter(self):
        report = summarize_converter(fixture())
        self.assertEqual(report["helpers_with_resolved_q8_converter"], 1)

    def test_six_indirect_calls_resolve_to_one_function(self):
        r = summarize_converter(fixture())
        self.assertEqual(r["linked_indirect_conversion_call_sites"], 6)
        self.assertEqual(r["distinct_resolved_converter_targets"], 1)

    def test_sentinel_scale_sources(self):
        r = summarize_converter(fixture())
        self.assertEqual(r["scale_input_field_offsets"], [88, 90])
        self.assertEqual(r["scale_identity_sentinel"], 256)
        self.assertTrue(r["identity_in_q8"])

    def test_result_sign_extension_in_rts_delay_slot(self):
        self.assertTrue(summarize_converter(fixture())[
            "return_sign_extension_in_RTS_delay_slot"])

    def test_signed_multiplier_opcode_required(self):
        self.assertIsNone(inspect_converter(fixture(broken_converter=0), ENTRY))

    def test_sts_macl_required(self):
        self.assertIsNone(inspect_converter(fixture(broken_converter=1), ENTRY))

    def test_shlr8_required(self):
        self.assertIsNone(inspect_converter(fixture(broken_converter=2), ENTRY))

    def test_rts_required(self):
        self.assertIsNone(inspect_converter(fixture(broken_converter=3), ENTRY))

    def test_exts_word_in_delay_slot_required(self):
        self.assertIsNone(inspect_converter(fixture(broken_converter=4), ENTRY))

    def test_out_of_range_converter_pointer(self):
        self.assertIsNone(inspect_converter(fixture(wrong_pointer=True), ENTRY))

    def test_register_specific_literal_load(self):
        self.assertIsNone(inspect_converter(fixture(wrong_r13_load=True), ENTRY))

    def test_signed_scale_load_required(self):
        self.assertIsNone(inspect_converter(fixture(bad_scale_first=True), ENTRY))

    def test_move_scale_to_r5_required(self):
        self.assertIsNone(inspect_converter(fixture(bad_scale_second=True), ENTRY))

    def test_all_conversion_call_sites_required(self):
        self.assertIsNone(inspect_converter(fixture(bad_first_call=True), ENTRY))
        self.assertIsNone(inspect_converter(fixture(bad_second_call=True), ENTRY))

    def test_stage28_conditions_required(self):
        self.assertIsNone(inspect_converter(fixture(bad_stage28_guard=True), ENTRY))

    def test_detached_helper_not_reported(self):
        self.assertEqual(summarize_converter(fixture(detached=True))[
            "helpers_with_resolved_q8_converter"], 0)

    def test_literal_pc_relative_alignment(self):
        target, ptr = movl_pc_literal(fixture(), ENTRY + 0x90)
        self.assertEqual(target, ENTRY + 0x1DC)
        self.assertEqual(ptr, CODE_LOAD_BASE + 0x6C)
        self.assertIsNone(movl_pc_literal(fixture(), ENTRY + 0x91))

    def test_sign16_wrapping(self):
        self.assertEqual(signed16(0xFFFF), -1)
        self.assertEqual(signed16(0x10000 + 123), 123)
        self.assertEqual(signed16(-32768), -32768)

    def test_q8_identity(self):
        for value in (-32768, -125, -1, 0, 1, 32767):
            self.assertEqual(model_signed_q8_mul(value, 256), value)

    def test_q8_fractional_negative_rounding(self):
        self.assertEqual(model_signed_q8_mul(125, 128), 62)
        self.assertEqual(model_signed_q8_mul(-125, 128), -63)
        self.assertEqual(model_signed_q8_mul(-1, 1), -1)

    def test_q8_register_width_semantics(self):
        self.assertEqual(model_signed_q8_mul(0x10000 + 25, 256), 25)
        self.assertEqual(model_signed_q8_mul(-32768, -32768), 0)

    def test_report_contains_no_original_program_offsets(self):
        r = summarize_converter(fixture())
        for forbidden in ("helper_entry", "converter_offset", "raw_bytes", "literal_slot"):
            self.assertNotIn(forbidden, r)

    def test_empty_input(self):
        self.assertEqual(summarize_converter(b"")[
            "helpers_with_resolved_q8_converter"], 0)


if __name__ == "__main__":
    unittest.main()
