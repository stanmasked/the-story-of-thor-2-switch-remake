import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage87_set_filename_loader_context import (
    SET_NAMES,
    _call_target_from_recent_literal,
    _first_call_preserving_argument,
    summarize_low_set07,
    summarize_main_filename_table,
)

SLOT_A = 0x06000300


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | delta // 4)
    put32(data, literal_pos, value)


def generic_prologue(data, pos):
    put16(data, pos, 0x2FE6)
    put16(data, pos + 2, 0x0009)
    put16(data, pos + 4, 0x2FD6)
    put16(data, pos + 6, 0x2FC6)
    put16(data, pos + 8, 0x4F22)


def simple_prologue(data, pos):
    put16(data, pos, 0x2FE6)
    put16(data, pos + 2, 0x4F22)


def filename_fixture(gap_after=None):
    data = bytearray(0x300)
    generic_prologue(data, 0x10)
    generic_prologue(data, 0x100)
    simple_prologue(data, 0x80)
    cursor = 0x180
    offsets = []
    for index, name in enumerate(SET_NAMES[:7]):
        offsets.append(cursor)
        data[cursor:cursor + len(name)] = name
        cursor += len(name)
        data[cursor] = 0
        cursor += 1
        if gap_after == index:
            cursor += 1
    literal_load(data, 0x40, 1, 0x200, CODE_LOAD_ADDRESS + offsets[0])
    put16(data, 0x42, 0x6343)  # does not clobber R1
    literal_load(data, 0x44, 3, 0x204, CODE_LOAD_ADDRESS + 0x80)
    put16(data, 0x46, 0x0009)
    put16(data, 0x48, 0x430B)  # JSR @R3
    put16(data, 0x4A, 0x0009)
    return data, offsets


class Stage87SetFilenameLoaderContextTests(unittest.TestCase):
    def test_main_names_form_contiguous_table(self):
        data, _ = filename_fixture()
        result = summarize_main_filename_table(data)
        self.assertTrue(result["set00_to_set06_name_occurrences_each_once"])
        self.assertTrue(result["set00_to_set06_names_form_contiguous_ten_byte_table"])
        self.assertEqual(result["filename_table_entries"], 7)

    def test_only_first_name_needs_direct_literal_reference(self):
        data, _ = filename_fixture()
        result = summarize_main_filename_table(data)
        self.assertEqual(result["pc_literal_refs_to_first_filename"], 1)
        self.assertEqual(result["pc_literal_refs_to_later_filename_entries"], 0)

    def test_candidate_function_interval_is_found(self):
        data, _ = filename_fixture()
        result = summarize_main_filename_table(data)
        self.assertTrue(result["table_reference_has_candidate_function_interval"])
        self.assertEqual(result["candidate_function_jsr_like_sites"], 1)

    def test_filename_argument_is_preserved_to_call(self):
        data, offsets = filename_fixture()
        result = _first_call_preserving_argument(data, 0x40, 1)
        self.assertTrue(result["call_found_before_argument_register_is_clobbered"])
        self.assertTrue(result["argument_register_preserved_at_call"])
        self.assertTrue(result["call_target_resolved_from_nearby_pc_literal"])
        self.assertEqual(offsets[0], 0x180)

    def test_helper_target_must_not_be_clobbered_before_call(self):
        data, _ = filename_fixture()
        put16(data, 0x46, 0xE300)  # MOV #0,R3 destroys target register
        self.assertIsNone(_call_target_from_recent_literal(data, 0x48))

    def test_filename_argument_clobber_prevents_argument_claim(self):
        data, _ = filename_fixture()
        put16(data, 0x42, 0xE100)  # MOV #0,R1
        result = _first_call_preserving_argument(data, 0x40, 1)
        self.assertFalse(result["call_found_before_argument_register_is_clobbered"])
        self.assertFalse(result["argument_register_preserved_at_call"])

    def test_low_set07_string_without_pointer_is_not_resolved(self):
        data = bytearray(0x300)
        data[0x180:0x180 + len(b"SET07.BIN\x00")] = b"SET07.BIN\x00"
        result = summarize_low_set07(data)
        self.assertEqual(result["set07_name_occurrences"], 1)
        self.assertEqual(result["direct_pc_literal_refs_under_candidate_load_bases"], 0)
        self.assertEqual(result["raw_pointer_words_under_candidate_load_bases"], 0)
        self.assertFalse(result["low_module_load_base_resolved"])

    def test_low_set07_candidate_base_reference_is_detected(self):
        data = bytearray(0x300)
        offset = 0x180
        data[offset:offset + len(b"SET07.BIN\x00")] = b"SET07.BIN\x00"
        literal_load(data, 0x20, 2, 0x200, 0x06000000 + offset)
        result = summarize_low_set07(data)
        self.assertEqual(result["direct_pc_literal_refs_under_candidate_load_bases"], 1)
        self.assertEqual(result["raw_pointer_words_under_candidate_load_bases"], 1)

    def test_gap_breaks_contiguous_table_claim(self):
        data, _ = filename_fixture(gap_after=2)
        result = summarize_main_filename_table(data)
        self.assertFalse(result["set00_to_set06_names_form_contiguous_ten_byte_table"])

    def test_output_contains_no_addresses_or_offsets(self):
        data, _ = filename_fixture()
        result = summarize_main_filename_table(data)
        rendered = json.dumps(result)
        for value in ("0x180", "0x200", hex(CODE_LOAD_ADDRESS), hex(SLOT_A)):
            self.assertNotIn(value, rendered)
        self.assertFalse(result["loader_api_identity_confirmed"])
        self.assertFalse(result["filename_table_runtime_iteration_proven"])


if __name__ == "__main__":
    unittest.main()
