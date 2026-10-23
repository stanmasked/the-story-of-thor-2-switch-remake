import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage87_set_loader_callsite_audit import (
    SET_TABLE_NAMES,
    find_contiguous_set_table,
    summarize_main_set_loader,
    summarize_main_th2_low_load,
    summarize_low_set07,
)


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


def filename_table(names=SET_TABLE_NAMES):
    return b"".join(name + b"\x00" for name in names)


class Stage87SetLoaderCallsiteTests(unittest.TestCase):
    def test_contiguous_seven_name_table_is_found(self):
        data = b"\x00" * 32 + filename_table() + b"\x00" * 32
        self.assertEqual(find_contiguous_set_table(data), 32)

    def test_incomplete_set_table_is_not_accepted(self):
        data = b"\x00" * 32 + filename_table(SET_TABLE_NAMES[:6]) + b"\x00" * 32
        self.assertIsNone(find_contiguous_set_table(data))

    def test_non_ten_byte_stride_is_not_accepted(self):
        names = list(SET_TABLE_NAMES)
        data = b"\x00" * 32 + names[0] + b"\x00" + b"X" + filename_table(names[1:]) + b"\x00" * 32
        self.assertIsNone(find_contiguous_set_table(data))

    def test_literal_backed_index10_consumer_is_recognized(self):
        data = bytearray(0x400)
        table_pos = 0x180
        data[table_pos:table_pos + len(filename_table())] = filename_table()
        put_literal_load(data, 0x10, 1, 0x100, CODE_LOAD_ADDRESS + table_pos)
        for delta, op in {2: 0x6343, 4: 0x4408, 6: 0x343C, 10: 0x4400, 12: 0x644E, 14: 0x430B, 16: 0x341C}.items():
            put16(data, 0x10 + delta, op)
        put_literal_load(data, 0x18, 3, 0x104, CODE_LOAD_ADDRESS + 0x300)
        result = summarize_main_set_loader(bytes(data))
        self.assertTrue(result["set00_to_set06_contiguous_name_table"])
        self.assertEqual(result["literal_backed_table_reference_count"], 1)
        self.assertEqual(result["index10_filename_argument_call_candidates"], 1)
        self.assertEqual(result["candidate_call_targets_inside_main_image"], 1)

    def test_wrong_register_for_table_pointer_is_not_counted(self):
        data = bytearray(0x400)
        table_pos = 0x180
        data[table_pos:table_pos + len(filename_table())] = filename_table()
        put_literal_load(data, 0x10, 2, 0x100, CODE_LOAD_ADDRESS + table_pos)
        for delta, op in {2: 0x6343, 4: 0x4408, 6: 0x343C, 10: 0x4400, 12: 0x644E, 14: 0x430B, 16: 0x341C}.items():
            put16(data, 0x10 + delta, op)
        put_literal_load(data, 0x18, 3, 0x104, CODE_LOAD_ADDRESS + 0x300)
        result = summarize_main_set_loader(bytes(data))
        self.assertEqual(result["literal_backed_table_reference_count"], 0)
        self.assertFalse(result["resource_loader_candidate_found"])

    def test_wrong_stride_sequence_is_rejected(self):
        data = bytearray(0x400)
        table_pos = 0x180
        data[table_pos:table_pos + len(filename_table())] = filename_table()
        put_literal_load(data, 0x10, 1, 0x100, CODE_LOAD_ADDRESS + table_pos)
        for delta, op in {2: 0x6343, 4: 0x4408, 6: 0x343C, 10: 0x4408, 12: 0x644E, 14: 0x430B, 16: 0x341C}.items():
            put16(data, 0x10 + delta, op)
        put_literal_load(data, 0x18, 3, 0x104, CODE_LOAD_ADDRESS + 0x300)
        result = summarize_main_set_loader(bytes(data))
        self.assertEqual(result["index10_filename_argument_call_candidates"], 0)

    def test_indirect_call_target_must_be_literal_loaded_into_r3(self):
        data = bytearray(0x400)
        table_pos = 0x180
        data[table_pos:table_pos + len(filename_table())] = filename_table()
        put_literal_load(data, 0x10, 1, 0x100, CODE_LOAD_ADDRESS + table_pos)
        for delta, op in {2: 0x6343, 4: 0x4408, 6: 0x343C, 10: 0x4400, 12: 0x644E, 14: 0x430B, 16: 0x341C}.items():
            put16(data, 0x10 + delta, op)
        put_literal_load(data, 0x18, 2, 0x104, CODE_LOAD_ADDRESS + 0x300)
        result = summarize_main_set_loader(bytes(data))
        self.assertEqual(result["index10_filename_argument_call_candidates"], 0)

    def test_th2_low_name_uses_literal_backed_generic_loader_call(self):
        data = bytearray(0x400)
        name_pos = 0x200
        data[name_pos:name_pos + 8] = b"TH2.LOW\x00"
        put_literal_load(data, 0x10, 4, 0x100, CODE_LOAD_ADDRESS + name_pos)
        put_literal_load(data, 0x12, 3, 0x104, CODE_LOAD_ADDRESS + 0x300)
        put16(data, 0x14, 0x430B)
        put16(data, 0x16, 0x0009)
        result = summarize_main_th2_low_load(bytes(data))
        self.assertEqual(result["filename_occurrences"], 1)
        self.assertEqual(result["literal_backed_filename_load_call_candidates"], 1)
        self.assertEqual(result["candidate_call_targets_inside_main_image"], 1)
        self.assertFalse(result["runtime_file_load_confirmed"])

    def test_th2_low_name_call_rejects_non_nop_delay_slot(self):
        data = bytearray(0x400)
        name_pos = 0x200
        data[name_pos:name_pos + 8] = b"TH2.LOW\x00"
        put_literal_load(data, 0x10, 4, 0x100, CODE_LOAD_ADDRESS + name_pos)
        put_literal_load(data, 0x12, 3, 0x104, CODE_LOAD_ADDRESS + 0x300)
        put16(data, 0x14, 0x430B)
        put16(data, 0x16, 0xE400)
        result = summarize_main_th2_low_load(bytes(data))
        self.assertEqual(result["literal_backed_filename_load_call_candidates"], 0)

    def test_low_set07_is_not_assumed_to_have_known_load_address(self):
        result = summarize_low_set07(b"\x00" * 20 + b"SET07.BIN\x00")
        self.assertEqual(result["set07_name_occurrences"], 1)
        self.assertFalse(result["load_address_known"])
        self.assertEqual(result["direct_code_xref_status"], "unresolved_without_verified_load_address")
        self.assertFalse(result["overlay_execution_confirmed"])

    def test_low_resource_filename_cluster_is_recognized_conservatively(self):
        names = b"SET07.BIN\x00" + b"\x00" * 128 + b"ED.BIN\x00CHR.BIN\x00CPK0.BIN\x00CPK1.BIN\x00CPK2.BIN\x00"
        result = summarize_low_set07(names)
        self.assertTrue(result["nearby_resource_filename_cluster_found"])
        self.assertEqual(result["nearby_resource_filename_kinds"], 5)

    def test_output_schema_never_contains_offsets_or_addresses(self):
        data = bytearray(0x400)
        table_pos = 0x180
        data[table_pos:table_pos + len(filename_table())] = filename_table()
        put_literal_load(data, 0x10, 1, 0x100, CODE_LOAD_ADDRESS + table_pos)
        for delta, op in {2: 0x6343, 4: 0x4408, 6: 0x343C, 10: 0x4400, 12: 0x644E, 14: 0x430B, 16: 0x341C}.items():
            put16(data, 0x10 + delta, op)
        put_literal_load(data, 0x18, 3, 0x104, CODE_LOAD_ADDRESS + 0x300)
        import json
        rendered = json.dumps(summarize_main_set_loader(bytes(data)))
        self.assertNotIn("0x", rendered)
        self.assertNotIn("address", rendered)


if __name__ == "__main__":
    unittest.main()
