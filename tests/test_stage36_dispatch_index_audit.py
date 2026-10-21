"""Stage36: synthetic-only signed-word indexed dispatch tests, no game data."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage35_table_tail_link import fixture as stage35_fixture, put, TABLE
from stage36_dispatch_index_audit import (
    CODE_LOAD_BASE, signed16, index_slot, match_indexed_dispatch,
    scan_dispatches,
)

BASE = 0xB06
CELL = 0xB66


def fixture(corrupt=None, include_base=True, include_cell=True):
    data = bytearray(stage35_fixture())
    if include_base:
        for addr, op in (
            (BASE-10, 0xE07E), (BASE-8, 0x4F26),
            (BASE-6, 0x64E3), (BASE-4, 0x02ED),
            (BASE-2, 0x4208), (BASE, 0xD028),
            (BASE+2, 0x032E), (BASE+4, 0x432B),
            (BASE+6, 0x6EF6),
        ):
            put(data, addr, op)
        data[0xBA8:0xBAC] = (CODE_LOAD_BASE + TABLE).to_bytes(4, "big")
    if include_cell:
        for addr, op in (
            (CELL-12, 0x64E3), (CELL-10, 0xE07E),
            (CELL-8, 0x4F26), (CELL-6, 0x64E3),
            (CELL-4, 0x03ED), (CELL-2, 0x4308),
            (CELL, 0xD020), (CELL+2, 0x023E),
            (CELL+4, 0x6CF6), (CELL+6, 0x6DF6),
            (CELL+8, 0x422B), (CELL+10, 0x6EF6),
        ):
            put(data, addr, op)
        data[0xBE8:0xBEC] = (CODE_LOAD_BASE + TABLE + 8).to_bytes(4, "big")
    if corrupt:
        put(data, *corrupt)
    return bytes(data)


class Stage36DispatchTests(unittest.TestCase):
    def report(self, *args, **kwargs):
        return scan_dispatches(fixture(*args, **kwargs))

    def test_two_full_dispatches(self):
        self.assertEqual(self.report()["complete_dispatch_patterns"], 2)

    def test_base_and_selected_cell_counts(self):
        s = self.report()
        self.assertEqual(s["dispatches_using_table_start"], 1)
        self.assertEqual(s["dispatches_using_selected_cell"], 1)

    def test_shared_signed_word_field(self):
        s = self.report()
        self.assertEqual(s["index_source"], "signed16(memory[R14+126])")
        self.assertEqual(s["shared_signed_index_field_byte_offset"], 126)
        self.assertTrue(s["both_dispatches_read_index_from_saved_r14"])

    def test_stride_four(self):
        self.assertEqual(self.report()["table_pointer_stride_bytes"], 4)
        self.assertEqual(self.report()["index_shift_left_bits"], 2)

    def test_two_jmp_epilogues(self):
        self.assertEqual(self.report()["dispatch_epilogue_forms"], [
            "immediate_jmp_r14_delay", "r12_r13_then_jmp_r14_delay"
        ])

    def test_table_slot_bounds(self):
        self.assertEqual(self.report()["valid_index_ranges_as_mathematical_model"], {
            "table_start": [0, 5], "selected_function_cell": [-2, 3]
        })

    def test_slot_to_outer(self):
        self.assertEqual(self.report()["index_to_select_outer_function"], {
            "table_start": 2, "selected_function_cell": 0
        })

    def test_no_bounds_guard_claim(self):
        self.assertFalse(self.report()["local_index_bounds_guard_verified"])

    def test_base_without_cell(self):
        self.assertEqual(self.report(include_cell=False)["complete_dispatch_patterns"], 1)

    def test_cell_without_base(self):
        self.assertEqual(self.report(include_base=False)["complete_dispatch_patterns"], 1)

    def test_corrupt_base_index_source_register(self):
        self.assertEqual(self.report(corrupt=(BASE-4, 0x024D))["complete_dispatch_patterns"], 1)

    def test_corrupt_cell_index_source_register(self):
        self.assertEqual(self.report(corrupt=(CELL-4, 0x034D))["complete_dispatch_patterns"], 1)

    def test_corrupt_base_shift(self):
        self.assertEqual(self.report(corrupt=(BASE-2, 0x4200))["complete_dispatch_patterns"], 1)

    def test_corrupt_cell_shift(self):
        self.assertEqual(self.report(corrupt=(CELL-2, 0x4300))["complete_dispatch_patterns"], 1)

    def test_wrong_literal_pointer(self):
        self.assertEqual(self.report(corrupt=(0xBA8, 0))["dispatches_using_table_start"], 0)

    def test_wrong_cell_literal_pointer(self):
        self.assertEqual(self.report(corrupt=(0xBE8, 0))["dispatches_using_selected_cell"], 0)

    def test_base_wrong_indexed_memory_read(self):
        self.assertEqual(self.report(corrupt=(BASE+2, 0x032D))["complete_dispatch_patterns"], 1)

    def test_cell_wrong_indexed_memory_read(self):
        self.assertEqual(self.report(corrupt=(CELL+2, 0x023D))["complete_dispatch_patterns"], 1)

    def test_base_wrong_jmp_register(self):
        self.assertEqual(self.report(corrupt=(BASE+4, 0x422B))["complete_dispatch_patterns"], 1)

    def test_cell_wrong_jmp_register(self):
        self.assertEqual(self.report(corrupt=(CELL+8, 0x432B))["complete_dispatch_patterns"], 1)

    def test_base_jmp_delay_slot_required(self):
        self.assertEqual(self.report(corrupt=(BASE+6, 0x0009))["complete_dispatch_patterns"], 1)

    def test_cell_jmp_delay_slot_required(self):
        self.assertEqual(self.report(corrupt=(CELL+10, 0x0009))["complete_dispatch_patterns"], 1)

    def test_cell_intermediate_pop_required(self):
        self.assertEqual(self.report(corrupt=(CELL+6, 0x0009))["complete_dispatch_patterns"], 1)

    def test_load_register_must_be_r0(self):
        self.assertEqual(self.report(corrupt=(CELL, 0xD120))["complete_dispatch_patterns"], 1)

    def test_signed_word_arithmetic(self):
        self.assertEqual(signed16(0xFFFF), -1)
        self.assertEqual(signed16(0x10000 + 29), 29)
        self.assertEqual(signed16(0x8000), -32768)

    def test_relative_index_slot_math(self):
        self.assertEqual(index_slot(-2, 2, 6), 0)
        self.assertEqual(index_slot(0, 2, 6), 2)
        self.assertEqual(index_slot(3, 2, 6), 5)
        self.assertIsNone(index_slot(-3, 2, 6))
        self.assertIsNone(index_slot(4, 2, 6))

    def test_absolute_index_slot_math(self):
        self.assertEqual(index_slot(0, 0, 68), 0)
        self.assertEqual(index_slot(38, 0, 68), 38)
        self.assertEqual(index_slot(67, 0, 68), 67)
        self.assertIsNone(index_slot(-1, 0, 68))
        self.assertIsNone(index_slot(68, 0, 68))

    def test_table_shape_validation(self):
        with self.assertRaises(ValueError):
            index_slot(0, 0, 0)
        with self.assertRaises(ValueError):
            index_slot(0, 6, 6)

    def test_empty_data(self):
        self.assertEqual(scan_dispatches(b"")["complete_dispatch_patterns"], 0)

    def test_metadata_no_raw_positions(self):
        result = self.report()
        for key in ("literal_pos", "table_start", "entry_cell",
                    "program_offset", "instruction_position",
                    "raw_bytes", "iso_file_offset"):
            self.assertNotIn(key, result)


if __name__ == "__main__":
    unittest.main()
