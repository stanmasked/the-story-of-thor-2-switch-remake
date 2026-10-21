"""Stage41 synthetic-only SH-2 fixtures; no original Saturn executable bytes."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage40_pool_clone_audit import fixture as stage40_fixture, put
from stage41_pool_readers import (
    pool_base, checked_index_read_sites, find_pool_index_readers,
    check_unmarked_free_slot_finder, find_unmarked_finders,
    summarize_pool_readers,
)

BASE = 0x06080000
READERS = (0x1600, 0x1700, 0x1800, 0x1900)
MARKERS = (46, 84, 52, 52)
INDICES = (4, 36, 36, 21)
FREE = 0x1B00


def fixture(mutation=None, with_readers=True, with_free=True, pool=True):
    data = bytearray(stage40_fixture(with_pool=pool))
    data.extend(bytes(max(0, 0x2000 - len(data))))
    if with_readers:
        for pos, marker, index in zip(READERS, MARKERS, INDICES):
            for offset, word in (
                (0, 0xD41F), (2, 0x6041), (4, 0x8800 | marker),
                (6, 0x8B05), (8, 0xE07E), (10, 0x004D),
                (12, 0x8800 | index), (14, 0x8B02),
                (16, 0x9307), (18, 0x343C),
            ):
                put(data, pos + offset, word)
            put(data, pos + 0x22, 276)
            data[pos + 0x80:pos + 0x84] = BASE.to_bytes(4, "big")
    if with_free:
        words = (
            (0, 0xD410), (2, 0xE500), (4, 0xE62B),
            (6, 0x6341), (8, 0x2338), (10, 0x8B01),
            (12, 0x000B), (14, 0x6043), (16, 0x9309),
            (18, 0x7501), (20, 0x3563), (22, 0x8FF6),
            (24, 0x343C), (26, 0xE000), (28, 0x000B),
            (30, 0x0009),
        )
        for offset, word in words:
            put(data, FREE + offset, word)
        put(data, FREE + 0x26, 276)
        data[FREE + 0x44:FREE + 0x48] = BASE.to_bytes(4, "big")
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage41Tests(unittest.TestCase):
    def report(self, **kwargs):
        return summarize_pool_readers(fixture(**kwargs))

    def test_stage40_pool_provenance(self):
        self.assertEqual(pool_base(fixture()), (BASE, 276, 43))

    def test_slot_capacity(self):
        self.assertEqual(self.report()["pool_slot_capacity"], 43)

    def test_record_stride(self):
        self.assertEqual(self.report()["pool_stride_bytes"], 276)

    def test_four_reader_groups(self):
        self.assertEqual(self.report()["distinct_pool_based_index_reader_groups"], 4)

    def test_reader_sites_count(self):
        self.assertEqual(self.report()["index_word_read_and_immediate_compare_sites"], 4)

    def test_markers(self):
        self.assertEqual(self.report()["first_word_marker_values_examined"],
                         [46, 52, 52, 84])

    def test_index_values(self):
        self.assertEqual(self.report()["index_values_compared_in_matched_readers"],
                         [4, 21, 36])

    def test_value_counts(self):
        self.assertEqual(self.report()["comparison_counts_by_index"],
                         {"4": 1, "21": 1, "36": 2})

    def test_no_38_value_in_matched_groups(self):
        self.assertEqual(self.report()["matched_reader_comparisons_for_cloned_index_38"], 0)

    def test_index_field_offset(self):
        self.assertEqual(self.report()["pool_index_field_offset_bytes"], 126)

    def test_synthetic_movl_counts(self):
        result = self.report()
        self.assertGreaterEqual(result["pool_pc_relative_movl_loads"], 5)
        self.assertEqual(result["pool_pc_relative_movl_into_r4"], 5)

    def test_unmarked_scan(self):
        self.assertEqual(self.report()["independent_unmarked_free_slot_scanners"], 1)

    def test_unmarked_scan_same_capacity(self):
        self.assertEqual(self.report()["independent_scan_capacity"], 43)

    def test_unmarked_scan_same_stride(self):
        self.assertEqual(self.report()["independent_scan_stride_bytes"], 276)

    def test_unmarked_scan_returns_pointer(self):
        self.assertTrue(self.report()["independent_free_scan_returns_slot_without_marking"])

    def test_no_runtime_dispatch_alias(self):
        self.assertFalse(self.report()["cloned_index_38_consumed_by_68_entry_dispatcher_proven"])

    def test_pool_origin_needed(self):
        self.assertFalse(self.report(pool=False)["verified_cloned_slot_pool"])

    def test_first_word_tag_required(self):
        self.assertEqual(self.report(mutation=(READERS[0]+2,0x6040))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_marker_comparison_required(self):
        self.assertEqual(self.report(mutation=(READERS[1]+4,0x0009))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_marker_branch_required(self):
        self.assertEqual(self.report(mutation=(READERS[2]+6,0x0009))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_index_width_required(self):
        self.assertEqual(self.report(mutation=(READERS[3]+10,0x004C))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_index_displacement_required(self):
        self.assertEqual(self.report(mutation=(READERS[1]+8,0xE07D))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_missing_index_comparison(self):
        self.assertEqual(self.report(mutation=(READERS[0]+12,0x0009))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_stride_word_must_equal_276(self):
        self.assertEqual(self.report(mutation=(READERS[2]+0x22,280))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_stride_add_required(self):
        self.assertEqual(self.report(mutation=(READERS[3]+18,0x3438))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_wrong_pool_pointer(self):
        self.assertEqual(self.report(mutation=(READERS[0]+0x80,0x0609))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_wrong_pool_loading_register(self):
        self.assertEqual(self.report(mutation=(READERS[1],0xD51F))
                         ["distinct_pool_based_index_reader_groups"], 3)

    def test_unmarked_scan_checks_first_word(self):
        self.assertEqual(self.report(mutation=(FREE+6,0x6340))
                         ["independent_unmarked_free_slot_scanners"], 0)

    def test_unmarked_scan_capacity_43(self):
        self.assertEqual(self.report(mutation=(FREE+4,0xE62C))
                         ["independent_unmarked_free_slot_scanners"], 0)

    def test_unmarked_scan_stride_276(self):
        self.assertEqual(self.report(mutation=(FREE+0x26,280))
                         ["independent_unmarked_free_slot_scanners"], 0)

    def test_unmarked_scan_branch_slot(self):
        self.assertEqual(self.report(mutation=(FREE+24,0x0009))
                         ["independent_unmarked_free_slot_scanners"], 0)

    def test_unmarked_scan_base_reference(self):
        self.assertEqual(self.report(mutation=(FREE+0x44,0x0609))
                         ["independent_unmarked_free_slot_scanners"], 0)

    def test_readers_without_unmarked_scan(self):
        result = self.report(with_free=False)
        self.assertEqual(result["independent_unmarked_free_slot_scanners"], 0)
        self.assertEqual(result["distinct_pool_based_index_reader_groups"], 4)

    def test_unmarked_scan_without_readers(self):
        result = self.report(with_readers=False)
        self.assertEqual(result["distinct_pool_based_index_reader_groups"], 0)
        self.assertEqual(result["independent_unmarked_free_slot_scanners"], 1)

    def test_index_38_is_counted_when_present(self):
        result = self.report(mutation=(READERS[3]+12,0x8826))
        self.assertEqual(result["matched_reader_comparisons_for_cloned_index_38"], 1)
        self.assertEqual(result["index_values_compared_in_matched_readers"], [4,36,38])

    def test_empty_input(self):
        self.assertFalse(summarize_pool_readers(b"")["verified_cloned_slot_pool"])

    def test_index_read_bounds(self):
        self.assertEqual(checked_index_read_sites(b"\x00"*30, 10), [])

    def test_unmarked_finder_out_of_bounds(self):
        self.assertFalse(check_unmarked_free_slot_finder(b"", 0, BASE))

    def test_no_proprietary_offsets_in_output(self):
        result = self.report()
        for key in ("loader", "position", "program_offset", "pool_address",
                    "literal_pos", "raw_bytes", "game_program_locations"):
            self.assertNotIn(key, result)


if __name__ == "__main__":
    unittest.main()
