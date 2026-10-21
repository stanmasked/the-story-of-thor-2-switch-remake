"""Stage22 synthetic-only tests for narrowly recognized SP-relative stores."""
import unittest

from test_stage21_vdp1_stack_sources import stack_fixture, put16
from stage22_vdp1_stack_store_audit import (
    direct_stack_stores, find_stack_frame, saved_register_push_count,
    summarize_stack_store_audit, count_known_sp_adjustments,
)


def fixture(write_factor20=False, write_factor32=False, change_flag=False,
            remove_frame=False, mutate_sp=False, indirect_index=False):
    data = bytearray(b'\x00' * 0x100 + stack_fixture())
    # Seven saved registers and ADD #-88,R15 establish the stack-local frame.
    for index, register in enumerate((14, 13, 12, 11, 10, 9, 8)):
        put16(data, 0x20 + index * 2, 0x2F06 | (register << 4))
    if not remove_frame:
        put16(data, 0x30, 0x7FA8)

    # Two mutually possible writes to a flag in the local SP+80 field.
    put16(data, 0x48, 0xE051 if change_flag else 0xE050)
    put16(data, 0x4A, 0x0F44)
    put16(data, 0x4C, 0xE050)
    put16(data, 0x4E, 0x0F64)
    if write_factor20:
        put16(data, 0x58, 0xE014)
        put16(data, 0x5A, 0x0F44)
    if write_factor32:
        put16(data, 0x60, 0xE020)
        put16(data, 0x62, 0x0F44)
    if mutate_sp:
        put16(data, 0x70, 0x7F04)
    if indirect_index:
        put16(data, 0x7E, 0x0F44)  # R0 is not immediately initialized
    return bytes(data)


class Stage22StoreAuditTests(unittest.TestCase):
    def test_recognizes_88_byte_frame(self):
        report = summarize_stack_store_audit(fixture())
        self.assertEqual(report['chains_with_nearby_88_byte_local_frame_allocation'], 1)

    def test_counts_saved_registers(self):
        report = summarize_stack_store_audit(fixture())
        self.assertEqual(report['saved_register_push_counts_before_frame_allocation'], [7])

    def test_recognizes_two_direct_flag_stores(self):
        stores = summarize_stack_store_audit(fixture())['strict_direct_store_counts_by_stack_slot']
        self.assertEqual(stores, {'SP+20': 0, 'SP+32': 0, 'SP+80': 2})

    def test_detects_first_factor_store_when_added(self):
        stores = summarize_stack_store_audit(fixture(write_factor20=True))['strict_direct_store_counts_by_stack_slot']
        self.assertEqual(stores['SP+20'], 1)

    def test_detects_second_factor_store_when_added(self):
        stores = summarize_stack_store_audit(fixture(write_factor32=True))['strict_direct_store_counts_by_stack_slot']
        self.assertEqual(stores['SP+32'], 1)

    def test_flag_offset_mismatch_reduces_count(self):
        stores = summarize_stack_store_audit(fixture(change_flag=True))['strict_direct_store_counts_by_stack_slot']
        self.assertEqual(stores['SP+80'], 1)

    def test_unknown_immediate_index_not_counted(self):
        report = summarize_stack_store_audit(fixture(indirect_index=True))
        self.assertEqual(report['strict_direct_store_counts_by_stack_slot']['SP+20'], 0)

    def test_adjustment_is_recorded(self):
        self.assertEqual(summarize_stack_store_audit(fixture(mutate_sp=True))['recognized_sp_adjustments_inside_examined_frame'], 1)

    def test_missing_frame_reports_none(self):
        report = summarize_stack_store_audit(fixture(remove_frame=True))
        self.assertEqual(report['chains_with_nearby_88_byte_local_frame_allocation'], 0)

    def test_direct_longword_displacement_overlap(self):
        data = bytearray(fixture())
        put16(data, 0x88, 0x1F45)  # MOV.L R4,@(5,R15): bytes SP+20..+23
        report = summarize_stack_store_audit(bytes(data))
        self.assertEqual(report['strict_direct_store_counts_by_stack_slot']['SP+20'], 1)

    def test_adjacent_byte_load_required_for_indexed_store(self):
        data = bytes.fromhex('E0 14 0F 44 00 00 0F 44')
        self.assertEqual(direct_stack_stores(data, 0, len(data)), [(20, 1)])

    def test_no_raw_code_positions_in_report(self):
        report = summarize_stack_store_audit(fixture())
        for forbidden in ('code_offsets', 'block_start', 'raw_bytes', 'source_payload'):
            self.assertNotIn(forbidden, report)

    def test_empty_input(self):
        self.assertEqual(summarize_stack_store_audit(bytes(128))['matched_stage21_factor_load_chains'], 0)

    def test_direct_sp_adjustments_counted(self):
        data = bytes.fromhex('7F 04 2F E6 6A F6')
        self.assertEqual(count_known_sp_adjustments(data, 0, len(data)), 3)


if __name__ == '__main__':
    unittest.main()
