import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage78_writer_entry_and_alias_audit import (
    audit_writer_callers,
    scan_literal_alias_writes,
)

SOURCE_GLOBAL = 0x0609BA7C
ENTRY = 0x100


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def literal_load(data, pos, register, literal_pos, value):
    base = (pos + 4) & ~3
    displacement = literal_pos - base
    assert displacement >= 0 and displacement % 4 == 0
    assert displacement // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | displacement // 4)
    put32(data, literal_pos, value)


def caller_fixture():
    data = bytearray(0x300)
    literal_load(data, 0x20, 1, 0x180, CODE_LOAD_ADDRESS + ENTRY)
    put16(data, 0x22, 0x410B)
    put16(data, 0x24, 0x0009)
    literal_load(data, 0x60, 2, 0x184, CODE_LOAD_ADDRESS + ENTRY)
    put16(data, 0x62, 0x420B)
    put16(data, 0x64, 0x0009)
    put16(data, 0x7A, 0x000B)  # RTS barrier before nearby gate
    return data


def alias_fixture(initial=SOURCE_GLOBAL):
    data = bytearray(0x200)
    literal_load(data, 0x20, 2, 0x100, initial)
    put16(data, 0x22, 0x2231)  # MOV.W R3,@R2
    return data


class Stage78WriterCallersTests(unittest.TestCase):
    def test_two_literal_backed_calls_but_no_direct_edges(self):
        result = audit_writer_callers(caller_fixture(), ENTRY, 0x80)
        self.assertEqual(result["writer_routine_literal_references"], 2)
        self.assertEqual(result["literal_backed_jsr_callsites"], 2)
        self.assertEqual(result["literal_backed_jsr_nop_delay_slots"], 2)
        self.assertEqual(result["direct_bsr_to_writer_entry_candidates"], 0)
        self.assertTrue(result["nearby_callsite_before_submit_gate"])
        self.assertTrue(result["nearby_callsite_separated_from_gate_by_rts"])
        self.assertFalse(result["runtime_execution_order_proven"])

    def test_corrupted_jsr_is_not_counted(self):
        data = caller_fixture()
        put16(data, 0x62, 0x0009)
        result = audit_writer_callers(data, ENTRY, 0x80)
        self.assertEqual(result["literal_backed_jsr_callsites"], 1)

    def test_direct_bsr_is_reported_separately(self):
        data = caller_fixture()
        put16(data, 0x40, 0xB05E)  # BSR at 0x40 to 0x100
        result = audit_writer_callers(data, ENTRY, None)
        self.assertEqual(result["direct_bsr_to_writer_entry_candidates"], 1)
        self.assertFalse(result["alternative_entry_points_excluded"])

    def test_bounded_additive_alias_detected(self):
        data = alias_fixture(SOURCE_GLOBAL - 4)
        put16(data, 0x22, 0x7204)  # ADD #4,R2
        put16(data, 0x24, 0x2231)
        result = scan_literal_alias_writes(data, SOURCE_GLOBAL)
        self.assertEqual(result["bounded_word_store_candidates"], 1)
        self.assertEqual(result["additive_alias_word_store_candidates"], 1)

    def test_branch_delay_slot_store_is_counted(self):
        data = alias_fixture()
        put16(data, 0x22, 0xA000)  # BRA with delay-slot store
        put16(data, 0x24, 0x2231)
        result = scan_literal_alias_writes(data, SOURCE_GLOBAL)
        self.assertEqual(result["bounded_word_store_candidates"], 1)
        self.assertEqual(result["additive_alias_word_store_candidates"], 0)

    def test_branch_skips_non_delay_store(self):
        data = alias_fixture()
        put16(data, 0x22, 0xA000)
        put16(data, 0x24, 0x0009)
        put16(data, 0x26, 0x2231)
        result = scan_literal_alias_writes(data, SOURCE_GLOBAL)
        self.assertEqual(result["bounded_word_store_candidates"], 0)

    def test_pointer_overwrite_breaks_alias(self):
        data = alias_fixture()
        put16(data, 0x22, 0xE200)
        put16(data, 0x24, 0x2231)
        result = scan_literal_alias_writes(data, SOURCE_GLOBAL)
        self.assertEqual(result["bounded_word_store_candidates"], 0)

    def test_unresolved_entry_fails_closed(self):
        result = audit_writer_callers(caller_fixture(), None, 0x80)
        self.assertEqual(result["literal_backed_jsr_callsites"], 0)
        self.assertFalse(result["runtime_execution_order_proven"])

    def test_aggregate_output_redacts_addresses(self):
        result = {
            **audit_writer_callers(caller_fixture(), ENTRY, 0x80),
            **scan_literal_alias_writes(alias_fixture(), SOURCE_GLOBAL),
        }
        rendered = json.dumps(result)
        for value in (SOURCE_GLOBAL, CODE_LOAD_ADDRESS + ENTRY):
            self.assertNotIn(hex(value), rendered)
        self.assertFalse(result["global_writer_census_exhaustive"])


if __name__ == "__main__":
    unittest.main()
