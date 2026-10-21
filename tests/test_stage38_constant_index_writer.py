"""Stage38 synthetic-only tests for local constant index and flag writes."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from test_stage36_dispatch_index_audit import fixture as base_fixture,put
from stage38_constant_index_writer import (
    candidate_store_pairs,adjacent_immediate_stores,exact_slot39_writer,summarize,
)

WRITER=0xCA0
ADJ_R14=0xCD0
ADJ_R4=0xCE0
OPS=(0xE326,0xDC09,0xE219,0xCB09,0x80E7,0xE07E,0x0E35)


def fixture(mutation=None,slot39=True,extra_adjacent=True):
    data=bytearray(base_fixture())
    if slot39:
        for i,opcode in enumerate(OPS):
            put(data,WRITER+i*2,opcode)
    if extra_adjacent:
        for start,seq in (
            (ADJ_R14,(0xE200,0xE07E,0x0E25)),
            (ADJ_R4,(0xE501,0xE07E,0x0455)),
        ):
            for i,opcode in enumerate(seq):
                put(data,start+i*2,opcode)
    if mutation:
        put(data,*mutation)
    return bytes(data)


class Stage38Tests(unittest.TestCase):
    def report(self,**kwargs):
        return summarize(fixture(**kwargs))

    def test_exact_writer_matched(self):
        self.assertEqual(self.report()["exact_local_constant_38_and_flag_update_writers"],1)

    def test_register_and_offsets(self):
        r=self.report()
        self.assertEqual((r["confirmed_local_straight_line_R3_value"],
                          r["verified_local_index_word_offset"],
                          r["verified_local_flag_byte_offset"]),(38,126,7))

    def test_no_runtime_alias_claim(self):
        self.assertFalse(self.report()["writer_and_dispatcher_runtime_object_identity_verified"])

    def test_short_table_index_not_38(self):
        self.assertFalse(self.report()["writer_constant_equals_base_table_selected_index"])

    def test_original_dispatch_patterns_unmodified(self):
        self.assertEqual(self.report()["linked_signed_dispatch_patterns"],2)

    def test_full_exact_signature(self):
        self.assertTrue(exact_slot39_writer(fixture(),WRITER+10))

    def test_absent_writer(self):
        self.assertEqual(self.report(slot39=False)["exact_local_constant_38_and_flag_update_writers"],0)

    def test_every_fixed_opcode_required(self):
        for index in (0,2,3,4,5,6):
            with self.subTest(index=index):
                self.assertFalse(exact_slot39_writer(
                    fixture(mutation=(WRITER+index*2,0x0009)),WRITER+10))

    def test_pc_literal_destination_r12_required(self):
        self.assertFalse(exact_slot39_writer(
            fixture(mutation=(WRITER+2,0xDD09)),WRITER+10))

    def test_pc_literal_displacement_free(self):
        self.assertTrue(exact_slot39_writer(
            fixture(mutation=(WRITER+2,0xDCFC)),WRITER+10))

    def test_different_constant_is_rejected(self):
        self.assertFalse(exact_slot39_writer(
            fixture(mutation=(WRITER,0xE325)),WRITER+10))

    def test_store_width_must_be_word(self):
        self.assertFalse(exact_slot39_writer(
            fixture(mutation=(WRITER+12,0x0E34)),WRITER+10))

    def test_raw_r14_pair_detected(self):
        self.assertIn(WRITER+10,[p["position"] for p in candidate_store_pairs(fixture(),14)])

    def test_raw_r4_pair_detected(self):
        self.assertIn(ADJ_R4+2,[p["position"] for p in candidate_store_pairs(fixture(),4)])

    def test_adjacent_zero_r14(self):
        self.assertTrue(any(p["position"]==ADJ_R14+2 and p["value"]==0
                            for p in adjacent_immediate_stores(fixture(),14)))

    def test_adjacent_one_r4(self):
        self.assertTrue(any(p["position"]==ADJ_R4+2 and p["value"]==1
                            for p in adjacent_immediate_stores(fixture(),4)))

    def test_seven_opcode_writer_not_counted_as_adjacent(self):
        self.assertFalse(any(p["position"]==WRITER+10
                             for p in adjacent_immediate_stores(fixture(),14)))

    def test_adjacent_signed_negative_immediate(self):
        vals=adjacent_immediate_stores(
            fixture(mutation=(ADJ_R14,0xE2FF)),14)
        self.assertTrue(any(p["position"]==ADJ_R14+2 and p["value"]==-1 for p in vals))

    def test_adjacent_immediate_must_exist(self):
        vals=adjacent_immediate_stores(
            fixture(mutation=(ADJ_R14,0x0009)),14)
        self.assertFalse(any(p["position"]==ADJ_R14+2 for p in vals))

    def test_adjacent_source_register_must_match(self):
        vals=adjacent_immediate_stores(
            fixture(mutation=(ADJ_R14,0xE300)),14)
        self.assertFalse(any(p["position"]==ADJ_R14+2 for p in vals))

    def test_store_base_register_must_match(self):
        vals=adjacent_immediate_stores(
            fixture(mutation=(ADJ_R14+4,0x0455)),14)
        self.assertFalse(any(p["position"]==ADJ_R14+2 for p in vals))

    def test_no_odd_positions(self):
        self.assertFalse(exact_slot39_writer(fixture(),WRITER+11))

    def test_short_buffer_rejected(self):
        self.assertFalse(exact_slot39_writer(b"\x00"*12,10))

    def test_negative_position_rejected(self):
        self.assertFalse(exact_slot39_writer(b"\x00"*100,-2))

    def test_invalid_base_register(self):
        with self.assertRaises(ValueError):
            candidate_store_pairs(b"\x00"*8,16)

    def test_empty_binary(self):
        self.assertEqual(summarize(b"")["exact_local_constant_38_and_flag_update_writers"],0)

    def test_no_original_positions_in_json(self):
        r=self.report()
        for key in ("position","file_offset","program_counter","raw_bytes",
                    "instruction_address","start","end"):
            self.assertNotIn(key,r)

    def test_intermediate_r3_clobber_fails(self):
        self.assertFalse(exact_slot39_writer(
            fixture(mutation=(WRITER+6,0xE304)),WRITER+10))

    def test_short_test_table_is_3_entries_in(self):
        self.assertEqual(self.report()["selected_function_slot_one_based"],3)


if __name__=="__main__":
    unittest.main()
