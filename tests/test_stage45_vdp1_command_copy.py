"""Synthetic-only Stage45 SH-2 VRAM writer and indirect JSR tests."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage45_vdp1_command_copy import (
    COMMAND_BYTES, VRAM_BASE, SETUP, UNROLLED_COPY, LOOP,
    bf_destination, match_vdp1_writer, find_vdp1_writers,
    find_indirect_writer_callers, summarize,
)

LOAD=0x80
ENTRY=LOAD-4
CALLER=0x140


def put(blob,pos,code):
    blob[pos:pos+2]=code.to_bytes(2,'big')


def fixture(mutation=None, with_caller=True, with_writer=True):
    blob=bytearray(0x300)
    if with_writer:
        for off,word in {**SETUP,**UNROLLED_COPY,**LOOP}.items():
            put(blob, LOAD+off, word)
        put(blob,LOAD,0xD71F)
        put(blob,LOAD+56,0x8BEA)
        put(blob,LOAD+62,0x8BE0)
        blob[0x100:0x104]=VRAM_BASE.to_bytes(4,'big')
    if with_caller:
        put(blob,CALLER,0xD20F)
        put(blob,CALLER+2,0x2F42)
        put(blob,CALLER+4,0x420B)
        put(blob,CALLER+6,0x0009)
        blob[0x180:0x184]=(0x06004000+ENTRY).to_bytes(4,'big')
    if mutation:
        put(blob,*mutation)
    return bytes(blob)


class Stage45WriterTests(unittest.TestCase):
    def report(self,**kwargs):
        return summarize(fixture(**kwargs))

    def test_exact_one_writer(self):
        self.assertEqual(self.report()['exact_command_vram_copy_writers'],1)

    def test_indirect_jsr_one_caller(self):
        self.assertEqual(self.report()['pc_literal_resolved_jsr_callers_to_copy_writers'],1)

    def test_vram_base_load_count(self):
        self.assertEqual(self.report()['vdp1_base_address_literal_loads'],1)

    def test_eight_longword_stores(self):
        self.assertEqual(self.report()['matched_writers_have_8_longword_stores'],1)

    def test_32_byte_command(self):
        self.assertEqual(self.report()['bytes_per_unrolled_copy'],32)

    def test_index_times_eight(self):
        self.assertEqual(self.report()['command_address_offset_multiplier'],8)

    def test_unsigned_index(self):
        self.assertTrue(self.report()['destination_index_from_unsigned_word'])

    def test_record_contains_source_and_count(self):
        self.assertTrue(self.report()['source_address_from_input_record'])
        self.assertTrue(self.report()['inner_count_from_input_record_word'])

    def test_outer_count_is_caller_r5(self):
        self.assertTrue(self.report()['outer_count_from_caller_r5'])

    def test_branches_both_verified(self):
        self.assertTrue(self.report()['verified_inner_and_outer_branch_targets'])

    def test_caller_saves_r4(self):
        self.assertEqual(self.report()['matched_callers_save_r4_before_indirect_jsr'],1)

    def test_exact_writer_location_private(self):
        self.assertEqual(find_vdp1_writers(fixture())[0]['entry'],ENTRY)

    def test_jsr_location_private(self):
        self.assertEqual(find_indirect_writer_callers(fixture(),ENTRY)[0]['jsr'],CALLER+4)

    def test_branch_sign_extension(self):
        self.assertEqual(bf_destination(0x100,0x8BFE),0x100)
        self.assertIsNone(bf_destination(0x100,0x89FE))

    def test_no_writer(self):
        self.assertEqual(self.report(with_writer=False)['exact_command_vram_copy_writers'],0)

    def test_no_caller(self):
        self.assertEqual(self.report(with_caller=False)['pc_literal_resolved_jsr_callers_to_copy_writers'],0)

    def test_wrong_vram_literal(self):
        self.assertEqual(self.report(mutation=(0x100,0x25D0))['exact_command_vram_copy_writers'],0)

    def test_wrong_literal_register(self):
        self.assertEqual(self.report(mutation=(LOAD,0xD61F))['exact_command_vram_copy_writers'],0)

    def test_wrong_command_index_read(self):
        self.assertEqual(self.report(mutation=(LOAD+4,0x6144))['exact_command_vram_copy_writers'],0)

    def test_missing_unsigned_extend(self):
        self.assertEqual(self.report(mutation=(LOAD+6,0x611C))['exact_command_vram_copy_writers'],0)

    def test_missing_shift_by_two(self):
        self.assertEqual(self.report(mutation=(LOAD+8,0x4100))['exact_command_vram_copy_writers'],0)

    def test_missing_shift_by_one(self):
        self.assertEqual(self.report(mutation=(LOAD+10,0x4108))['exact_command_vram_copy_writers'],0)

    def test_wrong_base_register_add(self):
        self.assertEqual(self.report(mutation=(LOAD+12,0x316C))['exact_command_vram_copy_writers'],0)

    def test_wrong_first_store(self):
        self.assertEqual(self.report(mutation=(LOAD+20,0x2101))['exact_command_vram_copy_writers'],0)

    def test_each_longword_store_required(self):
        for offset in (20,22,28,30,36,38,44,46):
            with self.subTest(offset=offset):
                self.assertIsNone(match_vdp1_writer(
                    fixture(mutation=(LOAD+offset,0x0009)),LOAD))

    def test_missing_source_increment(self):
        self.assertEqual(self.report(mutation=(LOAD+48,0x7324))['exact_command_vram_copy_writers'],0)

    def test_wrong_inner_count_decrement(self):
        self.assertEqual(self.report(mutation=(LOAD+50,0x72FE))['exact_command_vram_copy_writers'],0)

    def test_wrong_destination_increment(self):
        self.assertEqual(self.report(mutation=(LOAD+52,0x7124))['exact_command_vram_copy_writers'],0)

    def test_inner_loop_target_required(self):
        self.assertEqual(self.report(mutation=(LOAD+56,0x8BE9))['exact_command_vram_copy_writers'],0)

    def test_outer_loop_target_required(self):
        self.assertEqual(self.report(mutation=(LOAD+62,0x8BDF))['exact_command_vram_copy_writers'],0)

    def test_jsr_register_required(self):
        self.assertEqual(self.report(mutation=(CALLER+4,0x430B))['pc_literal_resolved_jsr_callers_to_copy_writers'],0)

    def test_jsr_stack_save_required(self):
        self.assertEqual(self.report(mutation=(CALLER+2,0x2F32))['pc_literal_resolved_jsr_callers_to_copy_writers'],0)

    def test_jsr_delay_slot_required(self):
        self.assertEqual(self.report(mutation=(CALLER+6,0x6E43))['pc_literal_resolved_jsr_callers_to_copy_writers'],0)

    def test_wrong_caller_literal(self):
        self.assertEqual(self.report(mutation=(0x180,0xFFFF))['pc_literal_resolved_jsr_callers_to_copy_writers'],0)

    def test_empty_data(self):
        self.assertEqual(summarize(b'')['exact_command_vram_copy_writers'],0)

    def test_odd_writer_position_rejected(self):
        self.assertIsNone(match_vdp1_writer(fixture(),LOAD+1))

    def test_no_original_program_positions_in_summary(self):
        for key in ('entry','load','jsr','position','pc','file_offset','raw_bytes'):
            self.assertNotIn(key,self.report())

    def test_no_runtime_claim(self):
        r=self.report()
        self.assertFalse(r['executed_during_actual_gameplay'])
        self.assertFalse(r['copy_invoked_by_function_39_verified'])
        self.assertFalse(r['specific_vdp1_commands_captured'])


if __name__=='__main__':
    unittest.main()
