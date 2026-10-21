"""Stage30: invented synthetic SH-2 fixtures only, no game executable bytes."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage30_field_consumer_audit import (
    field_read, find_consumer_groups, summarize_consumers, is_branch,
)


def put(data, pos, word):
    data[pos:pos + 2] = word.to_bytes(2, 'big')


def synthetic(mode='sum5', extended=False, corrupt=None):
    data = bytearray(0x180)
    regs = (14, 12, 13, 11, 10, 8) if mode == 'sum5' else (0, 0, 0, 0, 0, 0)
    for i, field in enumerate(range(31, 37 if extended else 35)):
        at = 0x20 + 8 * i
        put(data, at, 0xE000 | field)
        width = 0xD if field == 36 else 0xC
        put(data, at + 2, (regs[i] << 8) | 0x40 | width)
        if mode == 'sum5':
            put(data, at + 4, 0x300C | (regs[i] << 8) | (5 << 4))
        elif mode == 'stack6':
            put(data, at + 4, 0x306C)
            put(data, at + 6, 0x81F0 | (i + 1))
    if corrupt:
        pos, opcode = corrupt
        put(data, pos, opcode)
    return bytes(data)


class Stage30ConsumerTests(unittest.TestCase):
    def test_first_four_fields(self):
        d = synthetic()
        self.assertEqual(len(find_consumer_groups(d)), 1)
        self.assertEqual(summarize_consumers(d)['common_read_fields'], [31,32,33,34])

    def test_full_seven_byte_reader(self):
        s = summarize_consumers(synthetic(extended=True))
        self.assertEqual(s['extended_reader_fields'], list(range(31,38)))
        self.assertEqual(s['extended_final_field_width_bytes'], 2)

    def test_initial_field_read_register(self):
        read = field_read(synthetic(),0x20)
        self.assertEqual((read['field'],read['width'],read['dest']), (31,1,14))

    def test_last_field_is_word(self):
        read = field_read(synthetic(extended=True),0x20+8*5)
        self.assertEqual((read['field'],read['width']), (36,2))

    def test_first_mode_adds_R5(self):
        s = summarize_consumers(synthetic())
        self.assertEqual(s['groups_adding_r5_to_all_four_results'],1)
        self.assertEqual(s['groups_adding_r6_and_storing_four_stack_words'],0)

    def test_second_mode_adds_R6_then_stores_stack(self):
        s = summarize_consumers(synthetic('stack6'))
        self.assertEqual(s['groups_adding_r5_to_all_four_results'],0)
        self.assertEqual(s['groups_adding_r6_and_storing_four_stack_words'],1)

    def test_negative_missing_first_field(self):
        self.assertEqual(find_consumer_groups(synthetic(corrupt=(0x20,0xE01E))),[])

    def test_negative_missing_last_of_four(self):
        self.assertEqual(find_consumer_groups(synthetic(corrupt=(0x20+8*3,0xE027))),[])

    def test_negative_invalid_byte_load_register_base(self):
        self.assertEqual(find_consumer_groups(synthetic(corrupt=(0x22,0x0E5C))),[])

    def test_negative_field_32_read_from_different_base(self):
        self.assertEqual(find_consumer_groups(synthetic(corrupt=(0x2A,0x0C5C))),[])

    def test_negative_word_in_byte_field(self):
        self.assertEqual(find_consumer_groups(synthetic(corrupt=(0x2A,0x0C4D))),[])

    def test_negative_byte_in_word_field(self):
        s=summarize_consumers(synthetic(extended=True, corrupt=(0x20+5*8+2, 0x084C)))
        self.assertEqual(s['candidate_four_field_consumer_groups'],1)
        self.assertEqual(s['groups_reading_all_seven_bytes'],0)

    def test_known_branch_blocks_candidate(self):
        self.assertEqual(find_consumer_groups(synthetic(corrupt=(0x20+8*2-2,0xA000))),[])

    def test_negative_incorrect_r5_add(self):
        s=summarize_consumers(synthetic(corrupt=(0x20+8*1+4,0x3C6C)))
        self.assertEqual(s['candidate_four_field_consumer_groups'],1)
        self.assertEqual(s['groups_adding_r5_to_all_four_results'],0)

    def test_negative_incorrect_r6_add(self):
        s=summarize_consumers(synthetic('stack6',corrupt=(0x20+8*2+4,0x3068)))
        self.assertEqual(s['groups_adding_r6_and_storing_four_stack_words'],0)

    def test_negative_incorrect_stack_store(self):
        s=summarize_consumers(synthetic('stack6',corrupt=(0x20+8*3+6,0x8104)))
        self.assertEqual(s['groups_adding_r6_and_storing_four_stack_words'],0)

    def test_branch_classifier(self):
        self.assertTrue(all(is_branch(x) for x in (0xA001,0xB200,0x8901,0x8B0A,0x430B,0x000B)))
        self.assertFalse(is_branch(0x0009))

    def test_non_byte_displacement(self):
        self.assertIsNone(field_read(bytes.fromhex('E0 1E 0E 4C'),0))

    def test_empty_input(self):
        self.assertEqual(summarize_consumers(b'')['candidate_four_field_consumer_groups'],0)

    def test_no_code_offsets_in_summary(self):
        r=summarize_consumers(synthetic(extended=True))
        for key in ('instruction_position','raw_bytes','binary_offset','program_location','reads'):
            self.assertNotIn(key,r)

    def test_multiple_independent_clusters(self):
        a=synthetic('sum5');b=synthetic('stack6');c=synthetic('sum5',extended=True)
        s=summarize_consumers(a+b+c)
        self.assertEqual(s['candidate_four_field_consumer_groups'],3)
        self.assertEqual(s['groups_reading_all_seven_bytes'],1)
        self.assertEqual(s['groups_adding_r5_to_all_four_results'],2)
        self.assertEqual(s['groups_adding_r6_and_storing_four_stack_words'],1)


if __name__=='__main__':
    unittest.main()
