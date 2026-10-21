"""Stage20 tests contain only synthetic opcode fixtures."""
import unittest
from stage18_writer_guard_flow import BUDGET_GLOBAL
from stage20_vdp1_product_flow import (
    PRELUDE, count_from_byte_factors, matching_product_preludes, summarize_product_flow,
)


def put16(buf, i, value):
    buf[i:i + 2] = value.to_bytes(2, 'big')


def put32(buf, i, value):
    buf[i:i + 4] = value.to_bytes(4, 'big')


def fixture(bad_prelude_index=None, bad_pre_branch=False,
            bad_stage19_count=False, bad_writer_guard=False):
    buf = bytearray(0x180)
    start = 0x20
    sequence = list(PRELUDE)
    sequence[7] = 0x8F20 if not bad_pre_branch else 0x8F00
    if bad_prelude_index is not None:
        sequence[bad_prelude_index] ^= 1
    for j, word in enumerate(sequence):
        put16(buf, start - len(sequence) * 2 + j * 2, word)
    for off, opcode in {
        0x20: 0xD337, 0x22: 0x6231,
        0x24: 0x916F,
        0x26: 0x3213, 0x28: 0x891A,
        0x2A: 0x2322, 0x2C: 0x6243,
        0x2E: 0x4221, 0x30: 0x4221,
        0x32: 0x4221 if not bad_stage19_count else 0x4201,
        0x34: 0x2301, 0x36: 0x2321,
        0x38: 0x7101, 0x3A: 0x2311,
        0x5A: 0x6382, 0x5C: 0x7308, 0x5E: 0x2832,
    }.items():
        put16(buf, off, opcode)
    put32(buf, 0x100, BUDGET_GLOBAL)
    put16(buf, 0x106, 512 if not bad_writer_guard else 256)
    return bytes(buf)


class Stage20ProductFlowTests(unittest.TestCase):
    def test_matches_full_prelude_and_writer(self):
        self.assertEqual(len(matching_product_preludes(fixture())), 1)

    def test_complete_link_to_stage19(self):
        self.assertEqual(summarize_product_flow(fixture())['preludes_linked_to_complete_stage19_count_writer'], 1)

    def test_rejects_missing_unsigned_extend_r5(self):
        self.assertEqual(matching_product_preludes(fixture(bad_prelude_index=0)), [])

    def test_rejects_missing_unsigned_extend_r3(self):
        self.assertEqual(matching_product_preludes(fixture(bad_prelude_index=1)), [])

    def test_rejects_wrong_multiply(self):
        self.assertEqual(matching_product_preludes(fixture(bad_prelude_index=3)), [])

    def test_rejects_wrong_stack_index_byte_load(self):
        self.assertEqual(matching_product_preludes(fixture(bad_prelude_index=4)), [])

    def test_rejects_missing_macl_transfer(self):
        self.assertEqual(matching_product_preludes(fixture(bad_prelude_index=5)), [])

    def test_rejects_mismatched_branch_exit(self):
        self.assertEqual(matching_product_preludes(fixture(bad_pre_branch=True)), [])

    def test_count_flow_must_be_complete(self):
        self.assertEqual(summarize_product_flow(fixture(bad_stage19_count=True))['preludes_linked_to_complete_stage19_count_writer'], 0)

    def test_requires_writer_guard(self):
        self.assertEqual(summarize_product_flow(fixture(bad_writer_guard=True))['product_prelude_matches'], 0)

    def test_product_math(self):
        self.assertEqual(count_from_byte_factors(255, 255), 8128)
        self.assertEqual(count_from_byte_factors(8, 1), 1)
        self.assertEqual(count_from_byte_factors(2, 3), 0)

    def test_rejects_out_of_bounds_math(self):
        with self.assertRaises(ValueError):
            count_from_byte_factors(-1, 3)
        with self.assertRaises(ValueError):
            count_from_byte_factors(256, 3)

    def test_report_has_no_offsets(self):
        report = summarize_product_flow(fixture())
        self.assertEqual(report['mathematical_max_product'], 65025)
        self.assertNotIn('offsets', report)
        self.assertNotIn('raw_bytes', report)
        self.assertNotIn('block_start', report)


if __name__ == '__main__':
    unittest.main()
