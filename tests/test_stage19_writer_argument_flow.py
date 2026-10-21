"""Stage19: synthetic SH-2 opcode fixtures only; no original game bytes."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage19_writer_argument_flow import summarize_argument_flow, clobbers_count_register
from stage18_writer_guard_flow import BUDGET_GLOBAL


def put16(data, offset, value):
    data[offset:offset + 2] = value.to_bytes(2, "big")


def put32(data, offset, value):
    data[offset:offset + 4] = value.to_bytes(4, "big")


def fixture(bad_cmp=False, bad_delay=False, bad_shift=False,
            bad_copy=False, bad_branch=False):
    data = bytearray(0x180)
    s = 0x20
    put16(data, s - 6, 0x8802 if bad_cmp else 0x8801)
    put16(data, s - 4, 0x8F00 if bad_branch else 0x8F20)
    put16(data, s - 2, 0x645C if bad_delay else 0x645D)
    put16(data, s, 0xD337)
    put16(data, s + 2, 0x6231)
    put16(data, s + 4, 0x916F)
    put16(data, s + 6, 0x3213)
    put16(data, s + 8, 0x891A)
    put16(data, s + 10, 0x2322)
    put16(data, s + 12, 0x6244 if bad_copy else 0x6243)
    put16(data, s + 14, 0x4221)
    put16(data, s + 16, 0x4221)
    put16(data, s + 18, 0x4201 if bad_shift else 0x4221)
    put16(data, s + 20, 0x2301)
    put16(data, s + 22, 0x2321)
    put16(data, s + 24, 0x7101)
    put16(data, s + 26, 0x2311)
    put16(data, 0x5A, 0x6382)
    put16(data, 0x5C, 0x7308)
    put16(data, 0x5E, 0x2832)
    put32(data, 0x100, BUDGET_GLOBAL)
    put16(data, 0x106, 512)
    return bytes(data)


class Stage19ArgumentFlowTests(unittest.TestCase):
    def test_complete_flow(self):
        self.assertEqual(summarize_argument_flow(fixture())["complete_argument_flow_matches"], 1)

    def test_two_guards(self):
        self.assertEqual(summarize_argument_flow(fixture())["blocks_with_cmp_equal_one_and_common_exit"], 1)

    def test_delay_slot(self):
        self.assertEqual(summarize_argument_flow(fixture())["blocks_with_zero_extension_in_bf_s_delay_slot"], 1)

    def test_arithmetic_formula(self):
        result = summarize_argument_flow(fixture())
        self.assertEqual(result["provisional_count_formula"], "(R5 & 0xFFFF) >> 3")
        self.assertEqual(result["provisional_count_mathematical_range"], [0, 8191])

    def test_bad_cmp(self):
        self.assertEqual(summarize_argument_flow(fixture(bad_cmp=True))["complete_argument_flow_matches"], 0)

    def test_bad_delay(self):
        self.assertEqual(summarize_argument_flow(fixture(bad_delay=True))["complete_argument_flow_matches"], 0)

    def test_bad_shift(self):
        self.assertEqual(summarize_argument_flow(fixture(bad_shift=True))["complete_argument_flow_matches"], 0)

    def test_bad_copy(self):
        self.assertEqual(summarize_argument_flow(fixture(bad_copy=True))["complete_argument_flow_matches"], 0)

    def test_bad_branch(self):
        self.assertEqual(summarize_argument_flow(fixture(bad_branch=True))["complete_argument_flow_matches"], 0)

    def test_empty_input(self):
        self.assertEqual(summarize_argument_flow(bytes(128))["writer_blocks_examined"], 0)

    def test_clobber_recognition(self):
        self.assertTrue(clobbers_count_register(0xE201))
        self.assertTrue(clobbers_count_register(0x7201))
        self.assertFalse(clobbers_count_register(0x4221))
        self.assertFalse(clobbers_count_register(0x7304))

    def test_metadata_has_no_offsets(self):
        report = summarize_argument_flow(fixture())
        self.assertNotIn("start", report)
        self.assertNotIn("exit", report)
        self.assertNotIn("source_bytes", report)


if __name__ == "__main__":
    unittest.main()
