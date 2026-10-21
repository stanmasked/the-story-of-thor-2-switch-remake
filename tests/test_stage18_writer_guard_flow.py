"""Stage18 synthetic tests: a conditional SH-2 VDP1 descriptor-writer block."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage18_writer_guard_flow import (
    BUDGET_GLOBAL, conditional_branch_target, find_guarded_writer_blocks,
    movl_target, movw_target, summarize_guard_flow,
)


def put16(data, offset, value):
    data[offset:offset + 2] = value.to_bytes(2, "big")


def put32(data, offset, value):
    data[offset:offset + 4] = value.to_bytes(4, "big")


def fixture(bad_guard=False, bad_exit=False, bad_store=False, bad_previous=False):
    data = bytearray(0x180)
    start = 0x20
    # BF/S prior to guard targets the same exit as BT.
    put16(data, start - 4, 0x8F20 if not bad_previous else 0x8F00)
    put16(data, start, 0xD337)  # Counter address in PC-relative literal pool
    put16(data, start + 2, 0x6231)
    put16(data, start + 4, 0x916F)  # Capacity in PC-relative literal pool
    put16(data, start + 6, 0x3213)
    put16(data, start + 8, 0x891A if not bad_guard else 0x8900)
    put16(data, start + 10, 0x2322)  # 32-bit source address
    put16(data, start + 12, 0x2301 if not bad_store else 0x0009)
    put16(data, start + 14, 0x2321)  # per-source record count
    put16(data, start + 16, 0x7101)  # budget +1
    put16(data, start + 18, 0x2311)
    put16(data, 0x5A, 0x6382)
    put16(data, 0x5C, 0x7308)
    put16(data, 0x5E, 0x2832 if not bad_exit else 0x0009)
    put32(data, 0x100, BUDGET_GLOBAL)
    put16(data, 0x106, 512)
    return bytes(data)


class Stage18WriterGuardFlowTests(unittest.TestCase):
    def test_conditional_forward(self):
        self.assertEqual(conditional_branch_target(0x28, 0x891A), 0x60)

    def test_conditional_negative(self):
        self.assertEqual(conditional_branch_target(0x40, 0x8BFA), 0x38)

    def test_invalid_branch(self):
        self.assertIsNone(conditional_branch_target(0x40, 0xB000))

    def test_movl_alignment(self):
        self.assertEqual(movl_target(0x20, 0xD337, 0x180), 0x100)

    def test_movw_target(self):
        self.assertEqual(movw_target(0x24, 0x916F, 0x180), 0x106)

    def test_one_guarded_block(self):
        self.assertEqual(len(find_guarded_writer_blocks(fixture())), 1)

    def test_previous_branch_shares_exit(self):
        self.assertTrue(find_guarded_writer_blocks(fixture())[0]["previous_delayed_branch_same_exit"])

    def test_previous_branch_mismatch(self):
        self.assertFalse(find_guarded_writer_blocks(fixture(bad_previous=True))[0]["previous_delayed_branch_same_exit"])

    def test_guard_must_skip_all_stores(self):
        self.assertEqual(find_guarded_writer_blocks(fixture(bad_guard=True)), [])

    def test_pointer_commit_must_precede_exit(self):
        self.assertEqual(find_guarded_writer_blocks(fixture(bad_exit=True)), [])

    def test_missing_field_store_is_rejected(self):
        self.assertEqual(find_guarded_writer_blocks(fixture(bad_store=True)), [])

    def test_report_is_aggregated(self):
        result = summarize_guard_flow(fixture())
        self.assertEqual(result["capacity_guards_with_validated_writer_block"], 1)
        self.assertEqual(result["pre_guard_bf_s_branches_sharing_writer_exit"], 1)
        self.assertNotIn("start", result)
        self.assertNotIn("exit", result)
        self.assertNotIn("raw_bytes", result)


if __name__ == "__main__":
    unittest.main()
