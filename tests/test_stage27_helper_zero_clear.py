"""Purely synthetic Stage27 SH-2 null-pointer and clear-arm tests."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage25_r4_provenance_probe import fixture as stage25_fixture, put
from stage27_helper_zero_clear import (
    ZERO_ARM, EPILOGUE, branch_target, check_zero_arm,
    summarize_helper_zero_clear,
)

ENTRY = 0x420
EPILOGUE_AT = ENTRY + 0x114


def fixture(change=None, disable_call=False, drop_last_store=False,
            broken_epilogue=None, broken_null=False,
            broken_alternate=False, wrong_nonzero_branch=False,
            bad_first_r4_source=False):
    data = bytearray(stage25_fixture(call=not disable_call))
    data.extend(bytes(0x250))
    for off, instruction in (
        (0, 0x2FE6), (2, 0x6E43), (14, 0x04EE), (16, 0x2448),
        (0x12, 0x890C), (0x1C, 0x8907),
        (0x2A, 0x2008), (0x2C, 0x8B1C),
    ):
        put(data, ENTRY + off, instruction)
    if bad_first_r4_source:
        put(data, ENTRY + 14, 0x04EF)
    if broken_null:
        put(data, ENTRY + 0x12, 0x890D)
    if broken_alternate:
        put(data, ENTRY + 0x1C, 0x8908)
    if wrong_nonzero_branch:
        put(data, ENTRY + 0x2C, 0x8B1D)
    for i, word in enumerate(ZERO_ARM):
        word = 0xA065 if word is None else word
        if drop_last_store and i == len(ZERO_ARM) - 1:
            word = 0x0009
        put(data, ENTRY + 0x2E + 2*i, word)
    for i, word in enumerate(EPILOGUE):
        put(data, EPILOGUE_AT + i*2,
            word ^ 1 if broken_epilogue == i else word)
    if change is not None:
        off, word = change
        put(data, ENTRY + off, word)
    return bytes(data)


class Stage27Tests(unittest.TestCase):
    def test_one_complete_helper(self):
        s = summarize_helper_zero_clear(fixture())
        self.assertEqual(s["helpers_with_complete_zero_clear_and_return_arm"], 1)

    def test_7_contiguous_zero_bytes(self):
        self.assertEqual(
            summarize_helper_zero_clear(fixture())["cleared_input_structure_byte_offsets"],
            list(range(31, 38)))

    def test_store_widths(self):
        self.assertEqual(summarize_helper_zero_clear(fixture())["clear_operations"],
                         {"byte_stores": 5, "word_stores": 1})

    def test_bra_delay_slot(self):
        self.assertTrue(summarize_helper_zero_clear(fixture())[
            "final_word_store_in_BRA_delay_slot"])

    def test_null_branch_target(self):
        self.assertEqual(branch_target(ENTRY+0x12, 0x890C), ENTRY+0x2E)

    def test_alternate_branch_target(self):
        self.assertEqual(branch_target(ENTRY+0x1C, 0x8907), ENTRY+0x2E)

    def test_nonzero_guard(self):
        self.assertEqual(branch_target(ENTRY+0x2C, 0x8B1C), ENTRY+0x68)

    def test_bra_epilogue_target(self):
        self.assertEqual(branch_target(ENTRY+0x46, 0xA065), EPILOGUE_AT)

    def test_signed_backward_bra(self):
        self.assertEqual(branch_target(0x310, 0xAFFE), 0x310)

    def test_invalid_branch(self):
        self.assertIsNone(branch_target(ENTRY, 0x0009))

    def test_null_branch_must_reach_zero(self):
        self.assertIsNone(check_zero_arm(fixture(broken_null=True), ENTRY))

    def test_second_branch_must_reach_zero(self):
        self.assertIsNone(check_zero_arm(fixture(broken_alternate=True), ENTRY))

    def test_nonzero_branch_must_skip_clear_arm(self):
        self.assertIsNone(check_zero_arm(fixture(wrong_nonzero_branch=True), ENTRY))

    def test_last_store_required(self):
        self.assertIsNone(check_zero_arm(fixture(drop_last_store=True), ENTRY))

    def test_restoring_r14_required(self):
        self.assertIsNone(check_zero_arm(fixture(broken_epilogue=5), ENTRY))

    def test_r4_input_load_required(self):
        self.assertIsNone(check_zero_arm(fixture(bad_first_r4_source=True), ENTRY))

    def test_no_linked_helper_without_bsr(self):
        self.assertEqual(summarize_helper_zero_clear(fixture(disable_call=True))[
            "helpers_with_complete_zero_clear_and_return_arm"], 0)

    def test_proprietary_positions_not_reported(self):
        s = summarize_helper_zero_clear(fixture())
        for name in ("entry", "program_offset", "source_bytes", "zero",
                     "epilogue", "helper_target"):
            self.assertNotIn(name, s)

    def test_empty_input(self):
        self.assertEqual(summarize_helper_zero_clear(b"")[
            "stage25_helper_targets_examined"], 0)


if __name__ == "__main__":
    unittest.main()
