"""Stage26 synthetic-only checks for SH-2 helper R4 register contract."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage25_r4_provenance_probe import fixture as stage25_fixture, put
from stage26_helper_r4_nested_pointer import (
    ENTRY_PREFIX, RETURN_SUFFIX, bt_branch_target,
    movw_pc_literal_position, match_entry, inspect_helper,
    find_return_sequences, summarize_helper_registers,
)

HELPER = 0x420
EPILOGUE = HELPER + 0x114


def fixture(broken_word=None, wrong_literal=False, wrong_branch=False,
            wrong_zero_case=False, wrong_epilogue=None, no_helper_call=False):
    data = bytearray(stage25_fixture(call=not no_helper_call))
    data.extend(bytes(0x240))
    for i, opcode in enumerate(ENTRY_PREFIX):
        if opcode is None:
            opcode = 0x9027 if i == 2 else 0x890C
        if broken_word == i:
            opcode ^= 1
        put(data, HELPER + i * 2, opcode)
    # MOV.W at HELPER+4 reads from HELPER+0x56.
    put(data, HELPER + 0x56, 0xA1 if wrong_literal else 0xA0)
    put(data, HELPER + 0x2E, 0x0009 if wrong_zero_case else 0xE400)
    if wrong_branch:
        put(data, HELPER + 18, 0x890E)
    for i, opcode in enumerate(RETURN_SUFFIX):
        if wrong_epilogue == i:
            opcode ^= 1
        put(data, EPILOGUE + i * 2, opcode)
    return bytes(data)


class Stage26NestedPointerTests(unittest.TestCase):
    def test_full_helper_signature(self):
        self.assertIsNotNone(inspect_helper(fixture(), HELPER))

    def test_stage25_linked_helper_count(self):
        s = summarize_helper_registers(fixture())
        self.assertEqual(s["stage25_helper_calls_examined"], 1)
        self.assertEqual(s["helpers_with_complete_entry_and_return_signature"], 1)

    def test_nested_pointer_displacement(self):
        s = summarize_helper_registers(fixture())
        self.assertEqual(s["nested_pointer_field_offset_bytes"], 160)

    def test_r4_clobbered_before_first_branch(self):
        s = summarize_helper_registers(fixture())
        self.assertEqual(s["helpers_with_unconditional_r4_write_before_first_branch"], 1)

    def test_zero_pointer_path(self):
        self.assertEqual(summarize_helper_registers(fixture())[
            "helpers_with_explicit_zero_case_r4_assignment"], 1)

    def test_zero_pointer_path_optional(self):
        self.assertEqual(summarize_helper_registers(fixture(wrong_zero_case=True))[
            "helpers_with_explicit_zero_case_r4_assignment"], 0)

    def test_reject_wrong_input_save(self):
        self.assertIsNone(inspect_helper(fixture(broken_word=1), HELPER))

    def test_reject_wrong_pointer_load(self):
        self.assertIsNone(inspect_helper(fixture(broken_word=7), HELPER))

    def test_reject_wrong_zero_test(self):
        self.assertIsNone(inspect_helper(fixture(broken_word=8), HELPER))

    def test_reject_wrong_pc_literal(self):
        self.assertIsNone(inspect_helper(fixture(wrong_literal=True), HELPER))

    def test_reject_non_returning_epilogue(self):
        self.assertIsNone(inspect_helper(fixture(wrong_epilogue=4), HELPER))

    def test_requires_r14_restore_in_rts_delay_slot(self):
        self.assertIsNone(inspect_helper(fixture(wrong_epilogue=5), HELPER))

    def test_requires_pr_restore(self):
        self.assertIsNone(inspect_helper(fixture(wrong_epilogue=1), HELPER))

    def test_matched_epilogue_does_not_restore_r4(self):
        s = summarize_helper_registers(fixture())
        self.assertFalse(s["r4_restored_by_matched_epilogue"])
        self.assertEqual(s["matched_epilogues_restoring_r12_r13_r14_and_pr"], 1)

    def test_no_call_no_connected_helper(self):
        self.assertEqual(summarize_helper_registers(fixture(no_helper_call=True))[
            "helpers_with_complete_entry_and_return_signature"], 0)

    def test_movw_pc_target(self):
        self.assertEqual(movw_pc_literal_position(HELPER + 4, 0x9027, 0x900),
                         HELPER + 0x56)
        self.assertIsNone(movw_pc_literal_position(HELPER + 4, 0xD027, 0x900))

    def test_bt_target(self):
        self.assertEqual(bt_branch_target(HELPER + 18, 0x890C), HELPER + 0x2E)
        self.assertIsNone(bt_branch_target(HELPER + 18, 0x8B0C))

    def test_no_binary_positions_exported(self):
        s = summarize_helper_registers(fixture())
        for key in ("entry", "zero_path", "epilogues", "raw_bytes", "program_offsets"):
            self.assertNotIn(key, s)

    def test_empty_input(self):
        self.assertEqual(summarize_helper_registers(b"")[
            "helpers_with_complete_entry_and_return_signature"], 0)


if __name__ == "__main__":
    unittest.main()
