"""Stage33 synthetic tests: provenance labels without original Saturn code."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage32_field_consumer_callers import (
    fixture as stage32_fixture, LITERAL_BLOCKS, BSR_POSITIONS, put,
)
from stage33_r14_origin_audit import (
    preceding_r14_save, r14_direct_write, wrapper_uses_incoming_r4,
    summarize_origins,
)


def fixture(mutation=None, conflicting=True, with_wrapper=True):
    data = bytearray(stage32_fixture())
    # Direct BSR #2 has an immediately preceding prologue; BSR #1 does not.
    put(data, BSR_POSITIONS[1] - 16, 0x2FE6)
    put(data, BSR_POSITIONS[1] - 14, 0x6E43)

    # Seven indirect JSRs pass R14 in the delay slot. Every one has a
    # candidate prologue; the first three contain an ambiguous R14 pop.
    for i, load_pos in enumerate(LITERAL_BLOCKS[:7]):
        put(data, load_pos - 16, 0x2FE6)
        put(data, load_pos - 14, 0x6E43)
        if conflicting and i < 3:
            put(data, load_pos - 4, 0x6EF6)

    # The eighth indirect caller uses incoming R4; delay slot sets R5=2.
    if with_wrapper:
        put(data, LITERAL_BLOCKS[7] - 2, 0x4F22)
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage33OriginTests(unittest.TestCase):
    def report(self, *args, **kwargs):
        return summarize_origins(fixture(*args, **kwargs))

    def test_ten_calls_found(self):
        self.assertEqual(self.report()["stage32_caller_sites_examined"], 10)

    def test_nine_calls_pass_r14(self):
        self.assertEqual(self.report()["calls_passing_r14_as_r4_in_delay_slot"], 9)

    def test_eight_nearby_prologue_copies(self):
        self.assertEqual(self.report()["r14_callers_with_local_push_and_input_r4_copy"], 8)

    def test_one_untraced_r14(self):
        self.assertEqual(self.report()["r14_callers_without_local_copy_in_bounded_window"], 1)

    def test_five_lexically_uninterrupted(self):
        self.assertEqual(self.report()["local_copies_without_recognized_intervening_r14_writes"], 5)

    def test_three_competing_r14_restores(self):
        self.assertEqual(self.report()["local_copies_with_competing_lexical_r14_writes"], 3)

    def test_one_exceptional_wrapper(self):
        self.assertEqual(self.report()["indirect_wrappers_saving_existing_r4_and_setting_r5_two"], 1)

    def test_wrapper_source_still_unknown(self):
        self.assertEqual(self.report()["wrapper_r4_source"], "incoming_R4_untraced")

    def test_remove_competing_writes(self):
        r = self.report(conflicting=False)
        self.assertEqual(r["local_copies_without_recognized_intervening_r14_writes"], 8)
        self.assertEqual(r["local_copies_with_competing_lexical_r14_writes"], 0)

    def test_prologue_copy_required(self):
        r = self.report(mutation=(LITERAL_BLOCKS[4] - 14, 0x6E53))
        self.assertEqual(r["r14_callers_with_local_push_and_input_r4_copy"], 7)

    def test_push_required(self):
        r = self.report(mutation=(LITERAL_BLOCKS[5] - 16, 0x0009))
        self.assertEqual(r["r14_callers_with_local_push_and_input_r4_copy"], 7)

    def test_direct_caller_copy_required(self):
        r = self.report(mutation=(BSR_POSITIONS[1] - 14, 0x0009))
        self.assertEqual(r["r14_callers_with_local_push_and_input_r4_copy"], 7)

    def test_wrapper_requires_save_pr(self):
        r = self.report(with_wrapper=False)
        self.assertEqual(r["indirect_wrappers_saving_existing_r4_and_setting_r5_two"], 0)

    def test_wrapper_requires_stack_store(self):
        r = self.report(mutation=(LITERAL_BLOCKS[7] + 4, 0x0009))
        self.assertEqual(r["indirect_wrappers_saving_existing_r4_and_setting_r5_two"], 0)

    def test_wrapper_requires_delay_r5(self):
        r = self.report(mutation=(LITERAL_BLOCKS[7] + 8, 0x0009))
        self.assertEqual(r["indirect_wrappers_saving_existing_r4_and_setting_r5_two"], 0)

    def test_does_not_mark_wrapper_as_r14_copy(self):
        self.assertIsNone(preceding_r14_save(fixture(), LITERAL_BLOCKS[7] + 6))

    def test_r14_write_recognition(self):
        for opcode in (0x6EF6, 0x6E43, 0x7E01, 0xDE20):
            self.assertTrue(r14_direct_write(opcode))
        for opcode in (0x64E3, 0xE502, 0x0009):
            self.assertFalse(r14_direct_write(opcode))

    def test_empty_input(self):
        self.assertEqual(summarize_origins(b"")["stage32_caller_sites_examined"], 0)

    def test_invalid_call_bounds(self):
        self.assertIsNone(preceding_r14_save(b"\x00" * 32, 33))
        self.assertFalse(wrapper_uses_incoming_r4(b"\x00" * 32, 14, 20))

    def test_output_never_contains_proprietary_program_positions(self):
        r = self.report()
        for name in ("call", "prologue", "initialization", "load_pos",
                     "literal_pos", "raw_bytes", "game_program_offsets"):
            self.assertNotIn(name, r)


if __name__ == "__main__":
    unittest.main()
