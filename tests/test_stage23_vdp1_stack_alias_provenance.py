"""Stage23 synthetic-only SH-2 stack-pointer alias tests."""
import unittest

from test_stage22_vdp1_stack_store_audit import fixture as stage22_fixture, put16
from stage23_vdp1_stack_alias_provenance import (
    stack_alias_writes, summarize_alias_provenance, find_frame, FRAME_ALLOC,
)


def alias_fixture(missing=None, with_branch=False, with_clobber=False,
                  without_frame=False):
    data = bytearray(stage22_fixture(remove_frame=without_frame))
    instructions = {
        0x70: 0x8492,  # MOV.B @(2,R4),R0
        0x72: 0x61F3,  # MOV R15,R1
        0x74: 0x7114,  # ADD #20,R1
        0x76: 0x2100,  # MOV.B R0,@R1
        0x80: 0x8493,  # MOV.B @(3,R4),R0
        0x82: 0x62F3,  # MOV R15,R2
        0x84: 0x7220,  # ADD #32,R2
        0x86: 0x2200,  # MOV.B R0,@R2
        0x8E: 0xE014,  # MOV #20,R0
        0x90: 0x61F3,  # MOV R15,R1
        0x92: 0x00FC,  # MOV.B @(R0,R15),R0
        0x94: 0x7114,  # ADD #20,R1
        0x96: 0xC93F,  # AND #63,R0
        0x98: 0x2100,  # MOV.B R0,@R1
        0xA0: 0x8491,  # MOV.B @(1,R4),R0
        0xA2: 0x63F3,  # MOV R15,R3
        0xA4: 0x7338,  # ADD #56,R3
        0xA6: 0x2300,  # MOV.B R0,@R3
    }
    if missing in instructions:
        instructions[missing] = 0x0009
    if with_branch:
        instructions[0x75] = 0x0009  # overwritten later by explicit branch below
        instructions[0x74] = 0xA000  # replaces ADD #20 with BRA
    if with_clobber:
        instructions[0x75] = 0x0009
        instructions[0x74] = 0x7114
        instructions[0x76] = 0xE100  # clobber R1 instead of store
    for offset, word in instructions.items():
        if offset % 2 == 0:
            put16(data, offset, word)
    return bytes(data)


class Stage23AliasTests(unittest.TestCase):
    def test_complete_matches_four_stores(self):
        self.assertEqual(summarize_alias_provenance(alias_fixture())["stack_alias_store_candidates"], 4)

    def test_both_factor_slots_are_written(self):
        self.assertEqual(summarize_alias_provenance(alias_fixture())["stack_alias_stores_by_field"]["SP+20"], 2)
        self.assertEqual(summarize_alias_provenance(alias_fixture())["stack_alias_stores_by_field"]["SP+32"], 1)

    def test_auxiliary_stack_field(self):
        self.assertEqual(summarize_alias_provenance(alias_fixture())["stack_alias_stores_by_field"]["SP+56"], 1)

    def test_no_alias_store_to_flag(self):
        self.assertEqual(summarize_alias_provenance(alias_fixture())["stack_alias_stores_by_field"]["SP+80"], 0)

    def test_first_factor_input_from_r4(self):
        self.assertEqual(summarize_alias_provenance(alias_fixture())["source_bytes_from_R4_input_displacements"]["SP+20"], [2])

    def test_second_factor_input_from_r4(self):
        self.assertEqual(summarize_alias_provenance(alias_fixture())["source_bytes_from_R4_input_displacements"]["SP+32"], [3])

    def test_auxiliary_input_from_r4(self):
        self.assertEqual(summarize_alias_provenance(alias_fixture())["source_bytes_from_R4_input_displacements"]["SP+56"], [1])

    def test_masked_rewrite(self):
        report = summarize_alias_provenance(alias_fixture())
        self.assertEqual(report["conditional_masked_rewrites_of_first_factor"], 1)
        self.assertEqual(report["masked_first_factor_max_when_rewrite_executes"], 63)

    def test_rejects_missing_second_alias(self):
        report = summarize_alias_provenance(alias_fixture(missing=0x82))
        self.assertEqual(report["stack_alias_stores_by_field"]["SP+32"], 0)

    def test_rejects_missing_first_store(self):
        report = summarize_alias_provenance(alias_fixture(missing=0x76))
        self.assertEqual(report["stack_alias_stores_by_field"]["SP+20"], 1)

    def test_rejects_missing_mask(self):
        report = summarize_alias_provenance(alias_fixture(missing=0x96))
        self.assertEqual(report["conditional_masked_rewrites_of_first_factor"], 0)

    def test_no_frame_produces_no_aliases(self):
        report = summarize_alias_provenance(alias_fixture(without_frame=True))
        self.assertEqual(report["chains_with_88_byte_frame"], 0)
        self.assertEqual(report["stack_alias_store_candidates"], 0)

    def test_scanner_rejects_outside_range(self):
        self.assertEqual(stack_alias_writes(bytes(64), -1, 32), [])

    def test_output_has_no_game_code_positions(self):
        report = summarize_alias_provenance(alias_fixture())
        for forbidden in ("program_offsets", "store_position", "raw_bytes", "block_start"):
            self.assertNotIn(forbidden, report)

    def test_empty_input(self):
        report = summarize_alias_provenance(bytes(200))
        self.assertEqual(report["stage21_stack_source_chains"], 0)


if __name__ == "__main__":
    unittest.main()
