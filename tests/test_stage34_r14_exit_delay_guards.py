"""Synthetic-only Stage34 exit-delay and special-wrapper linkage tests."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage33_r14_origin_audit import fixture as stage33_fixture
from test_stage32_field_consumer_callers import LITERAL_BLOCKS, put
from stage34_r14_exit_delay_guards import (
    bra_target, r14_restore_exit_kind, inspect_r14_restore_contexts,
)
from stage32_field_consumer_callers import LOAD_BASE

WRAPPER = LITERAL_BLOCKS[7] - 2


def fixture(mutation=None, with_exits=True, with_conflicts=True):
    data = bytearray(stage33_fixture(conflicting=with_conflicts))
    if with_exits:
        for idx in range(3):
            pos = LITERAL_BLOCKS[idx] - 6
            if idx == 0:
                put(data, pos, 0x412B)  # JMP @R1, POP R14 in delay slot
            else:
                call = LITERAL_BLOCKS[idx] + 2
                dest = call + 20
                put(data, pos, 0xA000 | (((dest - pos - 4) // 2) & 0xFFF))
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage34Tests(unittest.TestCase):
    def report(self, *args, **kwargs):
        return inspect_r14_restore_contexts(fixture(*args, **kwargs))

    def test_eight_local_r14_sources(self):
        self.assertEqual(self.report()["r14_pass_through_calls_with_local_origin"], 8)

    def test_one_unknown_r14_source(self):
        self.assertEqual(self.report()["r14_pass_through_calls_without_local_origin"], 1)

    def test_five_without_restores(self):
        self.assertEqual(self.report()["local_origins_with_no_restore_opcodes"], 5)

    def test_three_paths_with_restores(self):
        self.assertEqual(self.report()["local_origins_with_restore_opcodes"], 3)

    def test_one_dynamic_jump_delay_restore(self):
        self.assertEqual(self.report()["restores_in_dynamic_jmp_delay_slots"], 1)

    def test_two_forward_bra_delay_restores(self):
        self.assertEqual(self.report()["restores_in_forward_exit_bra_delay_slots"], 2)

    def test_no_unresolved_restores(self):
        self.assertEqual(self.report()["restores_with_unresolved_local_context"], 0)

    def test_wrapper_recognized(self):
        self.assertEqual(self.report()["distinct_special_wrapper_entries"], 1)

    def test_wrapper_no_direct_reference(self):
        self.assertEqual(self.report()["direct_bsr_references_to_special_wrapper"], 0)

    def test_wrapper_no_literal_reference(self):
        self.assertEqual(self.report()["pc_relative_address_literals_to_special_wrapper"], 0)

    def test_jmp_delay_classification(self):
        self.assertEqual(r14_restore_exit_kind(fixture(), LITERAL_BLOCKS[0]-4,
                                                LITERAL_BLOCKS[0]+2),
                         "dynamic_jmp_delay_slot")

    def test_bra_delay_classification(self):
        self.assertEqual(r14_restore_exit_kind(fixture(), LITERAL_BLOCKS[1]-4,
                                                LITERAL_BLOCKS[1]+2),
                         "forward_exit_bra_delay_slot")

    def test_bra_target_math(self):
        self.assertEqual(bra_target(0x100, 0xAFFE), 0x100)
        self.assertEqual(bra_target(0x100, 0xA002), 0x108)
        self.assertIsNone(bra_target(0x100, 0x412B))

    def test_malformed_jmp_yields_unresolved(self):
        r = self.report(mutation=(LITERAL_BLOCKS[0]-6, 0x0009))
        self.assertEqual(r["restores_in_dynamic_jmp_delay_slots"], 0)
        self.assertEqual(r["restores_with_unresolved_local_context"], 1)

    def test_bra_that_does_not_skip_call_is_unresolved(self):
        r = self.report(mutation=(LITERAL_BLOCKS[1]-6, 0xA000))
        self.assertEqual(r["restores_in_forward_exit_bra_delay_slots"], 1)
        self.assertEqual(r["restores_with_unresolved_local_context"], 1)

    def test_no_competing_restores(self):
        r = self.report(with_conflicts=False)
        self.assertEqual(r["local_origins_with_no_restore_opcodes"], 8)
        self.assertEqual(r["restores_in_dynamic_jmp_delay_slots"], 0)
        self.assertEqual(r["restores_in_forward_exit_bra_delay_slots"], 0)

    def test_one_removed_restore(self):
        r = self.report(mutation=(LITERAL_BLOCKS[2]-4, 0x0009))
        self.assertEqual(r["local_origins_with_no_restore_opcodes"], 6)
        self.assertEqual(r["restores_in_forward_exit_bra_delay_slots"], 1)

    def test_wrapper_requires_r5_two(self):
        r = self.report(mutation=(LITERAL_BLOCKS[7]+8, 0x0009))
        self.assertEqual(r["distinct_special_wrapper_entries"], 0)

    def test_direct_bsr_to_wrapper_now_detected(self):
        d=bytearray(fixture())
        p=0x780
        put(d,p,0xB000 | (((WRAPPER-p-4)//2) & 0xFFF))
        r=inspect_r14_restore_contexts(bytes(d))
        self.assertEqual(r["direct_bsr_references_to_special_wrapper"],1)

    def test_literal_pointer_to_wrapper_now_detected(self):
        d=bytearray(fixture())
        p=0x800
        put(d,p,0xD101)  # aligned PC+4 plus 4-byte displacement
        d[p+8:p+12]=(LOAD_BASE + WRAPPER).to_bytes(4, "big")
        r=inspect_r14_restore_contexts(bytes(d))
        self.assertEqual(r["pc_relative_address_literals_to_special_wrapper"],1)

    def test_invalid_restore_not_classified(self):
        self.assertEqual(r14_restore_exit_kind(b"\x00"*16,4,12),
                         "not_r14_restore")

    def test_output_is_metadata_only(self):
        r=self.report()
        for key in ("call_position", "restore_position", "load_pos", "literal_pos",
                    "entry", "raw_bytes", "game_program_offsets"):
            self.assertNotIn(key,r)

    def test_empty_image(self):
        r=inspect_r14_restore_contexts(b"")
        self.assertEqual(r["r14_pass_through_calls_with_local_origin"],0)
        self.assertEqual(r["distinct_special_wrapper_entries"],0)


if __name__ == "__main__":
    unittest.main()
