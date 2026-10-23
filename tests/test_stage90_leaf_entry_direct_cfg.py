import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage90_leaf_entry_direct_cfg import audit_direct_cfg


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def simple_prologue(data, pos):
    put16(data, pos, 0x2FE6)
    put16(data, pos + 2, 0x4F22)


class Stage90LeafEntryDirectCFGTests(unittest.TestCase):
    def test_straight_line_rts_with_delay_slot(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x6043)
        put16(data, 0x12, 0x000B)
        put16(data, 0x14, 0xE000)
        result = audit_direct_cfg(data, 0x10, 0x40)
        self.assertEqual(result["reachable_rts_sites"], 1)
        self.assertEqual(result["reachable_instruction_addresses_including_delay_slots"], 3)
        self.assertTrue(result["all_observed_exits_are_rts"])
        self.assertTrue(result["all_paths_proven_to_terminate_at_rts"])

    def test_conditional_branch_reaches_two_return_sites(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x8B02)  # BF to 0x1C
        put16(data, 0x12, 0x000B)
        put16(data, 0x14, 0x0009)  # RTS delay slot
        put16(data, 0x1C, 0x000B)
        put16(data, 0x1E, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30)
        self.assertEqual(result["reachable_rts_sites"], 2)
        self.assertTrue(result["all_observed_exits_are_rts"])
        self.assertTrue(result["all_paths_proven_to_terminate_at_rts"])

    def test_loop_with_return_exit_detects_cycle(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x8B02)  # BF to 0x18
        put16(data, 0x12, 0xA0FE)  # BRA back to 0x10
        put16(data, 0x14, 0x0009)  # BRA delay slot
        put16(data, 0x18, 0x000B)
        put16(data, 0x1A, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30)
        self.assertTrue(result["cycle_detected"])
        self.assertEqual(result["reachable_rts_sites"], 1)
        self.assertTrue(result["all_observed_exits_are_rts"])
        self.assertFalse(result["all_paths_proven_to_terminate_at_rts"])

    def test_branch_outside_bound_is_not_assumed_to_return(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0xA07E)  # BRA beyond end bound
        put16(data, 0x12, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30)
        self.assertFalse(result["all_observed_exits_are_rts"])
        self.assertFalse(result["all_paths_proven_to_terminate_at_rts"])

    def test_rts_delay_slot_does_not_fall_through_after_return(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x000B)
        put16(data, 0x12, 0xE000)  # executes as RTS delay slot
        put16(data, 0x14, 0xA07E)  # must not be reached
        result = audit_direct_cfg(data, 0x10, 0x30)
        self.assertEqual(result["reachable_rts_sites"], 1)
        self.assertEqual(result["reachable_unconditional_branches"], 0)
        self.assertEqual(result["reachable_instruction_addresses_including_delay_slots"], 2)

    def test_jsr_delay_slot_and_returning_callee_model(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x430B)
        put16(data, 0x12, 0x0009)
        put16(data, 0x14, 0x000B)
        put16(data, 0x16, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30)
        self.assertEqual(result["reachable_call_sites"], 1)
        self.assertEqual(result["reachable_rts_sites"], 1)
        self.assertTrue(result["all_paths_proven_to_terminate_at_rts"])

    def test_bsr_is_treated_as_call_with_delay_slot(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0xB001)
        put16(data, 0x12, 0x0009)
        put16(data, 0x14, 0x000B)
        put16(data, 0x16, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30)
        self.assertEqual(result["reachable_call_sites"], 1)
        self.assertEqual(result["reachable_rts_sites"], 1)

    def test_indirect_jump_is_an_unresolved_exit(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x432B)  # JMP @R3
        put16(data, 0x12, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30)
        self.assertEqual(result["reachable_indirect_jumps"], 1)
        self.assertFalse(result["all_observed_exits_are_rts"])

    def test_state_limit_is_reported(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x0009)
        put16(data, 0x12, 0x0009)
        put16(data, 0x14, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30, max_states=1)
        self.assertTrue(result["state_limit_reached"])
        self.assertFalse(result["all_paths_proven_to_terminate_at_rts"])

    def test_output_redacts_addresses_and_offsets(self):
        data = bytearray(0x100)
        put16(data, 0x10, 0x000B)
        put16(data, 0x12, 0x0009)
        result = audit_direct_cfg(data, 0x10, 0x30)
        rendered = json.dumps(result)
        for value in ("0x10", "0x12", "0x30", hex(CODE_LOAD_ADDRESS)):
            self.assertNotIn(value, rendered)
        self.assertFalse(result["runtime_reachability_proven"])


if __name__ == "__main__":
    unittest.main()
