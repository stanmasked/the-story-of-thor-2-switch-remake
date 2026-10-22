import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage75_indirect_services_count_provenance import LENGTH_SOURCE_GLOBAL
from stage76_length_field_feedback_cfg import (
    _direct_cfg_states_at_targets,
    _find_routine_prologues,
)


LENGTH_ADDRESS = 0x0609651C


def put16(data, position, value):
    data[position:position + 2] = value.to_bytes(2, "big")


def put32(data, position, value):
    data[position:position + 4] = value.to_bytes(4, "big")


def put_pc_literal_load(data, position, register, literal_position, value):
    pc_base = (position + 4) & ~3
    delta = literal_position - pc_base
    assert delta % 4 == 0
    displacement = delta // 4
    assert 0 <= displacement <= 0xFF
    put16(data, position, 0xD000 | (register << 8) | displacement)
    put32(data, literal_position, value)


def all_paths_seeded_fixture():
    data = bytearray(0x100)
    entry = 0x20
    put16(data, 0x20, 0xEA00)  # MOV #0,R10
    put_pc_literal_load(data, 0x22, 13, 0x80, LENGTH_ADDRESS)
    put16(data, 0x24, 0x8902)  # BT to 0x2C, or fall through
    put16(data, 0x26, 0xE100)  # MOV #0,R1
    put16(data, 0x28, 0xA002)  # BRA to 0x30
    put16(data, 0x2A, 0x0009)  # delay slot
    put16(data, 0x2C, 0xE200)  # alternate path still retains R10/R13
    put16(data, 0x2E, 0x0009)
    put16(data, 0x30, 0x22A1)  # synthetic writer/target
    return data, entry


class Stage76LengthFieldFeedbackCFGTests(unittest.TestCase):
    def test_complete_routine_prologue_is_required(self):
        data = bytearray(0x100)
        entry = 0x20
        opcodes = (
            0x2FE6, 0xE072, 0xD23E, 0x2FD6, 0x2FC6, 0x2FB6,
            0x2FA6, 0x2F96, 0x2F86, 0xE801, 0x4F22, 0x7FF8,
        )
        for index, opcode in enumerate(opcodes):
            put16(data, entry + index * 2, opcode)
        self.assertEqual(_find_routine_prologues(data), [entry])
        put16(data, entry, 0x0009)
        self.assertEqual(_find_routine_prologues(data), [])

    def test_all_direct_paths_reach_target_after_zero_and_pointer_seed(self):
        data, entry = all_paths_seeded_fixture()
        states, visited, calls, direct_calls = _direct_cfg_states_at_targets(
            data, entry, 0x30, {0x30}, LENGTH_ADDRESS
        )
        self.assertEqual(states[0x30], {(True, False, True, False)})
        self.assertGreater(visited, 0)
        self.assertEqual(calls, 0)
        self.assertEqual(direct_calls, 0)

    def test_branch_that_bypasses_zero_seed_blocks_dominance_claim(self):
        data = bytearray(0x100)
        entry = 0x20
        put16(data, 0x20, 0x8903)  # BT directly to 0x2A before initialization
        put16(data, 0x22, 0xEA00)  # MOV #0,R10
        put_pc_literal_load(data, 0x24, 13, 0x80, LENGTH_ADDRESS)
        put16(data, 0x26, 0xA003)  # BRA to 0x30
        put16(data, 0x28, 0x0009)  # delay slot
        put16(data, 0x2A, 0x0009)
        put16(data, 0x2C, 0x0009)
        put16(data, 0x2E, 0x0009)
        put16(data, 0x30, 0x22A1)
        states, _, _, _ = _direct_cfg_states_at_targets(
            data, entry, 0x30, {0x30}, LENGTH_ADDRESS
        )
        self.assertIn((False, False, False, False), states[0x30])
        self.assertIn((True, False, True, False), states[0x30])
        self.assertFalse(all(state[0] for state in states[0x30]))

    def test_r13_rewrite_invalidates_count_field_pointer_fact(self):
        data = bytearray(0x100)
        entry = 0x20
        put16(data, 0x20, 0xEA00)
        put_pc_literal_load(data, 0x22, 13, 0x80, LENGTH_ADDRESS)
        put16(data, 0x26, 0xED01)  # MOV #1,R13
        put16(data, 0x28, 0x22A1)
        states, _, _, _ = _direct_cfg_states_at_targets(
            data, entry, 0x28, {0x28}, LENGTH_ADDRESS
        )
        self.assertEqual(states[0x28], {(True, False, True, True)})

    def test_delay_slot_zero_seed_is_applied_before_branch_target(self):
        data = bytearray(0x100)
        entry = 0x20
        put16(data, 0x20, 0xA002)  # BRA to 0x28
        put16(data, 0x22, 0xEA00)  # MOV #0,R10 in delay slot
        put16(data, 0x24, 0xE101)  # skipped by BRA
        put16(data, 0x26, 0x0009)
        put16(data, 0x28, 0x22A1)
        states, _, _, _ = _direct_cfg_states_at_targets(
            data, entry, 0x28, {0x28}, LENGTH_ADDRESS
        )
        self.assertEqual(states[0x28], {(True, False, False, False)})

    def test_jsr_delay_slot_is_counted_but_callee_effects_are_not_claimed(self):
        data = bytearray(0x100)
        entry = 0x20
        put16(data, 0x20, 0xEA00)
        put16(data, 0x22, 0x430B)  # JSR @R3
        put16(data, 0x24, 0xE101)  # delay slot
        put16(data, 0x26, 0x22A1)
        states, _, calls, direct_calls = _direct_cfg_states_at_targets(
            data, entry, 0x26, {0x26}, LENGTH_ADDRESS
        )
        self.assertEqual(states[0x26], {(True, False, False, False)})
        self.assertEqual(calls, 1)
        self.assertEqual(direct_calls, 0)


if __name__ == "__main__":
    unittest.main()
