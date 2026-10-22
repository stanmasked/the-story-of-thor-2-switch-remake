import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage18_writer_guard_flow import be16
from stage73_memory_path_audit import FIRST_TARGET_OPCODES, SECOND_TARGET_DISPATCHER_OPCODES
from stage74_scu_dma_handler_audit import (
    COMMAND_BUFFER_POINTER,
    SCU_D0C,
    SCU_D0EN,
    SCU_D0R,
    SCU_D0W,
    _audit_command_count,
    _audit_terminator,
    audit_dma_chain,
)

CODE_LOAD_ADDRESS = 0x06004000
COUNT_ADDRESS = 0x0609651C
HELPER_ENTRY = 0x100
FIRST_ENTRY = 0x300
DISPATCHER_ENTRY = FIRST_ENTRY + 0x60
HANDLERS = (0x600, 0x670, 0x6E0)


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


def dma_fixture():
    data = bytearray(0x1000)
    put16(data, HELPER_ENTRY + 0x08, 0xED01)
    put_pc_literal_load(
        data, HELPER_ENTRY + 0xD8, 3, HELPER_ENTRY + 0x100,
        CODE_LOAD_ADDRESS + FIRST_ENTRY,
    )
    put16(data, HELPER_ENTRY + 0xDA, 0x430B)
    put16(data, HELPER_ENTRY + 0xDC, 0x7404)
    put_pc_literal_load(
        data, HELPER_ENTRY + 0xDE, 3, HELPER_ENTRY + 0x104,
        CODE_LOAD_ADDRESS + DISPATCHER_ENTRY,
    )
    put16(data, HELPER_ENTRY + 0xE0, 0x430B)
    put16(data, HELPER_ENTRY + 0xE2, 0x64E3)

    for index, opcode in enumerate(FIRST_TARGET_OPCODES):
        put16(data, FIRST_ENTRY + index * 2, opcode)

    for offset, opcode in SECOND_TARGET_DISPATCHER_OPCODES.items():
        put16(data, DISPATCHER_ENTRY + offset, opcode)
    put32(data, DISPATCHER_ENTRY + 0x3C, SCU_D0R)
    put32(data, DISPATCHER_ENTRY + 0x40, SCU_D0W)
    put32(data, DISPATCHER_ENTRY + 0x44, SCU_D0C)

    for offset, literal_offset, handler in zip(
        (0x26, 0x2C, 0x32), (0x48, 0x4C, 0x50), HANDLERS
    ):
        put_pc_literal_load(
            data, DISPATCHER_ENTRY + offset, 12,
            DISPATCHER_ENTRY + literal_offset,
            CODE_LOAD_ADDRESS + handler,
        )

    for offset, opcode in ((0x56, 0x89E6), (0x5A, 0x89E7), (0x5E, 0x89E8)):
        put16(data, DISPATCHER_ENTRY + offset, opcode)
    put16(data, DISPATCHER_ENTRY + 0xA4, 0x4D08)
    put16(data, DISPATCHER_ENTRY + 0xA6, 0x4D08)
    put16(data, DISPATCHER_ENTRY + 0xA8, 0x4D00)
    put16(data, DISPATCHER_ENTRY + 0xAA, 0x932B)
    put16(data, DISPATCHER_ENTRY + 0xAC, 0xD01D)
    put16(data, DISPATCHER_ENTRY + 0xAE, 0x0D36)
    put16(data, DISPATCHER_ENTRY + 0x104, 0x0101)
    put32(data, DISPATCHER_ENTRY + 0x124, SCU_D0EN)

    from stage74_scu_dma_handler_audit import HANDLER_COMMON
    for index, handler in enumerate(HANDLERS):
        for offset, opcode in HANDLER_COMMON.items():
            put16(data, handler + offset, opcode)
        tag = 0x4B - index
        put16(data, handler + 0x2C, 0xE400 + tag)
        put16(data, handler + 0x38, 0xE400 + tag)
        put32(data, handler + 0x5C, 0x06088668 + index)
        put32(data, handler + 0x60, 0x06000300)
        put32(data, handler + 0x64, 0x06088650 + index * 4)
        put32(data, handler + 0x68, 0x06000310)
        put32(data, handler + 0x6C, 0x0608865C + index * 4)
    return data


def count_fixture(include_unresolved_assignment=False):
    data = bytearray(0x240)
    # One append path: signed-safe CMP/GE limit, then count += 1 unless capped.
    put_pc_literal_load(data, 0x20, 4, 0x80, COUNT_ADDRESS)
    put16(data, 0x40, 0x6141)  # MOV.W @R4,R1
    put16(data, 0x42, 0x9321)  # MOV.W @(PC),R3 -> 508
    put16(data, 0x44, 0x3133)  # CMP/GE R3,R1
    put16(data, 0x46, 0x8905)  # BT skips increment at 0x52
    put16(data, 0x4E, 0x6241)  # MOV.W @R4,R2
    put16(data, 0x50, 0x7201)  # ADD #1,R2
    put16(data, 0x52, 0x2421)  # MOV.W R2,@R4
    put16(data, 0x88, 508)

    # One fixed initializer: clear the count, then increment once.
    put16(data, 0xBC, 0xE500)  # MOV #0,R5
    put_pc_literal_load(data, 0xC0, 6, 0x140, COUNT_ADDRESS)
    put16(data, 0xC4, 0x2651)  # MOV.W R5,@R6 (reset)
    put16(data, 0xCC, 0x6261)  # MOV.W @R6,R2
    put16(data, 0xCE, 0x7201)  # ADD #1,R2
    put16(data, 0xD0, 0x2621)  # MOV.W R2,@R6
    if include_unresolved_assignment:
        put_pc_literal_load(data, 0xE0, 5, 0x150, COUNT_ADDRESS)
        put16(data, 0xE4, 0x2521)  # MOV.W R2,@R5, source provenance unknown
    return data


def terminator_fixture():
    data = bytearray(0x100)
    entry = 0x20
    put_pc_literal_load(data, entry, 4, 0x60, COMMAND_BUFFER_POINTER)
    put_pc_literal_load(data, entry + 2, 2, 0x64, 0x00008000)
    for offset, opcode in {
        0x04: 0x6342, 0x06: 0x2321, 0x08: 0x6342, 0x0A: 0x7304,
        0x0C: 0x000B, 0x0E: 0x2432,
    }.items():
        put16(data, entry + offset, opcode)
    return data, entry


class Stage74SCUDMAAuditTests(unittest.TestCase):
    def test_three_handlers_and_level1_enable_start_are_verified(self):
        result = audit_dma_chain(dma_fixture(), 0x80, HELPER_ENTRY)
        self.assertTrue(result["helper_call_targets_resolved"])
        self.assertTrue(result["source_destination_count_register_block_pattern_verified"])
        self.assertTrue(result["dispatcher_selects_three_in_image_handlers"])
        self.assertTrue(result["three_handler_bodies_verified"])
        self.assertTrue(result["three_handler_argument_tags_verified"])
        self.assertTrue(result["three_handler_indirect_service_slots_verified"])
        self.assertTrue(result["three_handler_parameter_globals_verified"])
        self.assertTrue(result["three_handler_state_byte_clear_pattern_verified"])
        self.assertFalse(result["handlers_write_scu_registers_directly"])
        self.assertTrue(result["dispatcher_d1en_start_write_verified"])
        self.assertTrue(result["dispatcher_r13_offset_dataflow_verified"])
        self.assertTrue(result["dma_level1_enable_start_value_verified"])
        self.assertFalse(result["runtime_handler_choice_confirmed"])
        self.assertFalse(result["runtime_dma_completion_confirmed"])

    def test_corrupted_handler_pointer_fails_dispatch_audit(self):
        data = dma_fixture()
        put32(data, DISPATCHER_ENTRY + 0x48, 0x00001234)
        result = audit_dma_chain(data, 0x80, HELPER_ENTRY)
        self.assertFalse(result["dispatcher_selects_three_in_image_handlers"])
        self.assertFalse(result["three_handler_bodies_verified"])

    def test_wrong_handler_tag_fails_variant_check(self):
        data = dma_fixture()
        put16(data, HANDLERS[1] + 0x2C, 0xE44B)
        result = audit_dma_chain(data, 0x80, HELPER_ENTRY)
        self.assertFalse(result["three_handler_argument_tags_verified"])

    def test_wrong_d1en_start_value_fails(self):
        data = dma_fixture()
        put16(data, DISPATCHER_ENTRY + 0x104, 0x0001)
        result = audit_dma_chain(data, 0x80, HELPER_ENTRY)
        self.assertTrue(result["dispatcher_d1en_start_write_verified"])
        self.assertFalse(result["dma_level1_enable_start_value_verified"])

    def test_guarded_and_zero_seeded_count_updates(self):
        result = _audit_command_count(count_fixture(), COUNT_ADDRESS)
        self.assertEqual(result["command_count_increment_sites_guarded_by_limit"], 1)
        self.assertEqual(result["command_count_guard_limits"], [508])
        self.assertEqual(result["command_count_increment_sites_after_local_zero_reset"], 1)
        self.assertEqual(result["command_count_increment_sites_without_guard_or_zero_reset"], 0)
        self.assertEqual(result["command_count_unresolved_register_assignment_sites"], 0)
        self.assertTrue(result["command_count_global_upper_bound_proven"])

    def test_unresolved_count_assignment_prevents_global_bound_claim(self):
        result = _audit_command_count(
            count_fixture(include_unresolved_assignment=True), COUNT_ADDRESS
        )
        self.assertEqual(result["command_count_unresolved_register_assignment_sites"], 1)
        self.assertFalse(result["command_count_global_upper_bound_proven"])

    def test_halfword_marker_and_four_byte_reservation_are_distinguished(self):
        data, _ = terminator_fixture()
        result = _audit_terminator(data, count_formula_verified=True)
        self.assertTrue(result["halfword_end_marker_helper_signature_verified"])
        self.assertTrue(result["end_marker_is_written_as_16_bit_0x8000"])
        self.assertTrue(result["end_marker_pointer_reservation_is_four_bytes"])
        self.assertTrue(result["callback_plus_two_matches_marker_payload_bytes"])
        self.assertTrue(result["reserved_padding_excluded_from_transfer_length"])

    def test_wrong_terminator_store_width_fails(self):
        data, entry = terminator_fixture()
        put16(data, entry + 0x06, 0x2322)
        result = _audit_terminator(data, count_formula_verified=True)
        self.assertFalse(result["halfword_end_marker_helper_signature_verified"])

    def test_aggregate_dma_output_does_not_emit_private_addresses(self):
        rendered = json.dumps(audit_dma_chain(dma_fixture(), 0x80, HELPER_ENTRY))
        for private_value in (
            hex(COUNT_ADDRESS), hex(COMMAND_BUFFER_POINTER), hex(SCU_D0R),
            hex(SCU_D0W), hex(SCU_D0C), hex(SCU_D0EN),
        ):
            self.assertNotIn(private_value, rendered)
        self.assertNotIn("dispatcher_entry", rendered)
        self.assertNotIn("handler_entry", rendered)


if __name__ == "__main__":
    unittest.main()
