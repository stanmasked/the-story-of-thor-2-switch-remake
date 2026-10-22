import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage73_memory_path_audit import (
    FIRST_TARGET_OPCODES,
    HELPER_OPCODES,
    MEMMOVE_OPCODES,
    SECOND_TARGET_DISPATCHER_OPCODES,
    audit_helper_transfer,
)

CALLBACK_ENTRY = 0x100
HELPER_ENTRY = 0x400
MEMMOVE_ENTRY = 0x800
FIRST_TARGET_ENTRY = 0x900
SECOND_TARGET_ENTRY = 0xA00
HANDLER_ENTRIES = (0xD00, 0xD80, 0xE00)
COUNT_FIELD = 0x0609651C
SUBMIT_COUNT_FIELD = 0x0609651E
SOURCE_BUFFER = 0x06097A70
VDP1_VRAM_BASE = 0x25C00000


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


def fixture(source=SOURCE_BUFFER, destination=VDP1_VRAM_BASE):
    data = bytearray(0xF00)

    # Callback's signed word is loaded from the field immediately before the
    # submit gate's separate pending-record count. Length is count*32 + 2.
    put_pc_literal_load(data, CALLBACK_ENTRY + 0x18, 2, CALLBACK_ENTRY + 0x240, COUNT_FIELD)
    put16(data, CALLBACK_ENTRY + 0x1A, 0x21E0)
    put16(data, CALLBACK_ENTRY + 0x1C, 0x6621)
    put16(data, CALLBACK_ENTRY + 0x1E, 0x4608)
    put_pc_literal_load(data, CALLBACK_ENTRY + 0x20, 5, CALLBACK_ENTRY + 0x244, source)
    put16(data, CALLBACK_ENTRY + 0x22, 0x4608)
    put_pc_literal_load(data, CALLBACK_ENTRY + 0x24, 4, CALLBACK_ENTRY + 0x248, destination)
    put16(data, CALLBACK_ENTRY + 0x26, 0x4600)
    put_pc_literal_load(data, CALLBACK_ENTRY + 0x28, 3, CALLBACK_ENTRY + 0x24C, CODE_LOAD_ADDRESS + HELPER_ENTRY)
    put16(data, CALLBACK_ENTRY + 0x2A, 0x430B)
    put16(data, CALLBACK_ENTRY + 0x2C, 0x7602)

    for offset, opcode in HELPER_OPCODES.items():
        put16(data, HELPER_ENTRY + offset, opcode)
    put16(data, HELPER_ENTRY + 0x5C, 0xFF0F)
    put16(data, HELPER_ENTRY + 0x5E, 0xFFFF)
    for offset, value in {
        0x60: 0x20200000,
        0x64: 0x20300000,
        0x68: 0x00200000,
        0x6C: 0x00300000,
        0x70: 0x06088514,
        0x74: CODE_LOAD_ADDRESS + MEMMOVE_ENTRY,
        0x104: 0x00000100,
        0x106: 0xFF0F,
        0x108: 0x06088514,
        0x10C: 0x0608850C,
        0x110: 0x06088510,
        0x114: 0x25A00000,
        0x118: 0x25FE0000,
        0x11C: 0x05A00000,
        0x120: 0x05FE0000,
        0x124: CODE_LOAD_ADDRESS + FIRST_TARGET_ENTRY,
        0x128: CODE_LOAD_ADDRESS + SECOND_TARGET_ENTRY,
        0x12C: 0x06088515,
    }.items():
        if offset in (0x104, 0x106):
            put16(data, HELPER_ENTRY + offset, value)
        else:
            put32(data, HELPER_ENTRY + offset, value)

    for offset, opcode in MEMMOVE_OPCODES.items():
        put16(data, MEMMOVE_ENTRY + offset, opcode)

    for index, opcode in enumerate(FIRST_TARGET_OPCODES):
        put16(data, FIRST_TARGET_ENTRY + 2 * index, opcode)

    for offset, opcode in SECOND_TARGET_DISPATCHER_OPCODES.items():
        put16(data, SECOND_TARGET_ENTRY + offset, opcode)
    for offset, opcode in {
        0x24: 0x60D3, 0x26: 0xDC08, 0x28: 0xA01A, 0x2A: 0xEE4B,
        0x2C: 0xDC07, 0x2E: 0xA017, 0x30: 0xEE4A, 0x32: 0xDC07,
        0x34: 0xA014, 0x36: 0xEE49, 0x54: 0x8800, 0x56: 0x89E6,
        0x58: 0x8801, 0x5A: 0x89E7, 0x5C: 0x8802, 0x5E: 0x89E8,
        0x98: 0x932B, 0x9A: 0xD01D, 0x9C: 0x0D36,
        0xCC: 0x000B, 0xCE: 0x6EF6,
    }.items():
        put16(data, SECOND_TARGET_ENTRY + offset, opcode)
    for offset, value in {
        0x38: 0xFF0F, 0x3A: 0xFFFF,
        0x3C: 0x25FE0000, 0x40: 0x25FE0004, 0x44: 0x25FE0008,
        0x48: CODE_LOAD_ADDRESS + HANDLER_ENTRIES[0],
        0x4C: CODE_LOAD_ADDRESS + HANDLER_ENTRIES[1],
        0x50: CODE_LOAD_ADDRESS + HANDLER_ENTRIES[2],
        0x110: 0x25FE0010,
    }.items():
        if offset in (0x38, 0x3A):
            put16(data, SECOND_TARGET_ENTRY + offset, value)
        else:
            put32(data, SECOND_TARGET_ENTRY + offset, value)

    for handler in HANDLER_ENTRIES:
        put16(data, handler, 0x4F22)
        put16(data, handler + 2, 0x7FF8)

    return data


class Stage73MemoryPathAuditTests(unittest.TestCase):
    def test_main_ram_source_selects_dma_state_path_not_memmove(self):
        result = audit_helper_transfer(
            fixture(), CALLBACK_ENTRY, SUBMIT_COUNT_FIELD
        )
        self.assertFalse(result["callback_count_pointer_matches_submit_pending_count"])
        self.assertTrue(result["callback_length_field_is_adjacent_to_submit_pending_count"])
        self.assertTrue(result["callback_length_formula_is_signed_word_times_32_plus_2"])
        self.assertTrue(result["callback_sequence_contains_no_local_count_bounds_check"])
        self.assertTrue(result["callback_destination_is_vdp1_vram_base"])
        self.assertTrue(result["helper_range_dispatch_signature_verified"])
        self.assertTrue(result["helper_special_path_selected_for_callback_arguments"])
        self.assertFalse(result["helper_generic_memmove_path_selected_for_callback_arguments"])
        self.assertTrue(result["special_path_sets_transfer_state_flag"])
        self.assertTrue(result["special_path_stores_destination_and_byte_length"])
        self.assertTrue(result["destination_matches_primary_bbus_window"])
        self.assertTrue(result["special_path_has_two_call_sites"])
        self.assertTrue(result["generic_bytewise_overlap_safe_memmove_signature_verified"])
        self.assertTrue(result["generic_memmove_forward_and_backward_loops_verified"])
        self.assertTrue(result["generic_memmove_handles_equal_pointers_and_zero_length"])
        self.assertTrue(result["first_special_target_is_verified_leaf_helper"])
        self.assertTrue(result["second_special_target_is_verified_dma_dispatcher"])
        self.assertTrue(result["scu_dma_register_block_literals_verified"])
        self.assertTrue(result["three_in_image_transfer_handlers_verified"])
        self.assertTrue(result["special_path_call_return_contract_resolved"])
        self.assertFalse(result["actual_vdp1_memory_write_proven"])
        self.assertFalse(result["runtime_callback_invocation_confirmed"])

    def test_low_alias_source_selects_generic_memmove_branch(self):
        result = audit_helper_transfer(
            fixture(source=0x00280000), CALLBACK_ENTRY, SUBMIT_COUNT_FIELD
        )
        self.assertTrue(result["helper_range_dispatch_signature_verified"])
        self.assertTrue(result["helper_generic_memmove_path_selected_for_callback_arguments"])
        self.assertFalse(result["helper_special_path_selected_for_callback_arguments"])

    def test_exact_field_match_is_distinct_from_adjacent_field(self):
        result = audit_helper_transfer(
            fixture(), CALLBACK_ENTRY, COUNT_FIELD
        )
        self.assertTrue(result["callback_count_pointer_matches_submit_pending_count"])
        self.assertFalse(result["callback_length_field_is_adjacent_to_submit_pending_count"])

    def test_bad_length_shift_fails_closed(self):
        data = fixture()
        put16(data, CALLBACK_ENTRY + 0x26, 0x4608)
        result = audit_helper_transfer(data, CALLBACK_ENTRY, SUBMIT_COUNT_FIELD)
        self.assertFalse(result["callback_length_formula_is_signed_word_times_32_plus_2"])
        self.assertFalse(result["callback_sequence_contains_no_local_count_bounds_check"])

    def test_changed_dispatch_bound_breaks_route_claim(self):
        data = fixture()
        put32(data, HELPER_ENTRY + 0x6C, 0x00300004)
        result = audit_helper_transfer(data, CALLBACK_ENTRY, SUBMIT_COUNT_FIELD)
        self.assertFalse(result["helper_range_dispatch_signature_verified"])
        self.assertFalse(result["helper_special_path_selected_for_callback_arguments"])

    def test_changed_transfer_state_store_breaks_store_claim(self):
        data = fixture()
        put16(data, HELPER_ENTRY + 0x80, 0x2320)
        result = audit_helper_transfer(data, CALLBACK_ENTRY, SUBMIT_COUNT_FIELD)
        self.assertFalse(result["special_path_stores_destination_and_byte_length"])

    def test_corrupted_dma_handler_pointer_breaks_dispatch_claim(self):
        data = fixture()
        put32(data, HELPER_ENTRY + 0x128, 0x06000010)
        result = audit_helper_transfer(data, CALLBACK_ENTRY, SUBMIT_COUNT_FIELD)
        self.assertFalse(result["special_path_has_two_call_sites"])
        self.assertFalse(result["second_special_target_is_verified_dma_dispatcher"])

    def test_output_redacts_addresses_offsets_and_instruction_positions(self):
        result = audit_helper_transfer(
            fixture(), CALLBACK_ENTRY, SUBMIT_COUNT_FIELD
        )
        rendered = json.dumps(result, sort_keys=True)
        for private_value in (
            hex(COUNT_FIELD), hex(SUBMIT_COUNT_FIELD), hex(SOURCE_BUFFER),
            hex(VDP1_VRAM_BASE), hex(CODE_LOAD_ADDRESS + HELPER_ENTRY),
        ):
            self.assertNotIn(private_value, rendered)
        self.assertNotIn("helper_entry", rendered)
        self.assertNotIn("callback_entry", rendered)
        self.assertFalse(result["private_addresses_or_code_offsets_emitted"])


if __name__ == "__main__":
    unittest.main()
