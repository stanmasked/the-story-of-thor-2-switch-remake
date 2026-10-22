import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage71_callback_dispatch_chain import (
    CODE_LOAD_ADDRESS,
    TARGET_CALLBACK_ID,
    audit_dispatch_chain,
)

STATUS_ADDRESS = 0x06090020
CALLBACK_TABLE_BASE = 0x06090000
THUNK_TABLE_BASE = CODE_LOAD_ADDRESS + 0x3000
FIRST_STUB_OFFSET = 0x1000
COMMON_INVOKER_OFFSET = 0x1C00


def put16(data, position, value):
    data[position:position + 2] = value.to_bytes(2, "big")


def put32(data, position, value):
    data[position:position + 4] = value.to_bytes(4, "big")


def put_pc_literal_load(data, position, register, literal_position, value):
    pc_base = (position + 4) & ~3
    displacement = (literal_position - pc_base) // 4
    assert (literal_position - pc_base) % 4 == 0
    assert 0 <= displacement <= 0xFF
    put16(data, position, 0xD000 | (register << 8) | displacement)
    put32(data, literal_position, value)


def callback_dispatch_fixture(callback_id=TARGET_CALLBACK_ID):
    data = bytearray(0x4000)

    # Registration call: R5=writer function, R2=registrar helper,
    # and the callback ID is placed in R4 in the JSR delay slot.
    put_pc_literal_load(data, 0x20, 5, 0x380, CODE_LOAD_ADDRESS + 0x100)
    put_pc_literal_load(data, 0x22, 2, 0x384, CODE_LOAD_ADDRESS + 0x200)
    put16(data, 0x24, 0x420B)  # JSR @R2
    put16(data, 0x26, 0xE400 | (callback_id & 0xFF))  # MOV #id,R4

    # The registered writer sets the shared status byte to -1.
    put16(data, 0x100, 0xE2FF)  # MOV #-1,R2
    put_pc_literal_load(data, 0x102, 3, 0x3A4, STATUS_ADDRESS)
    put16(data, 0x104, 0x2320)  # MOV.B R2,@R3

    # Registration dispatcher: table_base + (ID * 4) receives R5.
    dispatcher = 0x200
    put_pc_literal_load(data, dispatcher, 0, 0x400, CALLBACK_TABLE_BASE)
    put16(data, dispatcher + 2, 0x7FF8)
    put_pc_literal_load(data, dispatcher + 4, 2, 0x404, 0x06000300)
    put16(data, dispatcher + 6, 0x6343)  # MOV R4,R3
    put_pc_literal_load(data, dispatcher + 8, 1, 0x408, THUNK_TABLE_BASE)
    put16(data, dispatcher + 10, 0x4308)  # SHLL2 R3
    put16(data, dispatcher + 12, 0x2F42)
    put16(data, dispatcher + 14, 0x1F31)
    put16(data, dispatcher + 16, 0x0356)  # MOV.L R5,@(R0,R3)
    put16(data, dispatcher + 18, 0x6322)
    put16(data, dispatcher + 20, 0x55F1)
    put16(data, dispatcher + 22, 0x351C)
    put16(data, dispatcher + 24, 0x6552)
    put16(data, dispatcher + 26, 0x64F2)
    put16(data, dispatcher + 28, 0x432B)  # JMP @R3
    put16(data, dispatcher + 30, 0x7F08)

    # A 256-entry thunk pointer table, with one six-byte wrapper per signed ID.
    for index in range(256):
        stub_offset = FIRST_STUB_OFFSET + index * 6
        signed_id = index if index < 128 else index - 256
        put16(data, stub_offset, 0xE000 | (signed_id & 0xFF))
        branch_position = stub_offset + 2
        displacement = (COMMON_INVOKER_OFFSET - (branch_position + 4)) // 2
        put16(data, branch_position, 0xA000 | (displacement & 0x0FFF))
        put16(data, stub_offset + 4, 0x4008)  # SHLL2 R0
        put32(data, 0x3000 + index * 4, CODE_LOAD_ADDRESS + stub_offset)

    # Common thunk body reads callback_table_base + (ID * 4) and calls it
    # only when the table entry is non-null.
    common = COMMON_INVOKER_OFFSET
    put_pc_literal_load(data, common, 1, 0x1C40, CALLBACK_TABLE_BASE)
    put16(data, common + 2, 0x021E)  # MOV.L @(R0,R1),R2
    put16(data, common + 4, 0x2228)  # TST R2,R2
    put16(data, common + 6, 0x8907)  # BT skips call if null
    put16(data, common + 8, 0x4F12)
    put16(data, common + 10, 0x4F02)
    put16(data, common + 12, 0x4F22)
    put16(data, common + 14, 0x420B)  # JSR @R2
    put16(data, common + 16, 0x0009)  # NOP delay slot
    put16(data, common + 18, 0x4F26)
    put16(data, common + 20, 0x4F06)
    put16(data, common + 22, 0x4F16)
    put16(data, common + 24, 0x000B)  # RTS
    put16(data, common + 26, 0x0009)
    return data


class Stage71CallbackDispatchChainTests(unittest.TestCase):
    def test_complete_registration_to_indirect_call_chain(self):
        result = audit_dispatch_chain(
            callback_dispatch_fixture(), STATUS_ADDRESS
        )
        self.assertEqual(result["negative_status_writer_candidates"], 1)
        self.assertEqual(result["negative_status_writer_registration_sites"], 1)
        self.assertEqual(result["callback_id_64_registration_sites"], 1)
        self.assertTrue(result["callback_id_64_writer_registered"])
        self.assertTrue(result["callback_registration_stores_by_id_times_four"])
        self.assertTrue(
            result["callback_registration_forwards_thunk_to_runtime_registrar"]
        )
        self.assertEqual(result["wrapper_table_entries_verified"], 256)
        self.assertTrue(result["all_wrapper_stubs_verified"])
        self.assertTrue(result["id64_wrapper_matches_registration_id"])
        self.assertTrue(result["common_invoker_reads_same_callback_table"])
        self.assertTrue(
            result["common_invoker_indirect_call_guarded_for_nonnull"]
        )
        self.assertTrue(result["static_registration_to_indirect_call_chain_verified"])
        self.assertFalse(result["runtime_callback_invocation_confirmed"])

    def test_wrong_registered_id_does_not_claim_id64(self):
        result = audit_dispatch_chain(
            callback_dispatch_fixture(callback_id=65), STATUS_ADDRESS
        )
        self.assertEqual(result["negative_status_writer_registration_sites"], 1)
        self.assertEqual(result["callback_id_64_registration_sites"], 0)
        self.assertFalse(result["static_registration_to_indirect_call_chain_verified"])

    def test_corrupted_id64_thunk_pointer_breaks_chain(self):
        data = callback_dispatch_fixture()
        put32(data, 0x3000 + TARGET_CALLBACK_ID * 4, CODE_LOAD_ADDRESS + FIRST_STUB_OFFSET)
        result = audit_dispatch_chain(data, STATUS_ADDRESS)
        self.assertFalse(result["all_wrapper_stubs_verified"])
        self.assertFalse(result["static_registration_to_indirect_call_chain_verified"])

    def test_different_invoker_table_breaks_callback_table_match(self):
        data = callback_dispatch_fixture()
        put32(data, 0x1C40, 0x06091000)
        result = audit_dispatch_chain(data, STATUS_ADDRESS)
        self.assertFalse(result["common_invoker_reads_same_callback_table"])
        self.assertFalse(result["static_registration_to_indirect_call_chain_verified"])

    def test_missing_status_address_fails_closed(self):
        result = audit_dispatch_chain(callback_dispatch_fixture(), None)
        self.assertFalse(result["callback_id_64_writer_registered"])
        self.assertFalse(result["static_registration_to_indirect_call_chain_verified"])

    def test_report_contains_no_private_addresses_or_instruction_positions(self):
        result = audit_dispatch_chain(
            callback_dispatch_fixture(), STATUS_ADDRESS
        )
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(hex(STATUS_ADDRESS), rendered)
        self.assertNotIn(hex(CALLBACK_TABLE_BASE), rendered)
        self.assertNotIn(hex(THUNK_TABLE_BASE), rendered)
        self.assertNotIn("callback_entry", rendered)
        self.assertNotIn("dispatcher_entry", rendered)
        self.assertFalse(result["private_addresses_or_code_offsets_emitted"])


if __name__ == "__main__":
    unittest.main()
