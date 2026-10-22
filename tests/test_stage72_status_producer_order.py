import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage72_status_producer_order import (
    VDP1_VRAM_BASE,
    audit_callback_body,
)

STATUS_ADDRESS = 0x06091020
CALLBACK_ENTRY = 0x100


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


def callback_body_fixture():
    data = bytearray(0x240)
    entry = CALLBACK_ENTRY
    put_pc_literal_load(data, entry + 0x0C, 3, 0x180, STATUS_ADDRESS)
    put16(data, entry + 0x0E, 0x6230)  # MOV.B @R3,R2 (sign-extends)
    put16(data, entry + 0x10, 0x4215)  # CMP/PL R2
    put16(data, entry + 0x12, 0x8F0F)  # BF/S skips producer when negative
    put16(data, entry + 0x14, 0xEE01)  # delay slot: MOV #1,R14
    put_pc_literal_load(data, entry + 0x16, 1, 0x184, 0x06091100)
    put_pc_literal_load(data, entry + 0x18, 2, 0x188, 0x06091110)
    put16(data, entry + 0x1A, 0x21E0)  # MOV.B R14,@R1
    put16(data, entry + 0x1C, 0x6621)  # MOV.W @R2+,R6
    put16(data, entry + 0x1E, 0x4608)  # SHLL2 R6
    put_pc_literal_load(data, entry + 0x20, 5, 0x18C, 0x06092000)
    put16(data, entry + 0x22, 0x4608)  # SHLL2 R6
    put_pc_literal_load(data, entry + 0x24, 4, 0x190, VDP1_VRAM_BASE)
    put16(data, entry + 0x26, 0x4600)  # SHLL R6
    put_pc_literal_load(data, entry + 0x28, 3, 0x194, 0x06093000)
    put16(data, entry + 0x2A, 0x430B)  # JSR @R3
    put16(data, entry + 0x2C, 0x7602)  # delay slot: ADD #2,R6
    put16(data, entry + 0x2E, 0xE2FF)  # MOV #-1,R2
    put_pc_literal_load(data, entry + 0x30, 3, 0x198, STATUS_ADDRESS)
    put16(data, entry + 0x32, 0x2320)  # MOV.B R2,@R3
    put_pc_literal_load(data, entry + 0x34, 1, 0x19C, 0x06094000)
    return data


class Stage72StatusProducerOrderTests(unittest.TestCase):
    def test_signed_status_guard_and_helper_before_negative_store(self):
        result = audit_callback_body(
            callback_body_fixture(), CALLBACK_ENTRY, STATUS_ADDRESS
        )
        self.assertTrue(result["callback_body_pattern_verified"])
        self.assertTrue(result["reads_gate_status_as_signed_byte"])
        self.assertTrue(result["negative_status_skips_producer_block"])
        self.assertTrue(result["nonnegative_status_calls_pre_status_helper"])
        self.assertTrue(result["helper_receives_vdp1_vram_base"])
        self.assertTrue(result["same_status_byte_written_after_helper"])
        self.assertTrue(result["callback_body_handshake_verified"])
        self.assertFalse(result["runtime_callback_invocation_confirmed"])

    def test_different_status_store_breaks_handshake(self):
        data = callback_body_fixture()
        put32(data, 0x198, STATUS_ADDRESS + 1)
        result = audit_callback_body(data, CALLBACK_ENTRY, STATUS_ADDRESS)
        self.assertFalse(result["same_status_byte_written_after_helper"])
        self.assertFalse(result["callback_body_handshake_verified"])

    def test_wrong_branch_target_does_not_claim_negative_status_guard(self):
        data = callback_body_fixture()
        put16(data, CALLBACK_ENTRY + 0x12, 0x8F0E)
        result = audit_callback_body(data, CALLBACK_ENTRY, STATUS_ADDRESS)
        self.assertFalse(result["negative_status_skips_producer_block"])
        self.assertFalse(result["callback_body_handshake_verified"])

    def test_missing_helper_call_breaks_side_effect_order(self):
        data = callback_body_fixture()
        put16(data, CALLBACK_ENTRY + 0x2A, 0x0009)
        result = audit_callback_body(data, CALLBACK_ENTRY, STATUS_ADDRESS)
        self.assertFalse(result["nonnegative_status_calls_pre_status_helper"])
        self.assertFalse(result["callback_body_handshake_verified"])

    def test_helper_must_receive_vdp1_vram_base(self):
        data = callback_body_fixture()
        put32(data, 0x190, 0x06090000)
        result = audit_callback_body(data, CALLBACK_ENTRY, STATUS_ADDRESS)
        self.assertFalse(result["helper_receives_vdp1_vram_base"])
        self.assertFalse(result["callback_body_handshake_verified"])

    def test_missing_status_address_fails_closed(self):
        result = audit_callback_body(callback_body_fixture(), CALLBACK_ENTRY, None)
        self.assertFalse(result["callback_body_pattern_verified"])
        self.assertFalse(result["callback_body_handshake_verified"])

    def test_output_redacts_addresses_and_positions(self):
        result = audit_callback_body(
            callback_body_fixture(), CALLBACK_ENTRY, STATUS_ADDRESS
        )
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(hex(STATUS_ADDRESS), rendered)
        self.assertNotIn(hex(VDP1_VRAM_BASE), rendered)
        self.assertNotIn("callback_entry", rendered)
        self.assertFalse(result["private_addresses_or_code_offsets_emitted"])


if __name__ == "__main__":
    unittest.main()
