import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage99_callee_register_preservation_audit import (
    _callee_r13_preservation,
    _pre_store_calls,
    _resolve_call_target,
    _save_restore_proven,
)


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def put_literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | (delta // 4))
    put32(data, literal_pos, value)


class Stage99CalleeRegisterPreservationTests(unittest.TestCase):
    def test_literal_backed_jsr_target_is_resolved(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 3, 0x40, CODE_LOAD_ADDRESS + 0x80)
        put16(data, 0x12, 0x430B)  # JSR @R3
        self.assertEqual(
            _resolve_call_target(bytes(data), 0x10, 0x12),
            {"kind": "literal", "value": CODE_LOAD_ADDRESS + 0x80},
        )

    def test_dereferenced_pointer_slot_remains_unresolved(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 2, 0x40, 0x06000344)
        put16(data, 0x12, 0x6222)  # MOV.L @R2,R2
        put16(data, 0x14, 0x420B)  # JSR @R2
        self.assertEqual(
            _resolve_call_target(bytes(data), 0x10, 0x14),
            {"kind": "pointer_slot", "value": 0x06000344},
        )

    def test_direct_bsr_target_is_resolved(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0xB002)
        self.assertEqual(
            _resolve_call_target(bytes(data), 0x10, 0x10),
            {"kind": "direct", "value": 0x18},
        )

    def test_r13_save_restore_must_dominate_return(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0x2FD6)  # MOV.L R13,@-R15
        put16(data, 0x12, 0x4F22)  # STS.L PR,@-R15
        put16(data, 0x14, 0x4F26)  # LDS.L @R15+,PR
        put16(data, 0x16, 0x6DF6)  # MOV.L @R15+,R13
        put16(data, 0x18, 0x000B)  # RTS
        put16(data, 0x1A, 0x0009)  # delay slot
        self.assertTrue(_save_restore_proven(bytes(data), 0x10, 0x1C))
        self.assertTrue(_callee_r13_preservation(bytes(data), 0x10))

    def test_unrestored_direct_r13_write_is_not_preserved(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0xED01)  # MOV #1,R13
        put16(data, 0x12, 0x000B)  # RTS
        put16(data, 0x14, 0x0009)
        self.assertFalse(_save_restore_proven(bytes(data), 0x10, 0x16))
        self.assertFalse(_callee_r13_preservation(bytes(data), 0x10))

    def test_final_call_whose_delay_slot_is_store_is_excluded(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 3, 0x40, CODE_LOAD_ADDRESS + 0x80)
        put16(data, 0x12, 0x430B)  # first call
        put16(data, 0x14, 0x0009)
        put16(data, 0x16, 0xB001)  # second call
        put16(data, 0x18, 0x0009)
        put16(data, 0x1A, 0xB001)  # final call
        put16(data, 0x1C, 0x21D0)  # MOV.B R13,@R1 in final call delay slot
        calls = _pre_store_calls(bytes(data), 0x10, 0x40, 0x1C)
        self.assertEqual(len(calls), 2)
        self.assertEqual([item["kind"] for item in calls], ["JSR", "BSR"])

    def test_output_contract_has_no_raw_address_fields(self):
        data = bytearray(0x40)
        put_literal_load(data, 0x10, 2, 0x30, 0x06000344)
        put16(data, 0x12, 0x6222)
        put16(data, 0x14, 0x420B)
        result = _resolve_call_target(bytes(data), 0x10, 0x14)
        self.assertEqual(result["kind"], "pointer_slot")
        self.assertEqual(result["value"], 0x06000344)


if __name__ == "__main__":
    unittest.main()
