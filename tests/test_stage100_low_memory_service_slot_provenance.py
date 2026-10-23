import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage100_low_memory_service_slot_provenance import (
    _bounded_store_candidates,
    _slot_call_pattern_sites,
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


class Stage100LowMemoryServiceSlotTests(unittest.TestCase):
    def test_immediate_pointer_dereference_and_jsr_are_detected(self):
        data = bytearray(0x80)
        slot = 0x06000344
        put_literal_load(data, 0x10, 2, 0x40, slot)
        put16(data, 0x12, 0x6222)  # MOV.L @R2,R2
        put16(data, 0x14, 0x420B)  # JSR @R2
        refs, calls = _slot_call_pattern_sites(bytes(data), slot)
        self.assertEqual(refs, 1)
        self.assertEqual(calls, [0x14])

    def test_argument_setup_between_dereference_and_jsr_is_allowed(self):
        data = bytearray(0x80)
        slot = 0x06000344
        put_literal_load(data, 0x10, 3, 0x40, slot)
        put16(data, 0x12, 0x6332)  # MOV.L @R3,R3
        put16(data, 0x14, 0xE501)  # MOV #1,R5
        put16(data, 0x16, 0xE4FF)  # MOV #-1,R4
        put16(data, 0x18, 0x430B)  # JSR @R3
        refs, calls = _slot_call_pattern_sites(bytes(data), slot)
        self.assertEqual(refs, 1)
        self.assertEqual(calls, [0x18])

    def test_overwriting_target_register_invalidates_call_pattern(self):
        data = bytearray(0x80)
        slot = 0x06000344
        put_literal_load(data, 0x10, 3, 0x40, slot)
        put16(data, 0x12, 0x6332)  # MOV.L @R3,R3
        put16(data, 0x14, 0xE300)  # MOV #0,R3
        put16(data, 0x16, 0x430B)  # JSR @R3, but target provenance is lost
        refs, calls = _slot_call_pattern_sites(bytes(data), slot)
        self.assertEqual(refs, 1)
        self.assertEqual(calls, [])

    def test_exact_byte_store_to_slot_is_detected(self):
        data = bytearray(0x80)
        slot = 0x06000344
        put_literal_load(data, 0x10, 1, 0x40, slot)
        put16(data, 0x12, 0x21D0)  # MOV.B R13,@R1
        self.assertEqual(_bounded_store_candidates(bytes(data), slot, 0x10, 0x40), 1)

    def test_literal_reference_without_dereference_is_not_a_slot_call(self):
        data = bytearray(0x80)
        slot = 0x06000344
        put_literal_load(data, 0x10, 2, 0x40, slot)
        put16(data, 0x12, 0x420B)  # JSR @R2 without loading slot contents
        refs, calls = _slot_call_pattern_sites(bytes(data), slot)
        self.assertEqual(refs, 1)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
