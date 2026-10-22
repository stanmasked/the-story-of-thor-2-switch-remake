import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage78_length_global_alias_audit import (
    SOURCE_FIELD_START,
    _scan_alias_stores_from_load,
)


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


class Stage78LengthGlobalAliasTests(unittest.TestCase):
    def test_long_displacement_store_from_neighbor_base_hits_source_field(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 2, 0x80, SOURCE_FIELD_START - 0x0C)
        put16(data, 0x22, 0x1233)  # MOV.L R3,@(disp=3,R2)
        result = _scan_alias_stores_from_load(
            data, 0x20, SOURCE_FIELD_START - 0x0C, 2, max_span=0x40
        )
        self.assertIn((0x22, 4, "long-displacement", SOURCE_FIELD_START - 0x0C, SOURCE_FIELD_START), result["stores"])
        self.assertFalse(result["unresolved_indexed"])

    def test_word_predecrement_from_adjacent_field_hits_source_field(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 3, 0x80, SOURCE_FIELD_START + 2)
        put16(data, 0x22, 0x2315)  # MOV.W R1,@-R3
        result = _scan_alias_stores_from_load(
            data, 0x20, SOURCE_FIELD_START + 2, 3, max_span=0x40
        )
        self.assertIn((0x22, 2, "predecrement", SOURCE_FIELD_START + 2, SOURCE_FIELD_START), result["stores"])

    def test_byte_displacement_store_can_overlap_source_word(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 1, 0x80, SOURCE_FIELD_START - 8)
        put16(data, 0x22, 0x8128)  # MOV.B R2,@(disp=8,R1)
        result = _scan_alias_stores_from_load(
            data, 0x20, SOURCE_FIELD_START - 8, 1, max_span=0x40
        )
        self.assertIn((0x22, 1, "byte-displacement", SOURCE_FIELD_START - 8, SOURCE_FIELD_START), result["stores"])

    def test_clobbered_base_register_does_not_create_false_alias(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 2, 0x80, SOURCE_FIELD_START - 0x0C)
        put16(data, 0x22, 0xE200)  # MOV #0,R2
        put16(data, 0x24, 0x1233)  # would hit source only if R2 stayed aliased
        result = _scan_alias_stores_from_load(
            data, 0x20, SOURCE_FIELD_START - 0x0C, 2, max_span=0x40
        )
        self.assertFalse(result["stores"])

    def test_unknown_register_index_is_reported_not_assumed_safe(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 2, 0x80, SOURCE_FIELD_START - 0x0C)
        put16(data, 0x22, 0x023F)  # MOV.L R3,@(R0,R2), R0 is unknown
        result = _scan_alias_stores_from_load(
            data, 0x20, SOURCE_FIELD_START - 0x0C, 2, max_span=0x40
        )
        self.assertFalse(result["stores"])
        self.assertEqual(len(result["unresolved_indexed"]), 1)

    def test_branch_delay_slot_store_is_scanned(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 2, 0x80, SOURCE_FIELD_START - 0x0C)
        put16(data, 0x22, 0xA002)  # BRA to 0x2A
        put16(data, 0x24, 0x1233)  # store in the delay slot
        result = _scan_alias_stores_from_load(
            data, 0x20, SOURCE_FIELD_START - 0x0C, 2, max_span=0x40
        )
        self.assertIn((0x24, 4, "long-displacement", SOURCE_FIELD_START - 0x0C, SOURCE_FIELD_START), result["stores"])


if __name__ == "__main__":
    unittest.main()
