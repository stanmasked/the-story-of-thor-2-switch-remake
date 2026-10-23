import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage79_expanded_store_alias_audit import scan_store_aliases

TARGET = 0x0609BA7C


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | delta // 4)
    put32(data, literal_pos, value)


def fixture(pointer_value=TARGET):
    data = bytearray(0x240)
    literal_load(data, 0x20, 2, 0x180, pointer_value)
    return data


class Stage79ExpandedStoreAliasTests(unittest.TestCase):
    def test_direct_word_store(self):
        data = fixture()
        put16(data, 0x22, 0x2231)  # MOV.W R3,@R2
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 1)
        self.assertEqual(result["store_candidates_by_mode"], {"indirect": 1})

    def test_add_immediate_alias(self):
        data = fixture(TARGET - 4)
        put16(data, 0x22, 0x7204)  # ADD #4,R2
        put16(data, 0x24, 0x2231)
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 1)
        self.assertEqual(result["store_candidates_requiring_pointer_arithmetic_or_alias"], 1)

    def test_register_alias_copy(self):
        data = fixture()
        put16(data, 0x22, 0x6233)  # MOV R3,R2 overwrites alias; no store should match
        put16(data, 0x24, 0x2231)
        self.assertEqual(scan_store_aliases(data)["exact_target_store_candidates"], 0)
        # Reverse copy from R2 into R4, then write through R4.
        data = fixture()
        put16(data, 0x22, 0x6423)  # MOV R2,R4
        put16(data, 0x24, 0x4431)  # MOV.W R3,@R4
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 1)
        self.assertEqual(result["store_candidates_requiring_pointer_arithmetic_or_alias"], 1)

    def test_predecrement_word_store_hits_target(self):
        data = fixture(TARGET + 2)
        put16(data, 0x22, 0x2255)  # MOV.W R5,@-R2
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 1)
        self.assertEqual(result["store_candidates_by_mode"], {"predecrement": 1})

    def test_word_displacement_store(self):
        data = fixture(TARGET - 8)
        put16(data, 0x22, 0x8294)  # MOV.W R1,@(4*2,R2)
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 1)
        self.assertEqual(result["store_candidates_by_mode"], {"displacement_word": 1})

    def test_long_displacement_store(self):
        data = fixture(TARGET - 8)
        put16(data, 0x22, 0x1232)  # MOV.L R3,@(2*4,R2)
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 1)
        self.assertEqual(result["store_candidates_by_mode"], {"displacement_long": 1})

    def test_indexed_store_is_reported_as_unresolved(self):
        data = fixture()
        put16(data, 0x22, 0x0235)  # MOV.W R3,@(R0,R2), R0 unknown
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 0)
        self.assertEqual(result["unresolved_indexed_store_candidates"], 1)

    def test_branch_delay_slot_store_is_checked(self):
        data = fixture()
        put16(data, 0x22, 0xA000)  # BRA
        put16(data, 0x24, 0x2231)  # delay-slot MOV.W R3,@R2
        result = scan_store_aliases(data)
        self.assertEqual(result["exact_target_store_candidates"], 1)

    def test_pointer_clobber_stops_linear_alias(self):
        data = fixture()
        put16(data, 0x22, 0xE201)  # MOV #1,R2
        put16(data, 0x24, 0x2231)
        self.assertEqual(scan_store_aliases(data)["exact_target_store_candidates"], 0)

    def test_output_is_aggregate_only_and_not_exhaustive(self):
        rendered = json.dumps(scan_store_aliases(fixture()))
        self.assertNotIn(hex(TARGET), rendered)
        self.assertNotIn("0x22", rendered)
        result = scan_store_aliases(fixture())
        self.assertFalse(result["all_store_writers_resolved"])
        self.assertFalse(result["arbitrary_register_arithmetic_and_interprocedural_aliases_excluded"])


if __name__ == "__main__":
    unittest.main()
