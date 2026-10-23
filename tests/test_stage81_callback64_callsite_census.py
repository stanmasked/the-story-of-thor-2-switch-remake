import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage81_callback64_callsite_census import (
    classify_callback_calls,
    literal_backed_jsr_sites,
)

CALLBACK_ADDRESS = 0x0600444E
WRITER_ADDRESS = 0x060085A8


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


def call_fixture():
    data = bytearray(0x240)
    # Writer JSR followed by callback ID64 JSR.
    literal_load(data, 0x20, 1, 0x180, WRITER_ADDRESS)
    put16(data, 0x22, 0x410B)
    put16(data, 0x24, 0x0009)
    literal_load(data, 0x26, 2, 0x184, CALLBACK_ADDRESS)
    put16(data, 0x28, 0x420B)
    put16(data, 0x2A, 0x0009)
    # Separate callback whose delay slot assigns the length field.
    literal_load(data, 0x50, 3, 0x188, CALLBACK_ADDRESS)
    put16(data, 0x52, 0x430B)
    put16(data, 0x54, 0x2211)  # MOV.W R1,@R2 in delay slot
    # An unclassified callback site.
    literal_load(data, 0x70, 4, 0x18C, CALLBACK_ADDRESS)
    put16(data, 0x72, 0x440B)
    put16(data, 0x74, 0x0009)
    return data


class Stage81CallbackCensusTests(unittest.TestCase):
    def test_literal_backed_jsr_sites_are_found(self):
        data = call_fixture()
        self.assertEqual(
            literal_backed_jsr_sites(data, CALLBACK_ADDRESS),
            [0x28, 0x52, 0x72],
        )

    def test_writer_and_copy_patterns_classified(self):
        result = classify_callback_calls(
            [0x28, 0x52], [0x22], {0x52}, {0x52}
        )
        self.assertEqual(result["callback_sites_followed_by_writer_predecessor"], 1)
        self.assertEqual(result["callback_sites_with_length_field_delay_store"], 1)
        self.assertEqual(result["callback_sites_copying_known_global_source"], 1)
        self.assertEqual(result["callback_sites_unclassified_by_known_patterns"], 0)
        self.assertTrue(result["all_detected_callback_sites_match_a_known_pattern"])

    def test_unclassified_site_prevents_full_pattern_claim(self):
        result = classify_callback_calls(
            [0x28, 0x52, 0x72], [0x22], {0x52}, {0x52}
        )
        self.assertEqual(result["callback_sites_unclassified_by_known_patterns"], 1)
        self.assertFalse(result["all_detected_callback_sites_match_a_known_pattern"])

    def test_writer_without_pair_is_counted(self):
        result = classify_callback_calls([0x28], [0x22, 0x40], set(), set())
        self.assertEqual(result["writer_sites_without_immediate_callback_pair"], 1)

    def test_length_copy_without_writer_is_counted(self):
        result = classify_callback_calls([0x52], [], {0x52}, {0x52})
        self.assertEqual(result["callback_sites_not_preceded_by_writer"], 1)
        self.assertEqual(result["callback_sites_copying_known_global_source"], 1)

    def test_wrong_writer_position_does_not_pair(self):
        result = classify_callback_calls([0x2A], [0x22], set(), set())
        self.assertEqual(result["callback_sites_followed_by_writer_predecessor"], 0)

    def test_empty_callback_set_fails_closed(self):
        result = classify_callback_calls([], [], set(), set())
        self.assertFalse(result["all_detected_callback_sites_match_a_known_pattern"])

    def test_output_is_aggregate_only(self):
        result = classify_callback_calls([0x28, 0x52], [0x22], {0x52}, {0x52})
        rendered = json.dumps(result)
        for value in (hex(CALLBACK_ADDRESS), hex(WRITER_ADDRESS), "0x28", "0x52"):
            self.assertNotIn(value, rendered)
        self.assertFalse(result["source_global_initialized_before_all_copy_reads_proven"])

    def test_callback_target_mismatch_not_recognized(self):
        data = call_fixture()
        self.assertEqual(literal_backed_jsr_sites(data, CALLBACK_ADDRESS + 2), [])

    def test_bad_jsr_opcode_not_recognized(self):
        data = call_fixture()
        put16(data, 0x28, 0x4208)
        self.assertEqual(
            literal_backed_jsr_sites(data, CALLBACK_ADDRESS),
            [0x52, 0x72],
        )


if __name__ == "__main__":
    unittest.main()
