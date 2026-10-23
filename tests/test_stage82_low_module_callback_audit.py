import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage82_low_module_callback_audit import (
    SERVICE_SLOT_A,
    SERVICE_SLOT_B,
    count_field_delay_store_sites,
    summarize_module,
)

CALLBACK = 0x0600444E
WRITER = 0x060085A8
COUNT = 0x0609651C
SOURCE = 0x0609BA7C


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


def module_fixture():
    data = bytearray(0x240)
    # Length field load -> callback load -> JSR -> count-field store in delay slot.
    literal_load(data, 0x20, 2, 0x180, COUNT)
    literal_load(data, 0x22, 3, 0x184, CALLBACK)
    put16(data, 0x24, 0x430B)
    put16(data, 0x26, 0x2211)
    # Writer call followed by callback.
    literal_load(data, 0x40, 1, 0x188, WRITER)
    put16(data, 0x42, 0x410B)
    put16(data, 0x44, 0x0009)
    literal_load(data, 0x46, 3, 0x18C, CALLBACK)
    put16(data, 0x48, 0x430B)
    put16(data, 0x4A, 0x0009)
    # Unpaired callback with NOP delay slot.
    literal_load(data, 0x60, 4, 0x190, CALLBACK)
    put16(data, 0x62, 0x440B)
    put16(data, 0x64, 0x0009)
    # Callback with an unknown non-NOP delay slot.
    literal_load(data, 0x80, 5, 0x194, CALLBACK)
    put16(data, 0x82, 0x450B)
    put16(data, 0x84, 0xE101)
    return data


class Stage82LowModuleAuditTests(unittest.TestCase):
    def test_count_field_delay_store_recognized(self):
        data = module_fixture()
        self.assertEqual(
            count_field_delay_store_sites(data, CALLBACK, COUNT), {0x24}
        )

    def test_module_classifies_writer_pair_and_copy_site(self):
        result = summarize_module(module_fixture(), WRITER, CALLBACK, COUNT)
        self.assertEqual(result["literal_backed_writer_jsr_sites"], 1)
        self.assertEqual(result["literal_backed_callback_id64_jsr_sites"], 4)
        self.assertEqual(result["writer_then_callback_pairs"], 1)
        self.assertEqual(result["callback_calls_with_count_field_delay_store"], 1)
        self.assertEqual(result["unpaired_callback_calls_with_nop_delay_slot"], 1)
        self.assertEqual(result["callback_calls_with_other_unclassified_delay_slot"], 1)
        self.assertFalse(result["callback_census_exhaustive"])

    def test_wrong_count_register_does_not_match_delay_store(self):
        data = module_fixture()
        put16(data, 0x26, 0x2311)  # store base R3, not count-pointer R2
        self.assertEqual(count_field_delay_store_sites(data, CALLBACK, COUNT), set())

    def test_wrong_callback_target_is_not_counted(self):
        self.assertEqual(
            count_field_delay_store_sites(module_fixture(), CALLBACK + 4, COUNT),
            set(),
        )

    def test_writer_pair_requires_immediate_call_distance(self):
        data = module_fixture()
        put16(data, 0x46, 0x0009)  # clobber callback literal-load instruction
        result = summarize_module(data, WRITER, CALLBACK, COUNT)
        self.assertEqual(result["writer_then_callback_pairs"], 0)

    def test_raw_slot_reference_is_not_a_literal_load_proof(self):
        data = bytearray(0x240)
        put32(data, 0x150, SERVICE_SLOT_A)
        result = summarize_module(data, WRITER, CALLBACK, COUNT)
        self.assertEqual(result["service_slot_a_raw_big_endian_occurrences"], 1)
        self.assertEqual(result["service_slot_a_pc_literal_refs"], 0)
        self.assertEqual(result["service_slot_b_raw_big_endian_occurrences"], 0)

    def test_no_direct_source_literal_in_fixture(self):
        result = summarize_module(module_fixture(), WRITER, CALLBACK, COUNT)
        self.assertEqual(result["pc_literal_refs_to_source_global"], 0)

    def test_output_redacts_targets_and_offsets(self):
        result = summarize_module(module_fixture(), WRITER, CALLBACK, COUNT)
        rendered = json.dumps(result)
        for value in (hex(CALLBACK), hex(WRITER), hex(COUNT), "0x24", "0x48"):
            self.assertNotIn(value, rendered)

    def test_empty_module_fails_closed(self):
        result = summarize_module(bytearray(0x80), WRITER, CALLBACK, COUNT)
        self.assertEqual(result["literal_backed_callback_id64_jsr_sites"], 0)
        self.assertFalse(result["all_literal_backed_callback_sites_fit_observed_patterns"])


if __name__ == "__main__":
    unittest.main()
