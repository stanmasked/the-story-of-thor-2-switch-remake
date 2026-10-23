import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage80_source_field_init_order_cfg import (
    _cfg_store_coverage,
    _count_followed_by_callback,
    _writer_call_sites,
)

ENTRY = 0x10
WRITER_ENTRY = 0x20
CALLBACK_ADDRESS = 0x0600444E


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


def caller_fixture():
    data = bytearray(0x180)
    literal_load(data, 0x20, 1, 0x100, CODE_LOAD_ADDRESS + WRITER_ENTRY)
    put16(data, 0x22, 0x410B)  # JSR @R1
    put16(data, 0x24, 0x0009)  # NOP delay slot
    literal_load(data, 0x26, 2, 0x104, CALLBACK_ADDRESS)
    put16(data, 0x28, 0x420B)  # JSR @R2
    put16(data, 0x2A, 0x0009)
    return data


class Stage80SourceFieldOrderTests(unittest.TestCase):
    def test_rts_after_store_is_proven(self):
        data = bytearray(0x80)
        put16(data, ENTRY, 0x0009)
        put16(data, ENTRY + 2, 0x000B)  # RTS
        result = _cfg_store_coverage(data, ENTRY, 0x40, {ENTRY})
        self.assertEqual(result["writer_rts_exit_states_after_source_store"], 1)
        self.assertEqual(result["writer_rts_exit_states_without_source_store"], 0)
        self.assertTrue(result["writer_all_observed_exit_states_follow_source_store"])

    def test_rts_without_store_fails_closed(self):
        data = bytearray(0x80)
        put16(data, ENTRY, 0x000B)
        result = _cfg_store_coverage(data, ENTRY, 0x40, set())
        self.assertEqual(result["writer_rts_exit_states_without_source_store"], 1)
        self.assertFalse(result["writer_all_observed_exit_states_follow_source_store"])

    def test_bra_delay_slot_store_counts(self):
        data = bytearray(0x80)
        put16(data, ENTRY, 0xA002)  # BRA to ENTRY+8
        put16(data, ENTRY + 2, 0x0009)
        put16(data, ENTRY + 8, 0x000B)
        result = _cfg_store_coverage(data, ENTRY, 0x40, {ENTRY + 2})
        self.assertEqual(result["writer_source_store_sites_reached"], 1)
        self.assertTrue(result["writer_all_observed_exit_states_follow_source_store"])

    def test_conditional_path_without_store_prevents_global_claim(self):
        data = bytearray(0x80)
        put16(data, ENTRY, 0x8B02)  # BF to ENTRY+8; no delay slot
        put16(data, ENTRY + 2, 0x0009)
        put16(data, ENTRY + 4, 0x000B)
        put16(data, ENTRY + 8, 0x000B)
        result = _cfg_store_coverage(data, ENTRY, 0x40, {ENTRY + 2})
        self.assertGreaterEqual(result["writer_rts_exit_states_without_source_store"], 1)
        self.assertFalse(result["writer_all_observed_exit_states_follow_source_store"])

    def test_tail_branch_after_store_is_counted(self):
        data = bytearray(0x80)
        put16(data, ENTRY, 0x0009)
        put16(data, ENTRY + 2, 0xA01D)  # tail BRA beyond bound
        put16(data, ENTRY + 4, 0x0009)
        result = _cfg_store_coverage(data, ENTRY, 0x40, {ENTRY})
        self.assertEqual(result["writer_tail_exit_states_after_source_store"], 1)
        self.assertEqual(result["writer_tail_exit_states_without_source_store"], 0)

    def test_literal_backed_writer_call_then_callback(self):
        data = caller_fixture()
        sites = _writer_call_sites(data, WRITER_ENTRY)
        self.assertEqual(sites, [0x22])
        result = _count_followed_by_callback(data, sites, CALLBACK_ADDRESS)
        self.assertEqual(result["writer_then_callback_id64_jsr_sequences"], 1)
        self.assertTrue(result["all_observed_writer_calls_followed_by_callback_id64"])
        self.assertFalse(result["global_callback_order_proven"])

    def test_wrong_callback_target_does_not_match(self):
        data = caller_fixture()
        result = _count_followed_by_callback(data, [0x22], CALLBACK_ADDRESS + 4)
        self.assertEqual(result["writer_then_callback_id64_jsr_sequences"], 0)
        self.assertFalse(result["all_observed_writer_calls_followed_by_callback_id64"])

    def test_intervening_instruction_breaks_immediate_pair(self):
        data = caller_fixture()
        put16(data, 0x26, 0x0009)
        result = _count_followed_by_callback(data, [0x22], CALLBACK_ADDRESS)
        self.assertEqual(result["writer_then_callback_id64_jsr_sequences"], 0)

    def test_no_callsite_means_no_order_claim(self):
        result = _count_followed_by_callback(bytearray(0x40), [], CALLBACK_ADDRESS)
        self.assertFalse(result["all_observed_writer_calls_followed_by_callback_id64"])

    def test_aggregate_output_has_no_addresses(self):
        result = {
            **_cfg_store_coverage(bytearray(0x80), ENTRY, 0x40, set()),
            **_count_followed_by_callback(caller_fixture(), [0x22], CALLBACK_ADDRESS),
        }
        rendered = json.dumps(result)
        self.assertNotIn(hex(CALLBACK_ADDRESS), rendered)
        self.assertNotIn(hex(ENTRY), rendered)
        self.assertFalse(result["global_callback_order_proven"])


if __name__ == "__main__":
    unittest.main()
