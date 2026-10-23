import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage88_filename_helper_callchain import (
    _has_frame_prologue,
    _inside_candidate_interval,
    _resolve_call_sites,
    summarize_function,
)

CALLBACK = 0x0600444E


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


def simple_prologue(data, pos):
    put16(data, pos, 0x2FE6)
    put16(data, pos + 2, 0x4F22)


def extended_prologue(data, pos):
    put16(data, pos, 0x2FE6)
    put16(data, pos + 2, 0x2FD6)
    put16(data, pos + 4, 0x2FC6)
    put16(data, pos + 6, 0x4F22)


def call_fixture(target=None, clobber=False, call_count=2):
    data = bytearray(0x300)
    simple_prologue(data, 0x20)
    simple_prologue(data, 0xC0)
    target = CODE_LOAD_ADDRESS + 0xC0 if target is None else target
    literal_load(data, 0x24, 3, 0x200, target)
    put16(data, 0x26, 0xE300 if clobber else 0x0009)
    put16(data, 0x28, 0x430B)
    put16(data, 0x2A, 0x0009)
    if call_count > 1:
        literal_load(data, 0x3A, 2, 0x204, target)
        put16(data, 0x3C, 0x0009)
        put16(data, 0x3E, 0x420B)
        put16(data, 0x40, 0x0009)
    return data


class Stage88FilenameHelperCallchainTests(unittest.TestCase):
    def test_simple_frame_prologue_recognized(self):
        data = bytearray(0x100)
        simple_prologue(data, 0x20)
        self.assertTrue(_has_frame_prologue(data, 0x20))

    def test_extended_frame_prologue_recognized(self):
        data = bytearray(0x100)
        extended_prologue(data, 0x20)
        self.assertTrue(_has_frame_prologue(data, 0x20))

    def test_missing_frame_prologue_rejected(self):
        self.assertFalse(_has_frame_prologue(bytes(0x100), 0x20))

    def test_call_targets_resolve_and_deduplicate(self):
        data = call_fixture()
        calls = _resolve_call_sites(data, 0x20, 0x80)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(target == CODE_LOAD_ADDRESS + 0xC0 for _, target in calls))
        result = summarize_function(data, 0x20, 0x80)
        self.assertEqual(result["jsr_like_sites"], 2)
        self.assertEqual(result["jsr_sites_with_nearby_literal_target"], 2)
        self.assertEqual(result["unique_literal_targets"], 1)
        self.assertEqual(result["unique_targets_with_frame_prologue_signature"], 1)

    def test_target_register_clobber_prevents_resolution(self):
        data = call_fixture(clobber=True, call_count=1)
        calls = _resolve_call_sites(data, 0x20, 0x80)
        self.assertEqual(calls, [(0x28, None)])

    def test_unresolvable_target_does_not_claim_full_resolution(self):
        data = bytearray(0x100)
        put16(data, 0x20, 0x430B)
        result = summarize_function(data, 0x20, 0x40)
        self.assertEqual(result["jsr_like_sites"], 1)
        self.assertEqual(result["jsr_sites_with_nearby_literal_target"], 0)
        self.assertFalse(result["all_jsr_literal_targets_resolved"])

    def test_no_calls_fails_closed(self):
        result = summarize_function(bytes(0x100), 0x20, 0x80)
        self.assertEqual(result["jsr_like_sites"], 0)
        self.assertFalse(result["all_jsr_literal_targets_resolved"])
        self.assertFalse(result["first_jsr_target_resolved"])

    def test_internal_entry_is_not_misclassified_as_prologue(self):
        data = bytearray(0x200)
        extended_prologue(data, 0x20)
        self.assertTrue(_inside_candidate_interval(len(data), 0x60, [0x20, 0x100]))
        self.assertFalse(_inside_candidate_interval(len(data), 0x100, [0x20, 0x100]))

    def test_out_of_executable_target_is_not_counted_as_internal_code(self):
        data = call_fixture(target=0x07000000, call_count=1)
        result = summarize_function(data, 0x20, 0x80)
        self.assertEqual(result["unique_targets_inside_main_executable"], 0)
        self.assertEqual(result["unique_targets_with_frame_prologue_signature"], 0)

    def test_r1_linear_preservation_is_reported_without_overclaiming(self):
        data = call_fixture()
        result = summarize_function(data, 0x20, 0x80)
        self.assertTrue(result["r1_not_explicitly_written_before_first_jsr"])
        self.assertTrue(result["first_jsr_target_resolved"])

    def test_aggregate_output_redacts_addresses_and_offsets(self):
        result = summarize_function(call_fixture(), 0x20, 0x80)
        rendered = json.dumps(result)
        for value in ("0x20", "0x28", "0xC0", hex(CALLBACK), hex(CODE_LOAD_ADDRESS)):
            self.assertNotIn(value, rendered)


if __name__ == "__main__":
    unittest.main()
