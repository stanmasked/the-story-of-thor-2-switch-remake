import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage95_dispatch_slot_cross_module_audit import OPTIONAL_TARGETS
from stage97_optional_target_provenance_cfg import (
    _function_window,
    _literal_target_sites,
    _map_targets_with_bases,
    _summarize_target_sites,
    _target_use_after_literal,
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


def put_prologue(data, pos):
    put16(data, pos, 0x2FE6)
    put16(data, pos + 2, 0x2FD6)
    put16(data, pos + 4, 0x2FC6)
    put16(data, pos + 6, 0x4F22)


def reachable_call_fixture(target=OPTIONAL_TARGETS[0]):
    data = bytearray(0x100)
    put_prologue(data, 0x10)
    put_literal_load(data, 0x18, 0, 0x80, target)
    put16(data, 0x1A, 0x402B)  # JSR @R0
    put16(data, 0x1C, 0x0009)  # delay-slot NOP
    return bytes(data)


class Stage97OptionalTargetProvenanceTests(unittest.TestCase):
    def test_reachable_literal_reference_and_indirect_call_are_counted(self):
        data = reachable_call_fixture()
        summary = _summarize_target_sites({"0TH2.BIN": data}, OPTIONAL_TARGETS[0])
        self.assertEqual(summary["raw_literal_reference_candidate_count"], 1)
        self.assertEqual(summary["reference_sites_in_prologue_windows"], 1)
        self.assertEqual(summary["reachable_reference_sites"], 1)
        self.assertEqual(summary["reachable_indirect_use_candidate_count"], 1)
        self.assertEqual(summary["reachable_indirect_use_candidates_by_mode"], {"indirect_call": 1})

    def test_target_register_alias_followed_by_jsr_is_recognized(self):
        data = bytearray(reachable_call_fixture())
        put16(data, 0x1A, 0x6103)  # MOV R0,R1
        put16(data, 0x1C, 0x412B)  # JSR @R1
        put16(data, 0x1E, 0x0009)
        self.assertEqual(_target_use_after_literal(bytes(data), 0x18, 0, 0x80), "indirect_call")

    def test_target_register_overwrite_stops_use_classification(self):
        data = bytearray(reachable_call_fixture())
        put_literal_load(data, 0x1A, 0, 0x84, 0x0600026C)
        put16(data, 0x1C, 0x402B)
        self.assertIsNone(_target_use_after_literal(bytes(data), 0x18, 0, 0x80))

    def test_unreachable_literal_candidate_after_unconditional_branch_is_not_reachable(self):
        data = bytearray(0x100)
        put_prologue(data, 0x10)
        put16(data, 0x18, 0xA006)  # BRA 0x28
        put16(data, 0x1A, 0x0009)
        put_literal_load(data, 0x1C, 0, 0x80, OPTIONAL_TARGETS[0])
        put16(data, 0x1E, 0x402B)
        summary = _summarize_target_sites({"0TH2.BIN": bytes(data)}, OPTIONAL_TARGETS[0])
        self.assertEqual(summary["raw_literal_reference_candidate_count"], 1)
        self.assertEqual(summary["reference_sites_in_prologue_windows"], 1)
        self.assertEqual(summary["reachable_reference_sites"], 0)
        self.assertEqual(summary["reference_sites_in_window_but_unreachable"], 1)
        self.assertEqual(summary["reachable_indirect_use_candidate_count"], 0)

    def test_literal_reference_in_delay_slot_is_not_misread_as_following_call(self):
        data = bytearray(0x100)
        put_prologue(data, 0x10)
        put16(data, 0x18, 0xA006)  # BRA 0x28
        put_literal_load(data, 0x1A, 0, 0x80, OPTIONAL_TARGETS[0])
        put16(data, 0x1C, 0x402B)  # not the branch continuation
        summary = _summarize_target_sites({"0TH2.BIN": bytes(data)}, OPTIONAL_TARGETS[0])
        self.assertEqual(summary["reachable_reference_sites"], 0)
        self.assertEqual(summary["reference_sites_reachable_only_as_delay_slots"], 1)
        self.assertEqual(summary["reachable_indirect_use_candidate_count"], 0)

    def test_literal_candidate_without_prologue_window_is_unmapped(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 0, 0x80, OPTIONAL_TARGETS[0])
        summary = _summarize_target_sites({"MONS.BIN": bytes(data)}, OPTIONAL_TARGETS[0])
        self.assertEqual(summary["raw_literal_reference_candidate_count"], 1)
        self.assertEqual(summary["reference_sites_without_prologue_window"], 1)
        self.assertEqual(summary["reachable_reference_sites"], 0)

    def test_function_window_stops_before_next_prologue(self):
        data_size = 0x500
        prologues = [0x10, 0x100]
        self.assertEqual(_function_window(data_size, 0x80, prologues), (0x10, 0x100))
        self.assertEqual(_function_window(data_size, 0x100, prologues), (0x100, 0x500))
        self.assertIsNone(_function_window(data_size, 0x450, [0x10]))

    def test_unique_load_base_maps_target_to_exact_prologue(self):
        low = bytearray(0x400)
        target = OPTIONAL_TARGETS[0]
        base = target - 0xF8
        put_prologue(low, 0xF8)
        result = _map_targets_with_bases(bytes(low), [base], (target,))
        self.assertTrue(result["th2_low_load_destination_unique_candidate_available"])
        self.assertTrue(result["optional_targets"]["1"]["maps_inside_th2_low_under_unique_load_base"])
        self.assertTrue(result["optional_targets"]["1"]["mapped_offset_matches_generic_prologue"])
        self.assertFalse(result["mapping_is_runtime_address_space_proof"])

    def test_conflicting_load_bases_do_not_choose_a_mapping(self):
        low = bytearray(0x400)
        target = OPTIONAL_TARGETS[0]
        put_prologue(low, 0xF8)
        result = _map_targets_with_bases(bytes(low), [target - 0xF8, target - 0x100], (target,))
        self.assertFalse(result["th2_low_load_destination_unique_candidate_available"])
        self.assertFalse(result["optional_targets"]["1"]["maps_inside_th2_low_under_unique_load_base"])
        self.assertFalse(result["optional_targets"]["1"]["mapped_offset_matches_generic_prologue"])

    def test_out_of_range_target_does_not_match_module_prologue(self):
        low = bytearray(0x100)
        target = OPTIONAL_TARGETS[0]
        result = _map_targets_with_bases(bytes(low), [target - 0x200], (target,))
        self.assertFalse(result["optional_targets"]["1"]["maps_inside_th2_low_under_unique_load_base"])
        self.assertFalse(result["optional_targets"]["1"]["mapped_offset_matches_generic_prologue"])

    def test_summary_contains_no_raw_addresses_or_offsets(self):
        data = reachable_call_fixture()
        summary = _summarize_target_sites({"0TH2.BIN": data}, OPTIONAL_TARGETS[0])
        rendered = repr(summary)
        self.assertNotIn("0x", rendered)
        self.assertNotIn(str(OPTIONAL_TARGETS[0]), rendered)
        self.assertNotIn("instruction_offset", rendered)


if __name__ == "__main__":
    unittest.main()
