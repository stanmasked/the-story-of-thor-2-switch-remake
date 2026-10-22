"""Synthetic-only Stage49 trace tests. No private ISO, VRAM dump or instructions."""
import copy
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage46_vdp1_submit_gate import fixture as program_fixture
from stage49_sh2_vdp1_trace_contract import (
    MAX_EVENTS, _validate_event, find_private_roles, expected_events,
    compare_trace, load_jsonl,
)

PROGRAM = program_fixture()
SOURCE = bytes(range(64))


def manifest(records=None, **overrides):
    m = {
        "schema_version": 1,
        "status_before": -1,
        "status_after": 0,
        "pending_count_before": 2,
        "pending_count_after": 0,
        "descriptors": records if records is not None else [
            {"destination_index": 0, "copy_count": 1},
            {"destination_index": 8, "copy_count": 1},
        ],
    }
    m.update(overrides)
    return m


def valid_events(m=None, src=SOURCE):
    return expected_events(PROGRAM, m if m is not None else manifest(), src)


class Stage49TraceTests(unittest.TestCase):
    def test_synthetic_role_pc_resolution(self):
        roles = find_private_roles(PROGRAM)
        self.assertEqual(len(roles["stores"]), 8)
        self.assertEqual(len(set(roles["stores"])), 8)

    def test_complete_two_command_trace(self):
        r = compare_trace(PROGRAM, manifest(), valid_events(), SOURCE)
        self.assertTrue(r["full_offline_trace_contract_matches"])
        self.assertEqual(r["expected_32bit_vram_stores"], 16)
        self.assertEqual(r["expected_trace_events"], 20)

    def test_no_source_values_not_claimed(self):
        r = compare_trace(PROGRAM, manifest(), valid_events(), None)
        self.assertTrue(r["static_opcode_pc_and_write_order_match"])
        self.assertIsNone(r["source_word_values_match"])
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_no_original_capture_attested(self):
        r = compare_trace(PROGRAM, manifest(), valid_events(), SOURCE)
        self.assertFalse(r["emulator_trace_authenticity_verified"])
        self.assertFalse(r["sh2_runtime_execution_proven"])
        self.assertFalse(r["handler_39_link_proven"])

    def test_wrong_gate_pc(self):
        events = valid_events()
        events[0]["pc"] += 2
        r = compare_trace(PROGRAM, manifest(), events, SOURCE)
        self.assertEqual(r["mismatched_static_program_counters"], 1)
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_wrong_call_pc(self):
        e = valid_events()
        e[1]["pc"] ^= 2
        self.assertEqual(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_static_program_counters"], 1)

    def test_corrupt_one_store_pc(self):
        e = valid_events()
        e[3]["pc"] += 2
        self.assertEqual(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_static_program_counters"], 1)

    def test_corrupt_one_dest(self):
        e = valid_events()
        e[2]["dest"] += 4
        r = compare_trace(PROGRAM, manifest(), e, SOURCE)
        self.assertEqual(r["mismatched_vram_destinations"], 1)
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_corrupt_one_word(self):
        e = valid_events()
        e[2]["value"] ^= 0x01
        r = compare_trace(PROGRAM, manifest(), e, SOURCE)
        self.assertEqual(r["mismatched_32bit_values"], 1)
        self.assertTrue(r["static_opcode_pc_and_write_order_match"])
        self.assertFalse(r["source_word_values_match"])

    def test_swapped_word_events(self):
        e = valid_events()
        e[2], e[3] = e[3], e[2]
        r = compare_trace(PROGRAM, manifest(), e, SOURCE)
        self.assertGreater(r["mismatched_static_program_counters"], 0)

    def test_missing_one_store_event(self):
        e = valid_events()
        e.pop(4)
        r = compare_trace(PROGRAM, manifest(), e, SOURCE)
        self.assertGreater(r["mismatched_roles_or_event_count"], 0)
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_extra_event(self):
        e = valid_events()
        e.append(copy.deepcopy(e[-1]))
        self.assertGreater(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_roles_or_event_count"], 0)

    def test_replaced_role(self):
        e = valid_events()
        e[2] = copy.deepcopy(e[1])
        r = compare_trace(PROGRAM, manifest(), e, SOURCE)
        self.assertGreater(r["mismatched_roles_or_event_count"], 0)

    def test_wrong_initial_status(self):
        e = valid_events()
        e[0]["status"] = 0
        self.assertEqual(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_register_or_flag_observations"], 1)

    def test_wrong_gate_counter(self):
        e = valid_events()
        e[0]["pending_count"] = 1
        self.assertEqual(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_register_or_flag_observations"], 1)

    def test_wrong_r5_at_jsr(self):
        e = valid_events()
        e[1]["r5"] = 1
        self.assertEqual(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_register_or_flag_observations"], 1)

    def test_wrong_r5_at_copy_rts(self):
        e = valid_events()
        e[-2]["r5"] = 1
        self.assertEqual(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_register_or_flag_observations"], 1)

    def test_wrong_submit_final_flag(self):
        e = valid_events()
        e[-1]["status"] = 1
        self.assertEqual(compare_trace(PROGRAM, manifest(), e, SOURCE)[
            "mismatched_register_or_flag_observations"], 1)

    def test_bad_static_program_rejected(self):
        with self.assertRaises(ValueError):
            find_private_roles(bytes(len(PROGRAM)))

    def test_one_copy_per_descriptor(self):
        records = [{"destination_index": 32, "copy_count": 1}]
        m = manifest(records, pending_count_before=1)
        src = bytes(range(32))
        r = compare_trace(PROGRAM, m, valid_events(m, src), src)
        self.assertTrue(r["full_offline_trace_contract_matches"])
        self.assertEqual(r["expected_32bit_vram_stores"], 8)

    def test_multicopy_single_descriptor(self):
        records = [{"destination_index": 12, "copy_count": 2}]
        m = manifest(records, pending_count_before=2)
        r = compare_trace(PROGRAM, m, valid_events(m), SOURCE)
        self.assertTrue(r["full_offline_trace_contract_matches"])
        self.assertFalse(r["pending_budget_equals_command_count"] is False)

    def test_count_mismatch_not_accepted(self):
        m = manifest(pending_count_before=1)
        r = compare_trace(PROGRAM, m, valid_events(m), SOURCE)
        self.assertFalse(r["pending_budget_equals_command_count"])
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_nonnegative_gate_flag_not_accepted(self):
        m = manifest(status_before=0)
        r = compare_trace(PROGRAM, m, valid_events(m), SOURCE)
        self.assertFalse(r["initial_negative_flag_and_nonzero_pending"])
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_missing_post_reset_not_accepted(self):
        m = manifest(pending_count_after=1)
        r = compare_trace(PROGRAM, m, valid_events(m), SOURCE)
        self.assertFalse(r["final_flag_and_pending_count_are_zero"])
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_trace_source_length_required(self):
        with self.assertRaises(ValueError):
            expected_events(PROGRAM, manifest(), SOURCE[:-1])

    def test_trace_command_cap(self):
        m = manifest([{"destination_index": 0, "copy_count": 4097}], pending_count_before=4097)
        with self.assertRaises(ValueError):
            expected_events(PROGRAM, m)

    def test_wrong_schema_event_fields(self):
        with self.assertRaises(ValueError):
            _validate_event({"role": "store", "pc": 1, "dest": 2})

    def test_invalid_event_role_rejected(self):
        with self.assertRaises(ValueError):
            _validate_event({"role": "wrong", "pc": 1})

    def test_nonstring_role_rejected(self):
        with self.assertRaises(ValueError):
            _validate_event({"role": ["store"], "pc": 1, "dest": 2, "value": 3})

    def test_inferred_load_base_not_runtime_verified(self):
        r = compare_trace(PROGRAM, manifest(), valid_events(), SOURCE)
        self.assertFalse(r["sh2_load_base_verified_in_live_emulator"])

    def test_string_pc_rejected(self):
        with self.assertRaises(ValueError):
            _validate_event({"role": "jsr", "pc": "0x100", "r5": 1})

    def test_bool_pc_rejected(self):
        with self.assertRaises(ValueError):
            _validate_event({"role": "jsr", "pc": True, "r5": 1})

    def test_bad_status_range(self):
        with self.assertRaises(ValueError):
            _validate_event({"role": "gate", "pc": 1, "status": -129, "pending_count": 1})

    def test_bad_r5_range(self):
        with self.assertRaises(ValueError):
            _validate_event({"role": "jsr", "pc": 1, "r5": 65536})

    def test_empty_event_list_reports_missing(self):
        r = compare_trace(PROGRAM, manifest(), [], SOURCE)
        self.assertEqual(r["mismatched_roles_or_event_count"], r["expected_trace_events"])
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_absent_source_cannot_validate_word_values(self):
        e = valid_events()
        e[2]["value"] = 0
        r = compare_trace(PROGRAM, manifest(), e, None)
        self.assertIsNone(r["mismatched_32bit_values"])
        self.assertFalse(r["full_offline_trace_contract_matches"])

    def test_no_original_program_address_in_report(self):
        e = valid_events()
        r = compare_trace(PROGRAM, manifest(), e, SOURCE)
        payload = json.dumps(r)
        roles = find_private_roles(PROGRAM)
        for pc in [roles["gate"], roles["jsr"], *roles["stores"],
                   roles["copy_rts"], roles["submit_rts"]]:
            self.assertNotIn(hex(pc), payload)
            self.assertNotIn(str(pc), payload)
        for key in ('"pc"', '"dest"', '"value"'):
            self.assertNotIn(key, payload)

    def test_jsonl_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.jsonl"
            p.write_text("".join(json.dumps(e) + "\n" for e in valid_events()), encoding="utf-8")
            e = load_jsonl(p)
            self.assertEqual(len(e), 20)
            self.assertTrue(compare_trace(PROGRAM, manifest(), e, SOURCE)[
                "full_offline_trace_contract_matches"])

    def test_jsonl_duplicate_key_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.jsonl"
            p.write_text('{"role":"jsr","pc":1,"pc":2,"r5":1}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_jsonl(p)

    def test_jsonl_unknown_fields_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.jsonl"
            p.write_text('{"role":"jsr","pc":1,"r5":1,"leak":"no"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_jsonl(p)

    def test_jsonl_oversized_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.jsonl"
            with p.open("wb") as f:
                f.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                load_jsonl(p)

    def test_trace_length_cap(self):
        e = valid_events()
        e.extend([copy.deepcopy(e[-1])] * (MAX_EVENTS + 1))
        with self.assertRaises(ValueError):
            compare_trace(PROGRAM, manifest(), e, SOURCE)


if __name__ == "__main__":
    unittest.main()
