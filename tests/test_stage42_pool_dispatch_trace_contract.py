"""Stage42 synthetic-only tests for SH-2 dispatch entries and trace contract."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage41_pool_readers import fixture as stage41_fixture, put
from test_stage36_dispatch_index_audit import BASE, CELL
from stage42_pool_dispatch_trace_contract import (
    ENTRY_PROLOGUES, ENTRY_DISTANCE, exact_entry_prologue,
    direct_reference_counts, signed12, scan_dispatch_entries,
    validate_trace_contract,
)

START_ENTRY = BASE - ENTRY_DISTANCE["table_start"]
CELL_ENTRY = CELL - ENTRY_DISTANCE["selected_cell"]


def fixture(mutation=None, with_base=True, with_cell=True):
    data = bytearray(stage41_fixture())
    for name, enable, entry in (
            ("table_start", with_base, START_ENTRY),
            ("selected_cell", with_cell, CELL_ENTRY)):
        if enable:
            for i, op in enumerate(ENTRY_PROLOGUES[name]):
                put(data, entry + 2*i, op)
    if mutation:
        put(data, *mutation)
    return bytes(data)


def sample_events(anchor="table_start"):
    return [
        {"kind": "slot-selected", "slot": 3, "object_id": "object-A"},
        {"kind": "object-cloned", "slot": 3, "object_id": "object-A",
         "copied_bytes": 276},
        {"kind": "index-written", "slot": 3, "object_id": "object-A",
         "field_offset": 126, "index": 38},
        {"kind": "table-dispatched", "slot": 3, "object_id": "object-A",
         "anchor": anchor, "index": 38 if anchor == "table_start" else 0,
         "selected_slot_one_based": 39},
    ]


class Stage42Tests(unittest.TestCase):
    def scan(self, **kwargs):
        return scan_dispatch_entries(fixture(**kwargs))

    def test_both_dispatch_entries(self):
        self.assertEqual(self.scan()["entry_prologues_copy_R4_to_R14"], 2)

    def test_two_indexed_jmps(self):
        self.assertEqual(self.scan()["matched_indexed_dispatches"], 2)

    def test_both_entry_forms(self):
        self.assertEqual(self.scan()["prologue_forms"],
                         ["selected_cell", "table_start"])

    def test_shared_pool_found(self):
        self.assertTrue(self.scan()["prerequisite_43_slot_pool_found"])

    def test_table_found(self):
        self.assertTrue(self.scan()["prerequisite_68_pointer_table_found"])

    def test_pool_size(self):
        self.assertEqual(self.scan()["pool_records"], 43)
        self.assertEqual(self.scan()["pool_stride_bytes"], 276)

    def test_dispatch_table_size(self):
        self.assertEqual(self.scan()["function_table_entries"], 6)

    def test_static_alias_is_not_proved(self):
        self.assertFalse(self.scan()["pool_to_dispatch_pointer_identity_verified"])
        self.assertFalse(self.scan()["runtime_index_38_dispatch_observed"])

    def test_prologue_exact(self):
        self.assertTrue(exact_entry_prologue(
            fixture(), START_ENTRY, "table_start"))
        self.assertTrue(exact_entry_prologue(
            fixture(), CELL_ENTRY, "selected_cell"))

    def test_prologue_wrong_register(self):
        s = self.scan(mutation=(START_ENTRY+2, 0x6E53))
        self.assertEqual(s["entry_prologues_copy_R4_to_R14"], 1)

    def test_cell_prologue_missing_r13_save(self):
        s = self.scan(mutation=(CELL_ENTRY+4, 0x0009))
        self.assertEqual(s["entry_prologues_copy_R4_to_R14"], 1)

    def test_no_base_prologue(self):
        self.assertEqual(self.scan(with_base=False)[
            "entry_prologues_copy_R4_to_R14"], 1)

    def test_no_cell_prologue(self):
        self.assertEqual(self.scan(with_cell=False)[
            "entry_prologues_copy_R4_to_R14"], 1)

    def test_wrong_prologue_type(self):
        self.assertFalse(exact_entry_prologue(fixture(), START_ENTRY, "unknown"))

    def test_bsr_reference_is_counted(self):
        data = bytearray(fixture())
        pos = 0x1100
        put(data, pos, 0xB000 | (((START_ENTRY-pos-4)//2) & 0xFFF))
        self.assertGreaterEqual(direct_reference_counts(bytes(data), START_ENTRY)[
            "direct_bsr"], 1)

    def test_bra_reference_is_counted(self):
        data = bytearray(fixture())
        pos = 0x1100
        put(data, pos, 0xA000 | (((CELL_ENTRY-pos-4)//2) & 0xFFF))
        self.assertGreaterEqual(direct_reference_counts(bytes(data), CELL_ENTRY)[
            "direct_bra"], 1)

    def test_pc_literal_reference_is_counted(self):
        data = bytearray(fixture())
        pos = 0x1150
        put(data, pos, 0xD102)
        data[pos+12:pos+16] = (0x06004000 + START_ENTRY).to_bytes(4, "big")
        self.assertGreaterEqual(direct_reference_counts(bytes(data), START_ENTRY)[
            "pc_literal_loads"], 1)

    def test_signed_branch_displacement(self):
        self.assertEqual(signed12(0xFFE), -2)
        self.assertEqual(signed12(0x7FF), 2047)

    def test_empty_static_input(self):
        self.assertEqual(scan_dispatch_entries(b"")["matched_indexed_dispatches"], 0)

    def test_trace_base_chain(self):
        self.assertTrue(validate_trace_contract(sample_events())[
            "trace_contract_consistent"])

    def test_trace_selected_cell_chain(self):
        self.assertTrue(validate_trace_contract(sample_events("selected_cell"))[
            "matched_clone_to_slot39_dispatch_sequence"])

    def test_trace_not_runtime_proof(self):
        self.assertFalse(validate_trace_contract(sample_events())[
            "runtime_proven_by_checker"])

    def test_trace_reject_empty(self):
        self.assertEqual(validate_trace_contract([])[
            "failure_code"], "incomplete_trace")

    def test_trace_reject_wrong_type(self):
        self.assertEqual(validate_trace_contract({"events": []})[
            "failure_code"], "events_not_list")

    def test_trace_reject_wrong_slot(self):
        e = sample_events()
        e[0]["slot"] = 43
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_boolean_slot(self):
        e = sample_events()
        e[0]["slot"] = True
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_missing_identity(self):
        e = sample_events()
        e[0]["object_id"] = ""
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_copy_alias_mismatch(self):
        e = sample_events()
        e[1]["object_id"] = "another"
        self.assertEqual(validate_trace_contract(e)["failure_code"],
                         "copy_identity_or_size_mismatch")

    def test_trace_reject_copy_byte_count(self):
        e = sample_events()
        e[1]["copied_bytes"] = 272
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_copy_to_different_slot(self):
        e = sample_events()
        e[1]["slot"] = 4
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_wrong_index_field(self):
        e = sample_events()
        e[2]["field_offset"] = 124
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_index_value_other_than_38(self):
        e = sample_events()
        e[2]["index"] = 37
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_wrong_dispatch_object(self):
        e = sample_events()
        e[3]["object_id"] = "object-B"
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_wrong_selected_slot(self):
        e = sample_events()
        e[3]["selected_slot_one_based"] = 38
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_bad_anchor(self):
        e = sample_events()
        e[3]["anchor"] = "unknown"
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_cell_index_38(self):
        e = sample_events("selected_cell")
        e[3]["index"] = 38
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_incorrect_order(self):
        e = sample_events()
        e[1], e[2] = e[2], e[1]
        self.assertEqual(validate_trace_contract(e)["failure_code"],
                         "invalid_event_order")

    def test_trace_reject_extra_event(self):
        e = sample_events()
        e.append(e[3])
        self.assertFalse(validate_trace_contract(e)["trace_contract_consistent"])

    def test_trace_reject_non_dict_event(self):
        e = sample_events()
        e[1] = "bad"
        self.assertEqual(validate_trace_contract(e)["failure_code"],
                         "invalid_event")

    def test_static_metadata_has_no_game_addresses(self):
        result = self.scan()
        for field in ("entry", "position", "raw_bytes", "pool_base",
                      "table_start", "literal_pos", "game_executable_offset"):
            self.assertNotIn(field, result)

    def test_trace_output_hides_object_identity(self):
        result = validate_trace_contract(sample_events())
        self.assertNotIn("object_id", result)
        self.assertNotIn("slot", result)


if __name__ == "__main__":
    unittest.main()
