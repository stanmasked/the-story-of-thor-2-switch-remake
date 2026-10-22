"""Stage47 tests: synthetic SH-2 instruction fixtures, never original Saturn bytes."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage16_vdp1_descriptor_writer_probe import make_fixture as writer_fixture
from test_stage46_vdp1_submit_gate import (
    fixture as gate_fixture, GATE, STATUS, COUNT, BUFFER, COMMITTED,
)
from test_stage45_vdp1_command_copy import put
from stage15_vdp1_callsite_probe import (
    BUFFER_POINTER_SLOT_ADDRESS, DESCRIPTOR_BUFFER_ADDRESS,
    TOTAL_RECORD_COUNT_ADDRESS,
)
from stage47_vdp1_producer_reconciliation import (
    _store_registers, direct_store_candidates, counter_increment_patterns,
    capacity_branch_skips_minimal_writer, summarize,
)

WRITER = 0x700


def fixture(with_writer=True, corrected_branch=True, with_setter=False,
            with_count_increment=False, cross_stage=False,
            wrong_producer_count=False, writer_mutation=None):
    data = bytearray(gate_fixture())
    data.extend(bytes(0xA00-len(data)))
    if cross_stage:
        data[0x494:0x498] = TOTAL_RECORD_COUNT_ADDRESS.to_bytes(4, "big")
        data[0x498:0x49C] = DESCRIPTOR_BUFFER_ADDRESS.to_bytes(4, "big")
        data[0x4A0:0x4A4] = BUFFER_POINTER_SLOT_ADDRESS.to_bytes(4, "big")
    if with_writer:
        source = writer_fixture(wrong_counter=wrong_producer_count)
        data[WRITER:WRITER+0x38] = source[0:0x38]
        data[WRITER+0x100:WRITER+0x114] = source[0x100:0x114]
        if corrected_branch:
            put(data, WRITER+8, 0x8917)  # BT goes past the pointer +8 update.
        if writer_mutation is not None:
            put(data, WRITER+writer_mutation, 0x0009)
    if with_setter:
        put(data, 0x900, 0xE180)  # MOV #-128,R1
        put(data, 0x902, 0xD31F)  # PC-relative literal -> R3
        put(data, 0x904, 0x2310)  # MOV.B R1,@R3
        data[0x980:0x984] = STATUS.to_bytes(4, "big")
    if with_count_increment:
        put(data, 0x920, 0xD318)
        put(data, 0x922, 0x6131)
        put(data, 0x924, 0x7101)
        put(data, 0x926, 0x2311)
        data[0x984:0x988] = COUNT.to_bytes(4, "big")
    return bytes(data)


class Stage47ProducerReconciliationTests(unittest.TestCase):
    def test_gate_only_no_producer(self):
        r = summarize(fixture(with_writer=False))
        self.assertEqual(r["stage46_submit_gates"], 1)
        self.assertEqual(r["stage16_descriptor_writer_candidates"], 0)
        self.assertFalse(r["static_cross_stage_candidate"])

    def test_writer_found(self):
        self.assertEqual(summarize(fixture())["stage16_descriptor_writer_candidates"], 1)

    def test_full_address_reconciliation(self):
        r = summarize(fixture(cross_stage=True))
        self.assertEqual(r["stage46_submit_gates"], 1)
        self.assertEqual(r["submit_gates_sharing_stage15_buffer_address"], 1)
        self.assertEqual(r["submit_gates_sharing_stage15_count_address"], 1)
        self.assertEqual(r["submit_gates_sharing_stage15_pointer_slot"], 1)
        self.assertEqual(r["submit_gates_matching_all_three_addresses"], 1)
        self.assertTrue(r["static_cross_stage_candidate"])
        self.assertEqual(r["descriptor_layout_width_bytes"], 8)

    def test_only_one_address_does_not_link(self):
        data = bytearray(fixture(cross_stage=True))
        data[0x498:0x49C] = BUFFER.to_bytes(4, "big")
        r = summarize(bytes(data))
        self.assertEqual(r["submit_gates_matching_all_three_addresses"], 0)
        self.assertFalse(r["static_cross_stage_candidate"])

    def test_stage16_bad_source_store_rejected(self):
        self.assertEqual(summarize(fixture(
            cross_stage=True, writer_mutation=0x12
        ))["stage16_descriptor_writer_candidates"], 0)

    def test_stage16_wrong_count_rejected(self):
        self.assertFalse(summarize(fixture(
            cross_stage=True, wrong_producer_count=True
        ))["static_cross_stage_candidate"])

    def test_no_link_without_writer(self):
        self.assertFalse(summarize(fixture(
            cross_stage=True, with_writer=False
        ))["static_cross_stage_candidate"])

    def test_old_synthetic_addresses_differ(self):
        r = summarize(fixture())
        self.assertFalse(r["static_cross_stage_candidate"])
        self.assertNotEqual(BUFFER, DESCRIPTOR_BUFFER_ADDRESS)
        self.assertNotEqual(COUNT, TOTAL_RECORD_COUNT_ADDRESS)
        self.assertNotEqual(COMMITTED, BUFFER_POINTER_SLOT_ADDRESS)

    def test_capacity_512_literal(self):
        self.assertEqual(summarize(fixture())["stage16_capacity_comparison_literal"], 512)

    def test_capacity_branch_skip_good(self):
        self.assertTrue(capacity_branch_skips_minimal_writer(fixture(), WRITER))

    def test_capacity_branch_skip_old_target_fails(self):
        self.assertFalse(capacity_branch_skips_minimal_writer(
            fixture(corrected_branch=False), WRITER))

    def test_capacity_branch_wrong_opcode_fails(self):
        raw = bytearray(fixture())
        put(raw, WRITER+8, 0x8B17)
        self.assertFalse(capacity_branch_skips_minimal_writer(bytes(raw), WRITER))

    def test_capacity_branch_requires_pointer_advance(self):
        self.assertFalse(capacity_branch_skips_minimal_writer(
            fixture(writer_mutation=0x36), WRITER))

    def test_capacity_guard_does_not_prove_global_safety(self):
        r = summarize(fixture())
        self.assertEqual(r["capacity_branch_locally_skips_pointer_advance_candidates"], 1)
        self.assertFalse(r["capacity_bound_enforced_on_all_runtime_paths"])

    def test_counter_increment_stage16(self):
        self.assertEqual(counter_increment_patterns(
            fixture(), TOTAL_RECORD_COUNT_ADDRESS), 1)

    def test_counter_increment_wrong_target(self):
        self.assertEqual(counter_increment_patterns(
            fixture(), TOTAL_RECORD_COUNT_ADDRESS+4), 0)

    def test_additional_counter_increment(self):
        self.assertEqual(counter_increment_patterns(
            fixture(with_count_increment=True), COUNT), 1)

    def test_gate_clears_flag(self):
        self.assertGreaterEqual(summarize(fixture())["byte_status_gate_clear_stores"], 1)

    def test_new_negative_flag_setter(self):
        r = summarize(fixture(with_setter=True))
        self.assertEqual(r["byte_status_other_negative_immediate_candidates"], 1)

    def test_no_negative_setter_claim_without_evidence(self):
        self.assertEqual(summarize(fixture())["byte_status_other_negative_immediate_candidates"], 0)

    def test_store_opcode_decoder(self):
        self.assertEqual(_store_registers(0x2310, "byte"), (3, 1))
        self.assertEqual(_store_registers(0x2311, "word"), (3, 1))
        self.assertIsNone(_store_registers(0x2311, "byte"))
        self.assertIsNone(_store_registers(0x0009, "byte"))

    def test_pointer_clobber_stops_scan(self):
        raw = bytearray(fixture(with_setter=True))
        put(raw, 0x904, 0xE300)
        put(raw, 0x906, 0x2310)
        found = direct_store_candidates(bytes(raw), STATUS, "byte")
        self.assertFalse(any(s["position"] == 0x906 for s in found))

    def test_branch_stops_scan(self):
        raw = bytearray(fixture(with_setter=True))
        put(raw, 0x904, 0x8901)
        put(raw, 0x906, 0x2310)
        found = direct_store_candidates(bytes(raw), STATUS, "byte")
        self.assertFalse(any(s["position"] == 0x906 for s in found))

    def test_positive_flag_immediate(self):
        raw = bytearray(fixture(with_setter=True))
        put(raw, 0x904, 0xE102)
        put(raw, 0x906, 0x2310)
        found = direct_store_candidates(bytes(raw), STATUS, "byte")
        self.assertTrue(any(s["position"] == 0x906 and s["immediate"] == 2 for s in found))

    def test_lookahead_window_bounded(self):
        raw = bytearray(fixture(with_setter=True))
        put(raw, 0x904, 0x0009)
        put(raw, 0x934, 0x2310)
        found = direct_store_candidates(bytes(raw), STATUS, "byte")
        self.assertFalse(any(s["position"] == 0x934 for s in found))

    def test_incomplete_gate_skips_status_scan(self):
        raw = bytearray(fixture(with_setter=True))
        put(raw, GATE+0x10, 0x0009)
        r = summarize(bytes(raw))
        self.assertEqual(r["stage46_submit_gates"], 0)
        self.assertEqual(r["byte_status_direct_store_candidates"], 0)

    def test_empty(self):
        self.assertEqual(summarize(b"")["stage16_descriptor_writer_candidates"], 0)
        self.assertEqual(summarize(b"")["stage46_submit_gates"], 0)

    def test_no_game_execution_or_handler_claims(self):
        r = summarize(fixture(cross_stage=True))
        for key in (
            "actual_saturn_execution_captured", "handler_39_to_vdp1_proven",
            "producer_to_gate_control_flow_proven",
            "producer_identity_by_runtime_pointer_alias_proven",
            "record_count_vs_per_descriptor_copy_count_reconciled",
        ):
            self.assertFalse(r[key])

    def test_no_addresses_or_positions_exported(self):
        exported = json.dumps(summarize(fixture(cross_stage=True)))
        for address in (STATUS, COUNT, BUFFER, COMMITTED,
                        DESCRIPTOR_BUFFER_ADDRESS, TOTAL_RECORD_COUNT_ADDRESS,
                        BUFFER_POINTER_SLOT_ADDRESS):
            self.assertNotIn(hex(address), exported)
            self.assertNotIn(str(address), exported)
        for name in ("position", "start", "status_address", "source_address",
                     "count_address", "raw_bytes"):
            self.assertNotIn('"'+name+'"', exported)


if __name__ == "__main__":
    unittest.main()
