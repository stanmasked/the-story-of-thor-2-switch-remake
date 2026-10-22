import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage18_writer_guard_flow import be16
from stage35_table_tail_link import branch_destination
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage76_count_block_reachability_audit import (
    audit_hwrm_vector_cluster,
    audit_increment_candidate,
    audit_r10_source_path,
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


def increment_fixture():
    data = bytearray(0x500)
    put16(data, 0x444, 0x000B)  # RTS
    put16(data, 0x446, 0x2432)  # return delay slot
    put16(data, 0x448, 0x6251)  # MOV.W @R5,R2
    put16(data, 0x44A, 0x7201)  # ADD #1,R2
    put16(data, 0x44C, 0x2521)  # MOV.W R2,@R5
    return data


def hwrm_fixture():
    data = bytearray(0x220)
    entries = (
        (0x20, 2, 0x06000300, 0x6322, 0x432B),
        (0x90, 1, 0x06000344, 0x6112, 0x410B),
        (0x100, 0, 0x06000310, 0x6002, 0x400B),
    )
    for pos, reg, address, deref, call in entries:
        put_pc_literal_load(data, pos, reg, pos + 0x20, address)
        put16(data, pos + 2, deref)
        put16(data, pos + 4, call)
    return data


class Stage76ReachabilityTests(unittest.TestCase):
    def test_increment_candidate_has_return_barrier_and_no_direct_entry(self):
        result = audit_increment_candidate(increment_fixture())
        self.assertTrue(result["unclassified_increment_signature_verified"])
        self.assertTrue(result["return_and_delay_slot_precede_candidate"])
        self.assertEqual(result["direct_branch_targets_to_candidate"], 0)
        self.assertEqual(result["literal_pointer_refs_to_candidate"], 0)
        self.assertEqual(result["raw_absolute_pointer_occurrences_to_candidate"], 0)
        self.assertFalse(result["candidate_has_static_direct_entry"])
        self.assertFalse(result["candidate_reachability_proven"])

    def test_direct_branch_to_candidate_is_detected(self):
        data = increment_fixture()
        branch_pos = 0x20
        displacement = (0x448 - (branch_pos + 4)) // 2
        put16(data, branch_pos, 0xA000 | (displacement & 0x0FFF))
        result = audit_increment_candidate(data)
        self.assertEqual(result["direct_branch_targets_to_candidate"], 1)
        self.assertTrue(result["candidate_has_static_direct_entry"])

    def test_literal_pointer_to_candidate_is_detected(self):
        data = increment_fixture()
        put_pc_literal_load(data, 0x60, 3, 0xA0, CODE_LOAD_ADDRESS + 0x448)
        result = audit_increment_candidate(data)
        self.assertEqual(result["literal_pointer_refs_to_candidate"], 1)
        self.assertGreaterEqual(result["raw_absolute_pointer_occurrences_to_candidate"], 1)
        self.assertTrue(result["candidate_has_static_direct_entry"])

    def test_early_hwrm_cluster_recognizes_pointer_mediated_calls(self):
        result = audit_hwrm_vector_cluster(hwrm_fixture())
        self.assertEqual(result["early_hwrm_literal_reference_sites"], 3)
        self.assertEqual(result["distinct_early_hwrm_addresses"], 3)
        self.assertEqual(result["references_followed_by_indirect_call_pattern"], 3)
        self.assertEqual(result["unique_indirect_call_sites"], 3)
        self.assertEqual(result["nearby_direct_store_sites"], 0)
        self.assertFalse(result["service_vector_contents_resolved"])

    def test_r10_zero_local_dataflow_is_not_a_transitive_preservation_proof(self):
        data = bytearray(0x4B00)
        put16(data, 0x45E0, 0xEA00)
        result = audit_r10_source_path(data)
        self.assertTrue(result["source_register_locally_initialized_to_zero"])
        self.assertEqual(result["explicit_source_register_reassignments_before_store"], 0)
        self.assertFalse(result["source_register_preservation_across_all_callees_proven"])


if __name__ == "__main__":
    unittest.main()
