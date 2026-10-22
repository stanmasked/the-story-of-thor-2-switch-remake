import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage18_writer_guard_flow import be16
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import (
    COMMAND_COUNT_FIELD,
    INITIALIZER_ENTRY,
    MARKER_HELPER_ENTRY,
    PRODUCER_ENTRY,
    SERVICE_ADDRESSES,
    SOURCE_COUNT_FIELD,
    _marker_copy_audit,
    _producer_initialization_audit,
    _service_entry_audit,
    _source_field_audit,
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


def source_fixture():
    data = bytearray(0x4D00)
    # First count-field copy: source word -> R1 -> count pointer in R2.
    put_pc_literal_load(data, 0x1D12, 4, 0x1D80, SOURCE_COUNT_FIELD)
    put16(data, 0x1D24, 0x6141)
    put_pc_literal_load(data, 0x1D26, 2, 0x1DA0, COMMAND_COUNT_FIELD)
    put_pc_literal_load(data, 0x1D28, 3, 0x1DA4, CODE_LOAD_ADDRESS + MARKER_HELPER_ENTRY)
    put16(data, 0x1D2A, 0x430B)
    put16(data, 0x1D2C, 0x2211)

    # Second count-field copy: source word -> R2 -> count pointer in R3.
    put_pc_literal_load(data, 0x2380, 4, 0x2400, SOURCE_COUNT_FIELD)
    put16(data, 0x23B8, 0x6241)
    put_pc_literal_load(data, 0x23BA, 3, 0x2410, COMMAND_COUNT_FIELD)
    put_pc_literal_load(data, 0x23BC, 1, 0x2414, CODE_LOAD_ADDRESS + MARKER_HELPER_ENTRY)
    put16(data, 0x23BE, 0x410B)
    put16(data, 0x23C0, 0x2321)

    # Main producer holds the command-count pointer in R13 and seeds R10=0.
    put_pc_literal_load(data, 0x45C4, 13, 0x46AC, COMMAND_COUNT_FIELD)
    put16(data, 0x45E0, 0xEA00)

    # Writer path A: R10 -> source-count field.
    put_pc_literal_load(data, 0x4A96, 2, 0x4AA4, SOURCE_COUNT_FIELD)
    put16(data, 0x4A98, 0xA0AB)
    put16(data, 0x4A9A, 0x22A1)

    # Writer path B: current command count -> source-count field.
    put_pc_literal_load(data, 0x4AAC, 0, 0x4C30, SOURCE_COUNT_FIELD)
    put16(data, 0x4AB0, 0x62D1)
    put16(data, 0x4AB2, 0x2021)
    return data


def initializer_fixture():
    data = bytearray(0x7800)
    # The initializer zeros the count field before writing its starter record.
    put16(data, INITIALIZER_ENTRY, 0xE200)
    put_pc_literal_load(data, INITIALIZER_ENTRY + 0x06, 5, 0x470, COMMAND_COUNT_FIELD)
    put16(data, INITIALIZER_ENTRY + 0x0A, 0x2521)

    init_sites = (
        (0x6E48, 0x6E98, 0x6E4A),
        (0x75DC, 0x7620, 0x75DE),
    )
    producer_sites = (
        (0x6E54, 0x6E9C, 0x6E56),
        (0x75E8, 0x7624, 0x75EA),
    )
    for pos, literal, call in init_sites:
        put_pc_literal_load(data, pos, 1, literal, CODE_LOAD_ADDRESS + INITIALIZER_ENTRY)
        put16(data, call, 0x410B)
    for pos, literal, call in producer_sites:
        put_pc_literal_load(data, pos, 1, literal, CODE_LOAD_ADDRESS + PRODUCER_ENTRY)
        put16(data, call, 0x410B)
    return data


def service_fixture():
    data = bytearray(0x280)
    sequences = (
        (0x20, 3, SERVICE_ADDRESSES[0], 0x6332, 0x430B),
        (0x50, 3, SERVICE_ADDRESSES[0], 0x6332, 0x430B),
        (0x80, 3, SERVICE_ADDRESSES[0], 0x6332, 0x430B),
        (0xB0, 2, SERVICE_ADDRESSES[2], 0x6222, 0x420B),
        (0xE0, 2, SERVICE_ADDRESSES[2], 0x6222, 0x420B),
        (0x110, 2, SERVICE_ADDRESSES[2], 0x6222, 0x420B),
        (0x140, 1, SERVICE_ADDRESSES[1], 0x6112, 0x410B),
        (0x170, 1, SERVICE_ADDRESSES[3], 0x6112, 0x410B),
    )
    for base, reg, address, deref, call in sequences:
        put_pc_literal_load(data, base, reg, base + 0x20, address)
        put16(data, base + 4, deref)
        put16(data, base + 8, call)

    # Separate direct tail-jump use of the same fixed address.
    put_pc_literal_load(data, 0x1A0, 2, 0x220, SERVICE_ADDRESSES[0])
    put16(data, 0x1AE, 0x6322)
    put16(data, 0x1B8, 0x432B)
    return data


class Stage75CountAndServiceTests(unittest.TestCase):
    def test_source_count_has_zero_and_current_count_writer_paths(self):
        result = _source_field_audit(source_fixture())
        self.assertEqual(result["source_field_literal_reference_sites"], 4)
        self.assertEqual(result["source_field_direct_word_writer_sites"], 2)
        self.assertTrue(result["source_field_zero_writer_shape_verified"])
        self.assertTrue(result["source_field_zero_local_register_dataflow_verified"])
        self.assertTrue(result["source_field_count_copy_writer_shape_verified"])
        self.assertTrue(result["source_field_count_copy_from_command_count_verified"])
        self.assertTrue(result["source_field_writer_values_locally_resolved"])
        self.assertFalse(result["source_field_initial_value_present_in_loaded_image"])

    def test_two_marker_callers_copy_the_same_source_field(self):
        result = _marker_copy_audit(source_fixture())
        self.assertTrue(result["count_assignments_from_source_field_verified"])
        self.assertEqual(result["count_assignment_copy_sites_verified"], 2)
        self.assertTrue(result["count_assignment_sources_are_same_global_field"])

    def test_both_producer_call_sites_follow_a_zero_seed_helper(self):
        result = _producer_initialization_audit(initializer_fixture())
        self.assertEqual(result["initializer_call_sites"], 2)
        self.assertEqual(result["producer_call_sites"], 2)
        self.assertTrue(result["initializer_resets_command_count"])
        self.assertTrue(result["all_static_producer_calls_preceded_by_zero_seed"])

    def test_service_entry_has_pointer_calls_and_direct_jump_use(self):
        result = _service_entry_audit(service_fixture())
        self.assertEqual(result["service_entry_literal_reference_sites"], 9)
        self.assertEqual(result["service_entry_nearby_direct_store_sites"], 0)
        self.assertEqual(result["service_entry_dereference_call_patterns_verified"], 8)
        self.assertTrue(result["fixed_hwrm_direct_tail_jump_pattern_verified"])
        self.assertTrue(result["service_entry_has_mixed_pointer_and_direct_jump_use"])
        self.assertFalse(result["service_entry_runtime_contents_resolved"])

    def test_service_slot_writer_claim_is_limited_to_local_reference_windows(self):
        result = _service_entry_audit(service_fixture())
        self.assertEqual(result["service_entry_nearby_direct_store_sites"], 0)
        self.assertFalse(result["service_entry_initialization_path_resolved"])
        self.assertFalse(result["runtime_service_completion_confirmed"])


if __name__ == "__main__":
    unittest.main()
