import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage75_indirect_services_count_provenance import (
    DMA_MODE_REGISTER,
    LENGTH_SOURCE_GLOBAL,
    SERVICE_SLOT_A,
    SERVICE_SLOT_B,
    _audit_length_source_writers,
    _count_length_assignments,
    _direct_store_sites,
    _pc_literal_sites,
    _slot_dispatch_sites,
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


def slot_fixture():
    data = bytearray(0x240)
    # Immediate slot-A dispatch: MOV.L @R3,R3; JSR @R3.
    put_pc_literal_load(data, 0x10, 3, 0x180, SERVICE_SLOT_A)
    put16(data, 0x12, 0x6332)
    put16(data, 0x14, 0x430B)
    # Immediate slot-B dispatch: MOV.L @R2,R2; JSR @R2.
    put_pc_literal_load(data, 0x30, 2, 0x184, SERVICE_SLOT_B)
    put16(data, 0x32, 0x6222)
    put16(data, 0x34, 0x420B)
    # Slot-A trampoline shape: load pointer from @R2, then JMP through R3.
    put_pc_literal_load(data, 0x50, 2, 0x188, SERVICE_SLOT_A)
    put16(data, 0x52, 0x2F42)  # unrelated stack store; keep R2 intact
    put16(data, 0x54, 0x6322)
    put16(data, 0x56, 0x55F1)
    put16(data, 0x58, 0x351C)
    put16(data, 0x5A, 0x432B)
    return data


def count_assignment_fixture():
    data = bytearray(0x400)
    count_address = 0x0609651C
    callback_address = 0x0600444E
    # Path A: load the global source address into R4 and read a word into R1.
    put_pc_literal_load(data, 0x10, 4, 0x300, LENGTH_SOURCE_GLOBAL)
    put16(data, 0x30, 0x6141)  # MOV.W @R4,R1
    put_pc_literal_load(data, 0x32, 2, 0x304, count_address)
    put_pc_literal_load(data, 0x34, 3, 0x308, callback_address)
    put16(data, 0x36, 0x430B)  # JSR @R3
    put16(data, 0x38, 0x2211)  # MOV.W R1,@R2 in the delay slot
    # Path B: same global source word, different destination/source registers.
    put_pc_literal_load(data, 0x50, 4, 0x30C, LENGTH_SOURCE_GLOBAL)
    put16(data, 0x70, 0x6241)  # MOV.W @R4,R2
    put_pc_literal_load(data, 0x72, 3, 0x310, count_address)
    put_pc_literal_load(data, 0x74, 1, 0x314, callback_address)
    put16(data, 0x76, 0x410B)  # JSR @R1
    put16(data, 0x78, 0x2321)  # MOV.W R2,@R3 in the delay slot
    # Two source-global writers with intentionally unresolved value origins.
    put_pc_literal_load(data, 0x88, 13, 0x320, 0x0609651C)
    put_pc_literal_load(data, 0x90, 2, 0x318, LENGTH_SOURCE_GLOBAL)
    put16(data, 0x92, 0xA0AB)  # BRA; following word is its delay slot
    put16(data, 0x94, 0x22A1)  # MOV.W R10,@R2
    put_pc_literal_load(data, 0xA0, 0, 0x31C, LENGTH_SOURCE_GLOBAL)
    put16(data, 0xA2, 0x2132)  # MOV.L R3,@R1
    put16(data, 0xA4, 0x62D1)  # MOV.L @R13+,R2
    put16(data, 0xA6, 0x2021)  # MOV.W R2,@R0
    return data


class Stage75IndirectServicesTests(unittest.TestCase):
    def test_service_slots_are_dereferenced_before_indirect_dispatch(self):
        data = slot_fixture()
        self.assertEqual(len(_pc_literal_sites(data, SERVICE_SLOT_A)), 2)
        self.assertEqual(len(_pc_literal_sites(data, SERVICE_SLOT_B)), 1)
        self.assertEqual(len(_slot_dispatch_sites(data, SERVICE_SLOT_A)), 2)
        self.assertEqual(len(_slot_dispatch_sites(data, SERVICE_SLOT_B)), 1)
        self.assertEqual(
            len(_direct_store_sites(data, SERVICE_SLOT_A)
                + _direct_store_sites(data, SERVICE_SLOT_B)),
            0,
        )

    def test_corrupt_indirect_call_no_longer_counts_as_dispatch(self):
        data = slot_fixture()
        put16(data, 0x14, 0x4308)  # not JSR/JMP through R3
        self.assertEqual(len(_slot_dispatch_sites(data, SERVICE_SLOT_A)), 1)

    def test_direct_slot_store_is_detected(self):
        data = slot_fixture()
        put_pc_literal_load(data, 0x90, 5, 0x190, SERVICE_SLOT_B)
        put16(data, 0x92, 0x2562)  # MOV.L R6,@R5
        self.assertEqual(len(_direct_store_sites(data, SERVICE_SLOT_B)), 1)

    def test_both_length_assignments_trace_to_the_same_global_word(self):
        data = count_assignment_fixture()
        found = _count_length_assignments(data, 0x0609651C, 0x0600444E)
        self.assertEqual(len(found), 2)
        self.assertTrue(all(item["source_read_verified"] for item in found))
        self.assertTrue(all(item["source_is_known_global"] for item in found))
        self.assertFalse(any(item["source_is_preexisting_pointer"] for item in found))

    def test_source_global_writer_signatures_are_found(self):
        data = count_assignment_fixture()
        self.assertEqual(len(_direct_store_sites(data, LENGTH_SOURCE_GLOBAL)), 2)

    def test_r10_writer_requires_zero_seed_and_no_detected_rewrite(self):
        data = count_assignment_fixture()
        self.assertEqual(
            _audit_length_source_writers(data, LENGTH_SOURCE_GLOBAL, 0x0609651C)[
                "length_source_global_writer_r10_zero_seeded_sites"
            ],
            0,
        )
        put16(data, 0x80, 0xEA00)  # MOV #0,R10 before the first source-global store
        result = _audit_length_source_writers(data, LENGTH_SOURCE_GLOBAL, 0x0609651C)
        self.assertEqual(result["length_source_global_direct_word_writer_signatures"], 2)
        self.assertEqual(result["length_source_global_writer_r10_zero_seeded_sites"], 1)
        self.assertEqual(result["length_source_global_writer_r13_postincrement_sources"], 1)
        self.assertEqual(result["length_source_global_writer_r13_stream_seeded_sources"], 1)
        self.assertFalse(result["length_source_global_writer_values_resolved"])

    def test_dma_mode_register_literal_is_not_assumed_from_other_register_bases(self):
        data = slot_fixture()
        self.assertEqual(len(_pc_literal_sites(data, DMA_MODE_REGISTER)), 0)
        put_pc_literal_load(data, 0xB0, 1, 0x1A0, DMA_MODE_REGISTER)
        self.assertEqual(len(_pc_literal_sites(data, DMA_MODE_REGISTER)), 1)

    def test_output_contract_is_aggregate_only(self):
        data = count_assignment_fixture()
        found = _count_length_assignments(data, 0x0609651C, 0x0600444E)
        summary = {
            "assignment_count": len(found),
            "source_read_count": sum(item["source_read_verified"] for item in found),
            "known_global_source_count": sum(item["source_is_known_global"] for item in found),
        }
        rendered = json.dumps(summary)
        for private_value in (
            hex(LENGTH_SOURCE_GLOBAL), hex(0x0609651C), hex(0x0600444E),
        ):
            self.assertNotIn(private_value, rendered)
        self.assertNotIn("store_pos", rendered)


if __name__ == "__main__":
    unittest.main()
