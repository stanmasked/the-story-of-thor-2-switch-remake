"""Stage67 tests use synthetic SH-2 instructions, never original Saturn bytes."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage16_vdp1_descriptor_writer_probe import make_fixture as writer_fixture
from stage67_vdp1_producer_callers import (
    PRODUCER_PROLOGUE,
    WRAPPER_PROLOGUE,
    bsr_target,
    classify_wrapper_input,
    direct_bsr_callers,
    find_global_field98_guards,
    find_pattern,
    summarize,
    find_stack60_descriptor_slot_candidates,
)


TABLE = 0x06088B14
OBJECT = 0x06088D14
COMPARE = 0x0609BA88
PRODUCER_ENTRY = 0x100
WRAPPER_ENTRY = 0x40
WRITER_START = 0x300


def put16(data, offset, value):
    data[offset:offset + 2] = value.to_bytes(2, "big")


def put32(data, offset, value):
    data[offset:offset + 4] = value.to_bytes(4, "big")


def put_bsr(data, position, target):
    delta = target - (position + 4)
    assert delta % 2 == 0
    displacement = delta // 2
    assert -2048 <= displacement <= 2047
    put16(data, position, 0xB000 | (displacement & 0x0FFF))


def put_movl_pc(data, position, register, literal_position, value):
    base = (position + 4) & ~3
    delta = literal_position - base
    assert delta % 4 == 0
    displacement = delta // 4
    assert 0 <= displacement <= 255
    put16(data, position, 0xD000 | (register << 8) | displacement)
    put32(data, literal_position, value)


def put_movw_pc(data, position, register, literal_position, value):
    delta = literal_position - (position + 4)
    assert delta % 2 == 0
    displacement = delta // 2
    assert 0 <= displacement <= 255
    put16(data, position, 0x9000 | (register << 8) | displacement)
    put16(data, literal_position, value)


def fixture():
    data = bytearray(0x600)
    writer = writer_fixture()
    data[WRITER_START:WRITER_START + len(writer)] = writer

    for i, opcode in enumerate(WRAPPER_PROLOGUE):
        put16(data, WRAPPER_ENTRY + i * 2, opcode)
    for i, opcode in enumerate(PRODUCER_PROLOGUE):
        put16(data, PRODUCER_ENTRY + i * 2, opcode)

    # Three callers of the wrapper with distinct R4 setup patterns.
    put_movl_pc(data, 0x04, 10, 0xC0, TABLE)
    put_bsr(data, 0x10, WRAPPER_ENTRY)
    put16(data, 0x12, 0x04AE)  # MOV.L @(R0,R10),R4

    put_movl_pc(data, 0x14, 0, 0xC4, TABLE)
    put16(data, 0x1E, 0x4408)  # SHLL2 R4
    put_bsr(data, 0x20, WRAPPER_ENTRY)
    put16(data, 0x22, 0x044E)  # MOV.L @(R0,R4),R4

    put16(data, 0x2E, 0x54F2)  # MOV.L @(8,SP),R4
    put_bsr(data, 0x30, WRAPPER_ENTRY)
    put16(data, 0x32, 0x0009)  # NOP delay slot

    # Global state object +0x98 is compared with a global word. Equality
    # branches around the BSR at 0x84.
    put_movl_pc(data, 0x70, 4, 0xD0, OBJECT)
    put_movl_pc(data, 0x78, 1, 0xD4, COMPARE)
    put16(data, 0x7A, 0x6312)  # MOV.L @R1,R3
    put_movw_pc(data, 0x7C, 0, 0xF0, 0x0098)
    put16(data, 0x7E, 0x024E)  # MOV.L @(R0,R4),R2
    put16(data, 0x80, 0x3230)  # CMP/EQ R3,R2
    put16(data, 0x82, 0x890D)  # BT to 0xA0, past the call
    put_bsr(data, 0x84, PRODUCER_ENTRY)
    put16(data, 0x86, 0x64E3)  # MOV R14,R4

    # Three additional direct producer call sites in the wrapper body.
    for call in (0x94, 0xA8, 0xB8):
        put_bsr(data, call, PRODUCER_ENTRY)
        put16(data, call + 2, 0x64E3)

    # Synthetic nested pointer -> SP+60 -> index*8 + base pointer chain.
    put_movw_pc(data, 0x180, 0, 0x220, 0x00AC)
    put16(data, 0x182, 0xE202)
    put16(data, 0x184, 0x09DE)  # MOV.L @(R0,R13),R9
    put16(data, 0x1A0, 0x6291)  # MOV.W @R9,R2
    put16(data, 0x1A2, 0xE03C)  # MOV #60,R0
    put16(data, 0x1A4, 0x0F25)  # MOV.W R2,@(R0,SP)
    put16(data, 0x1C0, 0xE03C)  # MOV #60,R0
    put16(data, 0x1C2, 0x6382)
    put16(data, 0x1C4, 0x02FD)  # MOV.W @(R0,SP),R2
    put_movw_pc(data, 0x1C6, 0, 0x240, 0x0098)
    put16(data, 0x1C8, 0x622D)  # MOV.W @(R0,R2),R2
    put16(data, 0x1CA, 0x01DE)  # MOV.L @(R0,R13),R1
    put16(data, 0x1CC, 0x4208)  # SHLL2 R2
    put16(data, 0x1CE, 0x4200)  # SHLL R2
    put16(data, 0x1D0, 0x321C)  # ADD R1,R2
    put16(data, 0x1D2, 0x2322)  # MOV.L R3,@R2

    return bytes(data)


class Stage67ProducerCallerTests(unittest.TestCase):
    def test_signed_bsr_target(self):
        raw = bytearray(0x40)
        put_bsr(raw, 0x20, 0x10)
        self.assertEqual(bsr_target(0x20, int.from_bytes(raw[0x20:0x22], "big")), 0x10)

    def test_finds_aligned_prologue_signatures(self):
        raw = fixture()
        self.assertIn(WRAPPER_ENTRY, find_pattern(raw, WRAPPER_PROLOGUE))
        self.assertIn(PRODUCER_ENTRY, find_pattern(raw, PRODUCER_PROLOGUE))

    def test_direct_callers_resolve_target(self):
        raw = fixture()
        self.assertEqual(direct_bsr_callers(raw, WRAPPER_ENTRY), [0x10, 0x20, 0x30])
        self.assertEqual(direct_bsr_callers(raw, PRODUCER_ENTRY), [0x84, 0x94, 0xA8, 0xB8])

    def test_classifies_all_three_wrapper_input_sources(self):
        raw = fixture()
        self.assertEqual(classify_wrapper_input(raw, 0x10), "global_pointer_table_lookup_using_R10")
        self.assertEqual(classify_wrapper_input(raw, 0x20), "global_pointer_table_lookup_using_R4_index")
        self.assertEqual(classify_wrapper_input(raw, 0x30), "caller_stack_SP_plus_8")

    def test_finds_global_field_98_guard(self):
        raw = fixture()
        guards = find_global_field98_guards(raw, PRODUCER_ENTRY)
        self.assertEqual(len(guards), 1)
        self.assertTrue(guards[0]["branch_skips_producer_call_when_field_matches"])

    def test_field_guard_requires_call_to_producer(self):
        raw = bytearray(fixture())
        put_bsr(raw, 0x84, 0x120)
        self.assertEqual(find_global_field98_guards(bytes(raw), PRODUCER_ENTRY), [])

    def test_field_guard_must_skip_call_delay_slot(self):
        raw = bytearray(fixture())
        put16(raw, 0x82, 0x8900)  # BT targets the BSR delay slot at 0x86
        self.assertEqual(find_global_field98_guards(bytes(raw), PRODUCER_ENTRY), [])

    def test_finds_stack60_nested_pointer_and_scaled_slot_address(self):
        chains = find_stack60_descriptor_slot_candidates(fixture())
        self.assertEqual(len(chains), 1)
        self.assertTrue(chains[0]["nested_pointer_field_0xAC"])
        self.assertTrue(chains[0]["stack_slot_SP_plus_60"])
        self.assertTrue(chains[0]["index_field_offset_0x98"])
        self.assertTrue(chains[0]["descriptor_slot_base_field_plus_9"])
        self.assertTrue(chains[0]["index_scale_8"])

    def test_stack60_chain_requires_nested_pointer_field(self):
        raw = bytearray(fixture())
        put16(raw, 0x220, 0x00B0)
        self.assertEqual(find_stack60_descriptor_slot_candidates(bytes(raw)), [])

    def test_stack60_chain_requires_final_descriptor_store(self):
        raw = bytearray(fixture())
        put16(raw, 0x1D2, 0x2323)
        self.assertEqual(find_stack60_descriptor_slot_candidates(bytes(raw)), [])

    def test_full_summary_reconciles_pointer_chain(self):
        result = summarize(fixture())
        self.assertEqual(result["descriptor_writer_guard_candidates"], 1)
        self.assertEqual(result["producer_function_entry_candidates"], 1)
        self.assertEqual(result["producer_direct_bsr_call_sites"], 4)
        self.assertEqual(result["producer_calls_forwarding_saved_R14_to_R4"], 4)
        self.assertEqual(result["producer_direct_calls_inside_wrapper_candidate"], 4)
        self.assertEqual(result["wrapper_function_entry_candidates"], 1)
        self.assertEqual(result["wrapper_direct_bsr_caller_sites"], 3)
        self.assertEqual(result["wrapper_input_source_candidate_counts"], {
            "global_pointer_table_lookup_using_R10": 1,
            "global_pointer_table_lookup_using_R4_index": 1,
            "caller_stack_SP_plus_8": 1,
            "other_or_unresolved": 0,
        })
        self.assertEqual(result["global_state_field_0x98_comparison_candidates"], 1)
        self.assertEqual(result["field_equality_branches_skipping_producer_call"], 1)
        self.assertEqual(result["stack_SP_plus_60_nested_pointer_to_descriptor_slot_candidates"], 1)
        self.assertEqual(result["descriptor_slot_index_uses_nested_field_plus_0x98"], 1)
        self.assertEqual(result["descriptor_slot_address_uses_R13_plus_9_and_index_times_8"], 1)

    def test_non_r14_delay_slot_is_not_counted_as_forwarding(self):
        raw = bytearray(fixture())
        put16(raw, 0x96, 0x0009)
        result = summarize(bytes(raw))
        self.assertEqual(result["producer_calls_forwarding_saved_R14_to_R4"], 3)

    def test_changed_global_field_offset_fails_closed(self):
        raw = bytearray(fixture())
        put16(raw, 0xF0, 0x0099)
        result = summarize(bytes(raw))
        self.assertEqual(result["global_state_field_0x98_comparison_candidates"], 0)

    def test_missing_producer_prologue_does_not_infer_entry(self):
        raw = bytearray(fixture())
        put16(raw, PRODUCER_ENTRY + 2, 0xE601)
        result = summarize(bytes(raw))
        self.assertEqual(result["producer_function_entry_candidates"], 0)
        self.assertEqual(result["producer_direct_bsr_call_sites"], 0)

    def test_report_contains_no_source_positions_or_bytes(self):
        result = summarize(fixture())
        self.assertNotIn("raw_bytes", result)
        self.assertNotIn("source_offsets", result)
        self.assertNotIn("producer_entry_offset", result)
        self.assertNotIn("call_positions", result)


if __name__ == "__main__":
    unittest.main()
