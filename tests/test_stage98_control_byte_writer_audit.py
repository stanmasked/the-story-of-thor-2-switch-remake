import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage92_set07_guard_predicate_audit import _delay_aware_cfg
from stage98_control_byte_writer_audit import (
    _caller_entry_anchors,
    _scan_store_sites_from_literal,
    _site_reachability,
    _source_register_seed_summary,
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


def writer_delay_slot_fixture():
    data = bytearray(0x100)
    put16(data, 0x10, 0xEE00)  # MOV #0,R14
    put_literal_load(data, 0x12, 1, 0x80, 0x06008AF5)
    put_literal_load(data, 0x14, 3, 0x84, CODE_LOAD_ADDRESS + 0x10)
    put16(data, 0x16, 0x430B)  # JSR @R3
    put16(data, 0x18, 0x21E0)  # MOV.B R14,@R1 -- call delay slot
    put16(data, 0x1A, 0x000B)  # RTS
    put16(data, 0x1C, 0x0009)
    return bytes(data)


class Stage98ControlByteWriterAuditTests(unittest.TestCase):
    def test_exact_byte_store_is_found_through_pointer_literal(self):
        data = writer_delay_slot_fixture()
        stores, unresolved = _scan_store_sites_from_literal(
            data, 0x12, 0x06008AF5, 1, 0x06008AF5
        )
        self.assertIn(0x18, stores)
        self.assertEqual(stores[0x18]["mode"], "indirect")
        self.assertEqual(stores[0x18]["width"], 1)
        self.assertEqual(stores[0x18]["source_register"], 14)
        self.assertFalse(unresolved)

    def test_literal_backed_call_anchor_reaches_store_delay_slot(self):
        data = writer_delay_slot_fixture()
        anchors = _caller_entry_anchors(data)
        self.assertIn((0x14, 0x10, 0x100), anchors)
        reachability, anchor_count = _site_reachability(data, {0x18})
        self.assertEqual(anchor_count, 1)
        self.assertTrue(reachability[0x18]["reachable_as_delay_slot"])
        self.assertFalse(reachability[0x18]["normal_instruction_reachable"])

    def test_cfg_executes_call_delay_slot_before_return_continuation(self):
        data = writer_delay_slot_fixture()
        cfg = _delay_aware_cfg(data, 0x10, 0x50)
        self.assertTrue(any(pc == 0x18 and pending is not None
                            for pc, pending in cfg["state_nodes"]))

    def test_zero_seed_is_proven_when_store_is_call_delay_slot(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0xEE00)  # MOV #0,R14
        put16(data, 0x12, 0x430B)  # JSR @R3
        put16(data, 0x14, 0x21E0)  # store in delay slot
        result = _source_register_seed_summary(bytes(data), 0x10, 0x14, 14)
        self.assertTrue(result["last_immediate_seed_found"])
        self.assertEqual(result["last_immediate_seed_value"], 0)
        self.assertEqual(result["lexical_call_sites_before_store"], 0)
        self.assertTrue(result["source_value_proven_at_store"])

    def test_nonzero_seed_is_not_proven_after_prior_call(self):
        data = bytearray(0x40)
        put16(data, 0x10, 0xED01)  # MOV #1,R13
        put16(data, 0x12, 0x430B)  # JSR @R3
        put16(data, 0x14, 0x0009)  # delay slot
        put16(data, 0x16, 0xB001)  # BSR before candidate store
        put16(data, 0x18, 0x0009)
        put16(data, 0x1A, 0x23D0)  # MOV.B R13,@R3
        result = _source_register_seed_summary(bytes(data), 0x10, 0x1A, 13)
        self.assertTrue(result["last_immediate_seed_found"])
        self.assertEqual(result["last_immediate_seed_value"], 1)
        self.assertEqual(result["lexical_call_sites_before_store"], 2)
        self.assertFalse(result["source_value_proven_at_store"])
        self.assertFalse(result["interprocedural_register_preservation_proven"])

    def test_source_summary_contains_no_raw_offsets_or_addresses(self):
        result = _source_register_seed_summary(
            writer_delay_slot_fixture(), 0x10, 0x18, 14
        )
        rendered = repr(result)
        self.assertNotIn("0x", rendered)
        self.assertNotIn("instruction_offset", rendered)


if __name__ == "__main__":
    unittest.main()
