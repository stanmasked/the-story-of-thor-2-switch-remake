import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage91_delay_slot_entry_reference_audit import (
    _first_rts_in_window,
    summarize_address_references,
)


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


class Stage91DelaySlotReferenceTests(unittest.TestCase):
    def test_unreferenced_address_has_no_direct_entry_evidence(self):
        data = bytearray(0x200)
        result = summarize_address_references(data, 0x40, {})
        self.assertEqual(result["pc_relative_literal_refs"], 0)
        self.assertEqual(result["resolved_literal_backed_jsr_calls"], 0)
        self.assertEqual(result["raw_big_endian_words_in_scanned_root_payloads"], 0)
        self.assertFalse(result["direct_entry_evidence_present"])

    def test_pc_literal_reference_is_counted(self):
        data = bytearray(0x200)
        literal_load(data, 0x10, 2, 0x100, CODE_LOAD_ADDRESS + 0x40)
        result = summarize_address_references(data, 0x40, {"TEST.BIN": bytes(data)})
        self.assertEqual(result["pc_relative_literal_refs"], 1)
        self.assertEqual(result["raw_big_endian_words_in_scanned_root_payloads"], 1)
        self.assertTrue(result["direct_entry_evidence_present"])

    def test_literal_backed_jsr_target_is_counted(self):
        data = bytearray(0x200)
        literal_load(data, 0x10, 2, 0x100, CODE_LOAD_ADDRESS + 0x40)
        put16(data, 0x12, 0x420B)
        put16(data, 0x14, 0x0009)
        result = summarize_address_references(data, 0x40, {"TEST.BIN": bytes(data)})
        self.assertEqual(result["resolved_literal_backed_jsr_calls"], 1)

    def test_raw_pointer_word_is_counted_across_payloads(self):
        data = bytearray(0x200)
        target = CODE_LOAD_ADDRESS + 0x40
        payloads = {
            "A.BIN": bytes(data),
            "B.BIN": b"prefix" + target.to_bytes(4, "big"),
        }
        result = summarize_address_references(data, 0x40, payloads)
        self.assertEqual(result["raw_big_endian_words_in_scanned_root_payloads"], 1)
        self.assertTrue(result["direct_entry_evidence_present"])

    def test_direct_branch_destination_is_counted(self):
        data = bytearray(0x200)
        put16(data, 0x10, 0x8907)  # BT to offset 0x22
        result = summarize_address_references(data, 0x22, {"TEST.BIN": bytes(data)})
        self.assertEqual(result["direct_branch_target_refs"], 1)
        self.assertTrue(result["direct_entry_evidence_present"])

    def test_frame_prologue_alone_is_entry_evidence(self):
        data = bytearray(0x200)
        simple_prologue(data, 0x40)
        result = summarize_address_references(data, 0x40, {})
        self.assertTrue(result["has_frame_prologue_signature"])
        self.assertTrue(result["direct_entry_evidence_present"])

    def test_first_rts_in_window_is_found(self):
        data = bytearray(0x200)
        put16(data, 0x44, 0x000B)
        self.assertEqual(_first_rts_in_window(data, 0x40), 0x44)

    def test_missing_rts_in_window_returns_none(self):
        data = bytearray(0x200)
        self.assertIsNone(_first_rts_in_window(data, 0x40))

    def test_multiple_payload_matches_are_aggregated(self):
        data = bytearray(0x200)
        target = CODE_LOAD_ADDRESS + 0x40
        payloads = {
            "A.BIN": target.to_bytes(4, "big") + bytes(8),
            "B.BIN": bytes(4) + target.to_bytes(4, "big"),
        }
        result = summarize_address_references(data, 0x40, payloads)
        self.assertEqual(result["raw_big_endian_words_in_scanned_root_payloads"], 2)

    def test_summary_redacts_addresses_and_offsets(self):
        data = bytearray(0x200)
        result = summarize_address_references(data, 0x40, {})
        rendered = json.dumps(result)
        for value in ("0x40", hex(CODE_LOAD_ADDRESS)):
            self.assertNotIn(value, rendered)


if __name__ == "__main__":
    unittest.main()
