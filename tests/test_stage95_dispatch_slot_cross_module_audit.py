import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage95_dispatch_slot_cross_module_audit import (
    DISPATCH_SLOT,
    _dispatch_call_after_ref,
    _is_direct_store_through_register,
    _slot_references,
    _store_candidate_after_ref,
    _summarize_payloads,
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


class Stage95DispatchSlotCrossModuleTests(unittest.TestCase):
    def test_literal_backed_slot_read_followed_by_indirect_call_is_detected(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 2, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x6322)  # MOV.L @R2,R3
        put16(data, 0x14, 0x432B)  # JSR @R3
        put16(data, 0x16, 0x0009)
        refs = _slot_references(bytes(data), DISPATCH_SLOT)
        self.assertEqual(refs, [(0x10, 2)])
        self.assertTrue(_dispatch_call_after_ref(bytes(data), 0x10, 2))

    def test_indirect_call_after_register_cleanup_is_detected(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x6212)  # MOV.L @R1,R2
        put16(data, 0x14, 0x7F04)
        put16(data, 0x16, 0x4F26)
        put16(data, 0x18, 0x422B)  # JSR @R2
        put16(data, 0x1A, 0x6EF6)
        self.assertTrue(_dispatch_call_after_ref(bytes(data), 0x10, 1))

    def test_wrong_pointer_base_register_is_rejected(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 2, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x6312)  # MOV.L @R1,R3, not @R2
        put16(data, 0x14, 0x432B)
        self.assertFalse(_dispatch_call_after_ref(bytes(data), 0x10, 2))

    def test_wrong_indirect_call_register_is_rejected(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 2, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x6322)
        put16(data, 0x14, 0x422B)  # JSR @R2, but loaded target is in R3
        self.assertFalse(_dispatch_call_after_ref(bytes(data), 0x10, 2))

    def test_store_through_slot_pointer_is_counted_as_candidate(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x2122)  # MOV.L R2,@R1
        self.assertTrue(_is_direct_store_through_register(0x2122, 1))
        self.assertTrue(_store_candidate_after_ref(bytes(data), 0x10, 1))

    def test_read_only_dispatch_call_is_not_misclassified_as_store(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x6212)
        put16(data, 0x14, 0x422B)
        put16(data, 0x16, 0x0009)
        self.assertFalse(_store_candidate_after_ref(bytes(data), 0x10, 1))

    def test_payload_summary_counts_only_modules_with_references(self):
        main = bytearray(0x100)
        put_literal_load(main, 0x10, 2, 0x80, DISPATCH_SLOT)
        put16(main, 0x12, 0x6322)
        put16(main, 0x14, 0x432B)
        put16(main, 0x16, 0x0009)
        low = bytearray(0x100)
        put_literal_load(low, 0x10, 1, 0x80, DISPATCH_SLOT)
        put16(low, 0x12, 0x6212)
        put16(low, 0x14, 0x422B)
        put16(low, 0x16, 0x0009)
        set07 = bytearray(0x100)
        put_literal_load(set07, 0x10, 3, 0x80, DISPATCH_SLOT)
        put16(set07, 0x12, 0x6232)
        put16(set07, 0x14, 0x422B)
        put16(set07, 0x16, 0x0009)
        summary = _summarize_payloads({"0TH2.BIN": bytes(main), "TH2.LOW": bytes(low), "SET07.BIN": bytes(set07), "OTHER.BIN": bytes(0x20)})
        self.assertEqual(summary["modules_with_dispatcher_slot_references"], 3)
        self.assertEqual(summary["recognized_indirect_dispatch_call_sites"], 3)
        self.assertEqual(summary["modules_with_recognized_dispatch_calls"], 3)
        self.assertEqual(summary["bounded_store_through_slot_candidates"], 0)

    def test_optional_error_targets_map_to_th2_low_function_entries(self):
        main = bytearray(0x200)
        put_literal_load(main, 0x10, 0, 0x180, 0x002E20F8)
        put_literal_load(main, 0x20, 0, 0x184, 0x002E227C)
        low_base = 0x002DA000
        low = bytearray(0x9000)
        first = 0x80F8
        put16(low, first, 0x2FE6)
        put16(low, first + 2, 0x2FD6)
        put16(low, first + 4, 0x2FC6)
        put16(low, first + 6, 0x4F22)
        put16(low, first + 0x0E, 0x6130)
        put16(low, first + 0x10, 0x2118)
        put16(low, first + 0x12, 0x8BFB)
        second = 0x827C
        put16(low, second, 0x2FE6)
        put16(low, second + 2, 0x4F22)
        put16(low, second + 0x22, 0x60F1)
        for delta, op in [(0x24, 0x8800), (0x28, 0x8801), (0x2C, 0x8802), (0x30, 0x8803), (0x34, 0x8804)]:
            put16(low, second + delta, op)
            put16(low, second + delta + 2, 0x8901)
        summary = _summarize_payloads({"0TH2.BIN": bytes(main), "TH2.LOW": bytes(low)}, low_base)
        self.assertTrue(summary["optional_indirect_target_1_maps_inside_th2_low"])
        self.assertTrue(summary["optional_indirect_target_2_maps_inside_th2_low"])
        self.assertTrue(summary["optional_indirect_target_1_has_prologue_like_entry"])
        self.assertTrue(summary["optional_indirect_target_2_has_prologue_like_entry"])
        self.assertTrue(summary["optional_indirect_target_1_starts_with_global_wait_loop"])
        self.assertTrue(summary["optional_indirect_target_2_has_value_switch_0_through_4"])

    def test_summary_does_not_emit_raw_addresses(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x10, 2, 0x80, DISPATCH_SLOT)
        put16(data, 0x12, 0x6322)
        put16(data, 0x14, 0x432B)
        summary = _summarize_payloads({"0TH2.BIN": bytes(data)})
        rendered = repr(summary)
        self.assertNotIn("0x", rendered)
        self.assertNotIn("address", rendered.lower())


if __name__ == "__main__":
    unittest.main()
