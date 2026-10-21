"""Stage31 synthetic SH-2 prologue and R4 field-gate tests."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage31_entry_guard_audit import (
    branch_destination, known_direct_r4_assignment, summarize_entry_guards,
)


def put(data, pos, opcode):
    data[pos:pos + 2] = opcode.to_bytes(2, "big")


def fixture(mutation=None, extend_third_gap=False):
    data = bytearray(0x900)
    specs = (
        (0x100, 106, (14, 13, 12, 11, 9), "flag6", False),
        (0x300, 46, (14, 13, 12, 11, 10, 9, 8), "gate7", False),
        (0x500, 24 if extend_third_gap else 18,
         (14, 13, 12, 11, 10, 9, 8), "", True),
    )
    for number, (entry, distance, regs, flag, extended) in enumerate(specs):
        first = entry + distance
        for i, reg in enumerate(regs):
            where = entry if i == 0 else (
                entry + (i + 1) * 2 if number == 0 else entry + i * 2)
            put(data, where, 0x2F06 | (reg << 4))
        if flag == "flag6":
            for i, code in enumerate((0x8446, 0xC804, 0x8B05)):
                put(data, entry + 16 + 2*i, code)
        if flag == "gate7":
            gate = entry + 16
            for i, code in enumerate((0x8447, 0xC801, 0x8901)):
                put(data, gate + 2*i, code)
            branch = gate + 6
            destination = first + 120
            put(data, branch, 0xA000 | (((destination - branch - 4)//2) & 0xFFF))
            put(data, gate + 8, 0x6053)  # branch delay slot
        put(data, first - (6 if number == 0 else 4), 0x8548)
        put(data, first - 2, 0x6503 if number == 0 else 0x6603)
        fields = (31, 32, 33, 34, 35, 36) if extended else (31, 32, 33, 34)
        for i, field in enumerate(fields):
            pos = first + i * 8
            put(data, pos, 0xE000 | field)
            put(data, pos + 2,
                ((14 - i) << 8) | 0x40 | (0xD if field == 36 else 0xC))
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage31Tests(unittest.TestCase):
    def report(self, *args, **kwargs):
        return summarize_entry_guards(fixture(*args, **kwargs))

    def test_three_prologues(self):
        self.assertEqual(self.report()["consumers_with_matched_prologue_and_r4_word16_read"], 3)

    def test_register_saves(self):
        self.assertEqual(self.report()["saved_register_counts_by_consumer"], [5, 7, 7])

    def test_extra_word_at_byte_offset_16(self):
        self.assertEqual(self.report()["shared_additional_word_field"], "R4+16")

    def test_branch_counts(self):
        self.assertEqual(self.report()["pre_read_branch_counts"], [1, 2, 0])

    def test_bit_zero_gate(self):
        self.assertEqual(self.report()["consumers_with_confirmed_r4_plus_7_bit0_clear_gate"], 1)

    def test_preliminary_bit_two(self):
        self.assertEqual(self.report()["consumers_with_preliminary_r4_plus_6_bit2_test"], 1)

    def test_extended_straight_line(self):
        self.assertTrue(self.report()["extended_reader_has_straight_line_prefix"])

    def test_incorrect_bit0_mask_rejected(self):
        self.assertEqual(self.report(mutation=(0x312, 0xC802))[
            "consumers_with_confirmed_r4_plus_7_bit0_clear_gate"], 0)

    def test_incorrect_bt_destination_rejected(self):
        self.assertEqual(self.report(mutation=(0x314, 0x8902))[
            "consumers_with_confirmed_r4_plus_7_bit0_clear_gate"], 0)

    def test_bra_must_bypass_reader(self):
        self.assertEqual(self.report(mutation=(0x316, 0xA000))[
            "consumers_with_confirmed_r4_plus_7_bit0_clear_gate"], 0)

    def test_gate_delay_slot_required(self):
        self.assertEqual(self.report(mutation=(0x318, 0x0009))[
            "consumers_with_confirmed_r4_plus_7_bit0_clear_gate"], 0)

    def test_bad_bit2_mask_rejected(self):
        self.assertEqual(self.report(mutation=(0x112, 0xC801))[
            "consumers_with_preliminary_r4_plus_6_bit2_test"], 0)

    def test_word_load_required(self):
        self.assertEqual(self.report(mutation=(0x32A, 0x8448))[
            "consumers_with_matched_prologue_and_r4_word16_read"], 2)

    def test_prologue_required(self):
        self.assertEqual(self.report(mutation=(0x500, 0x0009))[
            "consumers_with_matched_prologue_and_r4_word16_read"], 2)

    def test_saved_register_order_required(self):
        self.assertEqual(self.report(mutation=(0x10A, 0x2F86))[
            "consumers_with_matched_prologue_and_r4_word16_read"], 2)

    def test_direct_r4_overwrite_classifier(self):
        self.assertTrue(known_direct_r4_assignment(0x6453))
        self.assertFalse(known_direct_r4_assignment(0x6503))

    def test_direct_r4_assignment_counted(self):
        self.assertEqual(self.report(mutation=(0x30E, 0x6453))[
            "consumers_with_recognized_direct_r4_assignment_in_prefix"], 1)

    def test_branch_destroys_extended_straight_line(self):
        self.assertFalse(self.report(
            mutation=(0x50E, 0xA000), extend_third_gap=True)[
                "extended_reader_has_straight_line_prefix"])

    def test_signed_pc_relative_targets(self):
        self.assertEqual(branch_destination(0x100, 0xAFFE), 0x100)
        self.assertEqual(branch_destination(0x100, 0x8901), 0x106)
        self.assertIsNone(branch_destination(0x100, 0x0009))

    def test_no_proprietary_program_positions_in_report(self):
        result = self.report()
        for field in ("entry", "start", "program_offsets", "raw_bytes", "read_positions"):
            self.assertNotIn(field, result)

    def test_empty_input(self):
        self.assertEqual(summarize_entry_guards(b"")["stage30_consumer_groups"], 0)


if __name__ == "__main__":
    unittest.main()
