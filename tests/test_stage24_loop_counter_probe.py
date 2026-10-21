"""Stage24 synthetic SH-2 loop-tail fixtures; no game bytes."""
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage24_loop_counter_probe import (
    HEAD, INIT, TAIL, relative_branch_destination,
    find_signed_descriptor_loops, modeled_iterations, summarize_loop_provenance,
)


def put16(data, offset, value):
    data[offset:offset + 2] = value.to_bytes(2, "big")


def make_fixture(wrong_init=False, wrong_head=False, wrong_tail=False,
                 wrong_cond=False, wrong_backedge=False, wrong_delay=False,
                 with_mask=True):
    buf = bytearray(0x500)
    init, head, tail = 0x60, 0x100, 0x320
    for index, word in enumerate(INIT):
        put16(buf, init + 2 * index, (word ^ 1) if wrong_init and index == 0 else word)
    for index, word in enumerate(HEAD):
        put16(buf, head + 2 * index, (word ^ 1) if wrong_head and index == 2 else word)
    for index, word in enumerate(TAIL):
        put16(buf, tail + 2 * index, (word ^ 1) if wrong_tail and index == 5 else word)
    if with_mask:
        put16(buf, head + 20, 0xC93F)
    cond = tail + len(TAIL) * 2
    back = cond + 2
    put16(buf, cond, 0x8B00 if wrong_cond else 0x8B01)
    displacement = (head - (back + 4)) // 2
    put16(buf, back, 0xA000 | ((displacement + (1 if wrong_backedge else 0)) & 0xFFF))
    put16(buf, back + 2, 0xFFFF if wrong_delay else 0x0009)
    return bytes(buf)


class Stage24LoopCounterTests(unittest.TestCase):
    def test_recognizes_complete_loop(self):
        self.assertEqual(len(find_signed_descriptor_loops(make_fixture())), 1)

    def test_init_source_and_stack_field(self):
        report = summarize_loop_provenance(make_fixture())
        self.assertEqual(report["loop_counter_initial_source"], "u8(memory[R4+1])")
        self.assertEqual(report["loop_counter_stack_field"], "SP+56")

    def test_detects_mask_inside_body(self):
        self.assertEqual(summarize_loop_provenance(make_fixture())["loop_bodies_containing_and_0x3f"], 1)

    def test_absent_mask_is_allowed(self):
        self.assertEqual(summarize_loop_provenance(make_fixture(with_mask=False))["loop_bodies_containing_and_0x3f"], 0)

    def test_rejects_wrong_initialization(self):
        self.assertEqual(find_signed_descriptor_loops(make_fixture(wrong_init=True)), [])

    def test_rejects_wrong_loop_head(self):
        self.assertEqual(find_signed_descriptor_loops(make_fixture(wrong_head=True)), [])

    def test_rejects_wrong_tail_update(self):
        self.assertEqual(find_signed_descriptor_loops(make_fixture(wrong_tail=True)), [])

    def test_rejects_wrong_exit_target(self):
        self.assertEqual(find_signed_descriptor_loops(make_fixture(wrong_cond=True)), [])

    def test_rejects_wrong_backedge_target(self):
        self.assertEqual(find_signed_descriptor_loops(make_fixture(wrong_backedge=True)), [])

    def test_requires_bra_nop_delay_slot(self):
        self.assertEqual(find_signed_descriptor_loops(make_fixture(wrong_delay=True)), [])

    def test_branch_target_sign_extended(self):
        self.assertEqual(relative_branch_destination(0x332, 0xAEE5), 0x100)
        self.assertEqual(relative_branch_destination(0x330, 0x8B01), 0x336)
        self.assertIsNone(relative_branch_destination(0x330, 0x0009))

    def test_counter_math_zero_and_one(self):
        self.assertEqual(modeled_iterations(0), 1)
        self.assertEqual(modeled_iterations(1), 2)

    def test_counter_math_positive_boundary(self):
        self.assertEqual(modeled_iterations(127), 128)

    def test_counter_math_negative_boundary(self):
        self.assertEqual(modeled_iterations(128), 129)
        self.assertEqual(modeled_iterations(129), 1)
        self.assertEqual(modeled_iterations(255), 1)

    def test_invalid_input_rejected(self):
        for value in (-1, 256):
            with self.assertRaises(ValueError):
                modeled_iterations(value)

    def test_no_original_code_offsets_in_summary(self):
        summary = summarize_loop_provenance(make_fixture())
        for disallowed in ("head", "tail", "offsets", "code_bytes"):
            self.assertNotIn(disallowed, summary)

    def test_empty_data(self):
        self.assertEqual(summarize_loop_provenance(b"")["complete_counted_descriptor_loop_matches"], 0)


if __name__ == "__main__":
    unittest.main()
