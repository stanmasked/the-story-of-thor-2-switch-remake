"""Stage25 synthetic SH-2 fixtures only; original executable is never used in CI."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage24_loop_counter_probe import HEAD, INIT, TAIL
from stage25_r4_provenance_probe import (
    signed_pc_relative_bsr_target, is_explicit_branch,
    find_input_preservation_paths, mask_placement, summarize_r4_provenance,
)


def put(buf, offset, word):
    buf[offset:offset + 2] = int(word).to_bytes(2, "big")


def fixture(save=True, frame=True, delay=True, call=True,
            masked=True, prefix_branch=False, helper_outside=False):
    data = bytearray(0x500)
    head, tail = 0x100, 0x320
    for i, op in enumerate(INIT):
        put(data, 0x60 + i * 2, op)
    for i, op in enumerate(HEAD):
        put(data, head + i * 2, op)
    for i, op in enumerate(TAIL):
        put(data, tail + i * 2, op)
    cond = tail + len(TAIL) * 2
    put(data, cond, 0x8B01)
    back = cond + 2
    put(data, back, 0xA000 | (((head - back - 4) // 2) & 0xFFF))
    put(data, back + 2, 0x0009)
    put(data, 0x24, 0x2FD6)
    put(data, 0x2A, 0x6D43 if save else 0x0009)
    put(data, 0x36, 0x7FA8 if frame else 0x0009)
    call_offset = 0xC0
    helper = 0x800 if helper_outside else 0x420
    put(data, call_offset,
        0xB000 | (((helper - call_offset - 4) // 2) & 0xFFF)
        if call else 0x0009)
    put(data, call_offset + 2, 0x64D3 if delay else 0x0009)
    if masked:
        pattern = (0xE014, 0x61F3, 0x00FC, 0x7114, 0xC93F, 0x2100)
        for index, word in enumerate(pattern):
            put(data, head + 12 + index * 2, word)
    if prefix_branch:
        put(data, head + 8, 0xA000)
    return bytes(data)


class Stage25PointerProvenanceTests(unittest.TestCase):
    def test_one_preserved_pointer_and_masked_prefix(self):
        result = summarize_r4_provenance(fixture())
        self.assertEqual(result["complete_loop_signatures"], 1)
        self.assertEqual(result["saved_input_r4_in_r13_with_local_frame"], 1)
        self.assertEqual(result["relative_bsr_calls_passing_saved_pointer_in_delay_slot"], 1)
        self.assertEqual(result["loop_heads_with_unbranched_prefix_to_mask"], 1)

    def test_same_executable_helper(self):
        self.assertEqual(summarize_r4_provenance(fixture())[
            "helper_targets_within_same_executable"], 1)

    def test_requires_saved_entry_argument(self):
        self.assertEqual(find_input_preservation_paths(fixture(save=False)), [])

    def test_requires_stack_frame_allocation(self):
        self.assertEqual(find_input_preservation_paths(fixture(frame=False)), [])

    def test_requires_bsr(self):
        self.assertEqual(find_input_preservation_paths(fixture(call=False)), [])

    def test_requires_delay_slot_argument(self):
        self.assertEqual(find_input_preservation_paths(fixture(delay=False)), [])

    def test_rejects_helper_outside_binary(self):
        self.assertEqual(find_input_preservation_paths(
            fixture(helper_outside=True)), [])

    def test_unbranched_mask_rewrite(self):
        self.assertEqual(mask_placement(fixture(), 0x100, 0x320),
                         {"mask_and_store": True, "prefix_unbranched": True})

    def test_branch_blocks_straight_line_claim(self):
        result = mask_placement(fixture(prefix_branch=True), 0x100, 0x320)
        self.assertTrue(result["mask_and_store"])
        self.assertFalse(result["prefix_unbranched"])

    def test_mask_absent(self):
        self.assertFalse(mask_placement(fixture(masked=False),
                                        0x100, 0x320)["mask_and_store"])

    def test_bsr_forward_target(self):
        self.assertEqual(signed_pc_relative_bsr_target(0xC0, 0xB1AE), 0x420)

    def test_bsr_backward_target(self):
        self.assertEqual(signed_pc_relative_bsr_target(0x100, 0xBFFE), 0x100)

    def test_other_opcode_rejected_as_bsr(self):
        self.assertIsNone(signed_pc_relative_bsr_target(0x100, 0xA000))

    def test_branch_recognition(self):
        for opcode in (0xB000, 0xA001, 0x8902, 0x8F04, 0x430B, 0x000B):
            self.assertTrue(is_explicit_branch(opcode))
        for opcode in (0x0009, 0xC93F, 0x2100):
            self.assertFalse(is_explicit_branch(opcode))

    def test_empty_input(self):
        self.assertEqual(summarize_r4_provenance(b"")[
            "complete_loop_signatures"], 0)

    def test_report_does_not_expose_binary_positions(self):
        result = summarize_r4_provenance(fixture())
        for key in ("head", "tail", "offsets", "helper_call", "helper_target", "raw_bytes"):
            self.assertNotIn(key, result)


if __name__ == "__main__":
    unittest.main()
