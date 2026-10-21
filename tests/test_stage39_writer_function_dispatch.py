"""Stage39: synthetic indexed dispatch and returned-object provenance tests."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage38_constant_index_writer import fixture as stage38_fixture, put
from stage39_writer_function_dispatch import (
    WRITER_PROLOGUE, POINTER_HELPER_SEGMENT, signed16,
    find_writer_entries, indexed_dispatch_sites, match_table_dispatch,
    validate_returned_object, summarize_writer_dispatch,
)

ENTRY = 0xD00
WRITE = ENTRY + 0x8C
DISPATCH = 0x1010
LITERAL = 0x1040
TABLE = 0x1500
COUNT = 116
TARGET_SLOT = 77


def fixture(mutation=None, run=True, dispatch=True, writer=True, pointer=True):
    data = bytearray(stage38_fixture())
    data.extend(bytes(max(0, 0x2000 - len(data))))
    if run:
        for i in range(COUNT):
            target = ENTRY if i == TARGET_SLOT else 0x100 + i*2
            data[TABLE+i*4:TABLE+i*4+4] = (0x06004000+target).to_bytes(4, "big")
    if dispatch:
        for i, word in enumerate(
                (0xE07E, 0x03DD, 0xD00A, 0x4308, 0x023E, 0x420B, 0x64D3)):
            put(data, DISPATCH+i*2, word)
        data[LITERAL:LITERAL+4] = (0x06004000+TABLE).to_bytes(4, "big")
    if writer:
        for i, op in enumerate(WRITER_PROLOGUE):
            put(data, ENTRY+i*2, op)
        for i, op in enumerate(
                (0xE326, 0xDC09, 0xE219, 0xCB09, 0x80E7, 0xE07E, 0x0E35)):
            put(data, WRITE-10+i*2, op)
    if pointer:
        for offset, op in POINTER_HELPER_SEGMENT.items():
            put(data, ENTRY+offset, op)
        put(data, ENTRY+0x68, 0xD325)
        put(data, ENTRY+0x78, 0xD322)
        data[0xE00:0xE04] = (0x06004000+0x100).to_bytes(4, "big")
        data[0xE04:0xE08] = (0x06004000+0x140).to_bytes(4, "big")
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage39Tests(unittest.TestCase):
    def report(self, **kwargs):
        return summarize_writer_dispatch(fixture(**kwargs))

    def test_complete_chain(self):
        self.assertEqual(
            self.report()["complete_indexed_dispatch_to_constant_writer_chains"], 1)

    def test_contiguous_run_size(self):
        self.assertEqual(self.report()["contiguous_code_pointer_run_entries"], 116)

    def test_writer_slot(self):
        self.assertEqual(self.report()["writer_slot_one_based"], 78)

    def test_index_value(self):
        self.assertEqual(self.report()["signed_index_required_from_start"], 77)

    def test_one_indexed_jsr(self):
        self.assertEqual(self.report()["indirect_jsr_dispatch_sites_for_run"], 1)

    def test_input_register_index(self):
        self.assertEqual(
            self.report()["dispatch_index_source"], "signed16(memory[R13+126])")

    def test_index_stride(self):
        self.assertTrue(self.report()["index_scaled_by_four"])

    def test_jsr_delay_passes_r13_as_r4(self):
        self.assertEqual(self.report()["dispatch_argument"], "R4=R13 in JSR delay slot")

    def test_writer_saves_argument_in_r13(self):
        self.assertTrue(self.report()["writer_entry_argument_saved_in_R13"])

    def test_writer_stores_38_into_other_object(self):
        self.assertTrue(
            self.report()["writer_stores_constant_38_in_word_R14_plus_126"])

    def test_returned_r0_captured_in_bf_s_slot(self):
        self.assertTrue(
            self.report()["nonzero_R0_result_captured_in_R14_via_BF_S_delay_slot"])

    def test_intervening_jsr_keeps_runtime_alias_unknown(self):
        r = self.report()
        self.assertTrue(r["helper_call_between_R14_capture_and_index_write"])
        self.assertFalse(r["writer_and_later_68_entry_dispatch_object_alias_verified"])

    def test_runtime_execution_not_claimed(self):
        self.assertFalse(
            self.report()["writer_and_dispatcher_runtime_execution_verified"])

    def test_table_index_bounds_are_model_only(self):
        self.assertEqual(self.report()["mathematical_index_bounds_from_start"], [0,115])

    def test_exact_writer_entry(self):
        self.assertEqual(len(find_writer_entries(fixture())), 1)

    def test_exact_dispatch_location(self):
        self.assertEqual(indexed_dispatch_sites(fixture(), TABLE), [DISPATCH])

    def test_exact_pointer_helper(self):
        self.assertTrue(validate_returned_object(fixture(), ENTRY)["nonzero_branch"])

    def test_invalid_index_byte_read(self):
        self.assertEqual(self.report(mutation=(DISPATCH+2, 0x03ED))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_invalid_index_shift(self):
        self.assertEqual(self.report(mutation=(DISPATCH+6, 0x4300))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_invalid_indexed_pointer_load(self):
        self.assertEqual(self.report(mutation=(DISPATCH+8, 0x023D))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_invalid_jsr_register(self):
        self.assertEqual(self.report(mutation=(DISPATCH+10, 0x430B))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_invalid_jsr_delay_slot(self):
        self.assertEqual(self.report(mutation=(DISPATCH+12, 0x0009))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_invalid_table_base_pointer(self):
        self.assertEqual(self.report(mutation=(LITERAL, 0x0000))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_invalid_table_slot(self):
        self.assertEqual(self.report(mutation=(TABLE+TARGET_SLOT*4, 0x0000))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_writer_constant_must_be_38(self):
        self.assertEqual(self.report(mutation=(WRITE-10, 0xE325))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_writer_entry_prologue_required(self):
        self.assertEqual(self.report(mutation=(ENTRY+6, 0x6D53))[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_bf_s_required_for_pointer_path(self):
        self.assertFalse(self.report(mutation=(ENTRY+0x70, 0x8902))[
            "nonzero_R0_result_captured_in_R14_via_BF_S_delay_slot"])

    def test_bf_s_delay_slot_must_copy_r0_to_r14(self):
        self.assertFalse(self.report(mutation=(ENTRY+0x72, 0x6E13))[
            "nonzero_R0_result_captured_in_R14_via_BF_S_delay_slot"])

    def test_second_jsr_delay_slot_must_pass_r13_as_r4(self):
        self.assertFalse(self.report(mutation=(ENTRY+0x7E, 0x0009))[
            "helper_call_between_R14_capture_and_index_write"])

    def test_no_table(self):
        self.assertEqual(self.report(run=False)[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_no_writer(self):
        self.assertEqual(self.report(writer=False)[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_no_dispatch(self):
        self.assertEqual(self.report(dispatch=False)[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_signed16(self):
        self.assertEqual(signed16(0xFFFF), -1)
        self.assertEqual(signed16(77), 77)
        self.assertEqual(signed16(0x8000), -32768)

    def test_empty(self):
        self.assertEqual(summarize_writer_dispatch(b"")[
            "complete_indexed_dispatch_to_constant_writer_chains"], 0)

    def test_private_offsets_not_exported(self):
        for key in ("entry", "store", "table_start", "entry_cell",
                    "position", "raw_bytes", "iso_offset"):
            self.assertNotIn(key, self.report())

    def test_wrong_movl_register(self):
        self.assertFalse(
            match_table_dispatch(fixture(mutation=(DISPATCH+4, 0xD10A)),
                                 DISPATCH, TABLE))


if __name__ == "__main__":
    unittest.main()
