"""Stage56 synthetic-only independent SH-2 VDP1 longword dataflow tests."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage46_vdp1_submit_gate import fixture as sh2_program, GATE
from test_stage45_vdp1_command_copy import LOAD, put
from test_stage49_sh2_vdp1_trace_contract import manifest, expected_events
from stage56_sh2_vdp1_opcode_dataflow_proof import (
    decode_copy_words, compare_trace_roles, simulate_from_decoded,
    summarize_static, run_private,
)

PROGRAM = sh2_program()
SOURCE = bytes(range(96))


def altered(offset, opcode):
    data = bytearray(PROGRAM)
    put(data, LOAD + offset, opcode)
    return bytes(data)


class Stage56SH2DataflowTests(unittest.TestCase):
    def test_eight_source_longwords(self):
        self.assertEqual(decode_copy_words(PROGRAM)["source_word_indices"], tuple(range(8)))

    def test_eight_destination_longwords(self):
        self.assertEqual(decode_copy_words(PROGRAM)["destination_word_indices"], tuple(range(8)))

    def test_instruction_offsets_derived_independently(self):
        self.assertEqual(decode_copy_words(PROGRAM)[
            "store_offsets_from_vdp1_literal_load"], (20, 22, 28, 30, 36, 38, 44, 46))

    def test_source_register_r3_loads_are_interleaved(self):
        data = decode_copy_words(PROGRAM)
        self.assertEqual(len(data["source_word_indices"]), 8)
        self.assertEqual(data["source_word_indices"][0], 0)

    def test_inner_counter_is_r2(self):
        self.assertEqual(decode_copy_words(PROGRAM)["inner_command_count_register"], "R2")

    def test_outer_counter_is_r5(self):
        self.assertEqual(decode_copy_words(PROGRAM)["outer_descriptor_count_register"], "R5")

    def test_source_pointer_increments_32(self):
        self.assertEqual(decode_copy_words(PROGRAM)["source_pointer_step_bytes"], 32)

    def test_destination_pointer_increments_32(self):
        self.assertEqual(decode_copy_words(PROGRAM)["vdp1_destination_step_bytes"], 32)

    def test_destination_index_scale_8(self):
        self.assertEqual(decode_copy_words(PROGRAM)["vdp1_destination_index_unit_bytes"], 8)

    def test_independent_pc_roles_agree_with_stage49(self):
        self.assertTrue(compare_trace_roles(PROGRAM))

    def test_two_single_command_descriptors(self):
        m = manifest()
        stores = simulate_from_decoded(PROGRAM, m, SOURCE[:64])
        self.assertEqual(len(stores), 16)
        self.assertEqual(stores[0], (0, 0x00010203))
        self.assertEqual(stores[7], (28, 0x1C1D1E1F))
        self.assertEqual(stores[8], (64, 0x20212223))

    def test_single_descriptor_two_commands(self):
        m = manifest([{"destination_index": 12, "copy_count": 2}],
                     pending_count_before=1)
        stores = simulate_from_decoded(PROGRAM, m, SOURCE[:64])
        self.assertEqual(len(stores), 16)
        self.assertEqual(stores[0][0], 96)
        self.assertEqual(stores[8][0], 128)

    def test_second_descriptor_with_two_commands(self):
        recs = [{"destination_index": 0, "copy_count": 1},
                {"destination_index": 8, "copy_count": 2}]
        m = manifest(recs, pending_count_before=2)
        s = simulate_from_decoded(PROGRAM, m, SOURCE)
        self.assertEqual(len(s), 24)
        self.assertEqual(s[16], (96, 0x40414243))

    def test_stage49_word_and_destination_order_match(self):
        m = manifest([{"destination_index": 10, "copy_count": 2}],
                     pending_count_before=1)
        src = SOURCE[:64]
        actual = simulate_from_decoded(PROGRAM, m, src)
        stage49 = expected_events(PROGRAM, m, src)
        declared = [(e["dest"] - 0x25C00000, e["value"]) for e in stage49
                    if e["role"] == "store"]
        self.assertEqual(actual, declared)

    def test_multiple_destinations_no_implicit_32byte_alignment(self):
        m = manifest([{"destination_index": 1, "copy_count": 1}], pending_count_before=1)
        self.assertEqual(simulate_from_decoded(PROGRAM, m, SOURCE[:32])[0][0], 8)

    def test_minimum_valid_command(self):
        m = manifest([{"destination_index": 0, "copy_count": 1}], pending_count_before=1)
        self.assertEqual(len(simulate_from_decoded(PROGRAM, m, SOURCE[:32])), 8)

    def test_source_words_big_endian(self):
        m = manifest([{"destination_index": 0, "copy_count": 1}], pending_count_before=1)
        s = b"\xAB\xCD\xEF\x01" + bytes(28)
        self.assertEqual(simulate_from_decoded(PROGRAM, m, s)[0][1], 0xABCDEF01)

    def test_r5_one_descriptor_two_copies_valid(self):
        m = manifest([{"destination_index": 0, "copy_count": 2}], pending_count_before=1)
        self.assertEqual(len(simulate_from_decoded(PROGRAM, m, SOURCE[:64])), 16)

    def test_r5_two_with_one_descriptor_rejected(self):
        m = manifest([{"destination_index": 0, "copy_count": 2}], pending_count_before=2)
        with self.assertRaises(ValueError):
            simulate_from_decoded(PROGRAM, m, SOURCE[:64])

    def test_bad_source_size_rejected(self):
        with self.assertRaises(ValueError):
            simulate_from_decoded(PROGRAM, manifest(), SOURCE[:63])

    def test_bytearray_source_rejected(self):
        with self.assertRaises(ValueError):
            simulate_from_decoded(PROGRAM, manifest(), bytearray(SOURCE[:64]))

    def test_bad_descriptor_count_rejected(self):
        m = manifest()
        m["pending_count_before"] = 0
        with self.assertRaises(ValueError):
            simulate_from_decoded(PROGRAM, m, SOURCE[:64])

    def test_longword_already_converted_not_compared_as_little_endian(self):
        m = manifest([{"destination_index": 0, "copy_count": 1}], pending_count_before=1)
        s = bytes([1, 0, 0, 0]) + bytes(28)
        self.assertEqual(simulate_from_decoded(PROGRAM, m, s)[0][1], 0x01000000)

    def test_static_summary_no_original_code_or_pc(self):
        report = summarize_static(PROGRAM)
        self.assertNotIn('"pc"', json.dumps(report))
        self.assertNotIn('"source_commands"', json.dumps(report))
        self.assertFalse(report["original_executable_positions_or_code_exported"])

    def test_static_summary_explicit_no_actual_gameplay(self):
        report = summarize_static(PROGRAM)
        self.assertFalse(report["original_gameplay_execution_observed"])
        self.assertFalse(report["saturn_emulator_trace_authenticated"])
        self.assertFalse(report["handler_39_to_vdp1_proven"])

    def test_static_summary_replay_counts(self):
        report = summarize_static(PROGRAM, manifest(), SOURCE[:64])
        self.assertEqual(report["private_descriptors_replayed"], 2)
        self.assertEqual(report["private_32bit_store_events_replayed"], 16)

    def test_static_summary_without_source(self):
        report = summarize_static(PROGRAM)
        self.assertIsNone(report["private_descriptors_replayed"])
        self.assertIsNone(report["private_32bit_store_events_replayed"])

    def test_missing_paired_manifest_rejected(self):
        with self.assertRaises(ValueError):
            summarize_static(PROGRAM, manifest(), None)
        with self.assertRaises(ValueError):
            summarize_static(PROGRAM, None, SOURCE[:64])

    def test_static_writer_mutation_rejected(self):
        with self.assertRaises(ValueError):
            decode_copy_words(altered(22, 0x11E2))

    def test_wrong_source_register_rejected(self):
        with self.assertRaises(ValueError):
            decode_copy_words(altered(16, 0x6042))

    def test_missing_r2_decrement_rejected(self):
        with self.assertRaises(ValueError):
            decode_copy_words(altered(50, 0x72FE))

    def test_missing_r5_decrement_rejected(self):
        with self.assertRaises(ValueError):
            decode_copy_words(altered(58, 0x75FE))

    def test_incorrect_copy_inner_branch_rejected(self):
        with self.assertRaises(ValueError):
            decode_copy_words(altered(56, 0x8BE9))

    def test_empty_code_rejected(self):
        with self.assertRaises(ValueError):
            decode_copy_words(b"")

    def test_hash_pin_blocks_synthetic_iso(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "fake.iso"
            fake.write_bytes(b"no original disc")
            with self.assertRaises(ValueError):
                run_private(fake)


if __name__ == "__main__":
    unittest.main()
