import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage83_unpaired_callback_context_audit import (
    classify_unpaired_callback_contexts,
)

CALLBACK = 0x0600444E
WRITER = 0x060085A8


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


class Stage83UnpairedCallbackContextTests(unittest.TestCase):
    def test_writer_before_callback_in_candidate_interval(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [0x20], set(), set(), [0x10, 0x80]
        )
        self.assertEqual(result["unpaired_callback_sites_with_writer_before_in_candidate_function"], 1)
        self.assertEqual(result["unpaired_callback_sites_without_writer_in_candidate_function"], 0)

    def test_writer_after_callback_in_candidate_interval(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [0x60], set(), set(), [0x10, 0x80]
        )
        self.assertEqual(result["unpaired_callback_sites_with_writer_after_in_candidate_function"], 1)
        self.assertEqual(result["unpaired_callback_sites_with_writer_before_in_candidate_function"], 0)

    def test_no_writer_in_candidate_interval(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [], set(), set(), [0x10, 0x80]
        )
        self.assertEqual(result["unpaired_callback_sites_without_writer_in_candidate_function"], 1)

    def test_length_copy_without_writer_is_counted(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [], set(), {0x40}, [0x10, 0x80]
        )
        self.assertEqual(result["length_copy_sites_without_writer_in_candidate_function"], 1)

    def test_nop_delay_without_writer_is_counted(self):
        data = bytearray(0x100)
        put16(data, 0x42, 0x0009)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [], set(), set(), [0x10, 0x80]
        )
        self.assertEqual(result["nop_delay_callback_sites_without_writer_in_candidate_function"], 1)

    def test_non_nop_copy_is_not_counted_as_nop(self):
        data = bytearray(0x100)
        put16(data, 0x42, 0x2211)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [], set(), {0x40}, [0x10, 0x80]
        )
        self.assertEqual(result["nop_delay_callback_sites_without_writer_in_candidate_function"], 0)
        self.assertEqual(result["length_copy_sites_without_writer_in_candidate_function"], 1)

    def test_paired_callback_is_excluded_from_unpaired_count(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x30, 0x40], [], {0x30}, set(), [0x10, 0x80]
        )
        self.assertEqual(result["unpaired_callback_sites"], 1)

    def test_missing_prologue_interval_fails_closed(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x20], [], set(), set(), [0x40]
        )
        self.assertEqual(result["unpaired_callback_sites_without_resolved_candidate_function"], 1)

    def test_writer_before_takes_precedence_if_both_present(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [0x20, 0x60], set(), set(), [0x10, 0x80]
        )
        self.assertEqual(result["unpaired_callback_sites_with_writer_before_in_candidate_function"], 1)
        self.assertEqual(result["unpaired_callback_sites_with_writer_after_in_candidate_function"], 0)

    def test_output_has_no_offsets_or_targets(self):
        data = bytearray(0x100)
        result = classify_unpaired_callback_contexts(
            data, [0x40], [0x60], set(), {0x40}, [0x10, 0x80]
        )
        rendered = json.dumps(result)
        for value in (hex(CALLBACK), hex(WRITER), "0x40", "0x60"):
            self.assertNotIn(value, rendered)
        self.assertFalse(result["candidate_function_intervals_prove_control_flow"])


if __name__ == "__main__":
    unittest.main()
