"""Stage50 synthetic-only SH-2 RAM image mapping tests; original ISO is not used."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage46_vdp1_submit_gate import fixture as stage46_fixture, GATE
from stage49_sh2_vdp1_trace_contract import SH2_LOAD_BASE, find_private_roles
from stage50_sh2_load_mapping_evidence import (
    RAM_BASE, ANCHOR_BYTES, EXPECTED_ROLE_COUNT, HIGH_WORK_RAM_BYTES,
    REFERENCE_ISO_SHA256, _roles, _score, _candidates, _iso_sha256,
    static_preflight, summarize, analyze_private,
)

PROGRAM = stage46_fixture()
EXPECTED = SH2_LOAD_BASE - RAM_BASE


def ram_images(offsets=(EXPECTED,), fill=0xA5, program=PROGRAM):
    data = bytearray([fill] * HIGH_WORK_RAM_BYTES)
    for off in offsets:
        data[off:off + len(program)] = program
    return bytes(data)


class Stage50MappingTests(unittest.TestCase):
    def test_full_synthetic_image_at_expected_load_base(self):
        report = summarize(PROGRAM, ram_images())
        self.assertTrue(report["expected_mapping_uniquely_supported_by_supplied_snapshot"])
        self.assertEqual(report["expected_mapping_role_matches"], 12)

    def test_twelve_unique_private_pc_roles(self):
        roles = _roles(PROGRAM)
        self.assertEqual(len(roles), EXPECTED_ROLE_COUNT)
        self.assertEqual(len(set(pos for pos, _ in roles)), 12)

    def test_signature_size(self):
        for _, code in _roles(PROGRAM):
            self.assertEqual(len(code), ANCHOR_BYTES)

    def test_complete_mapping_discovery(self):
        locations, seeds = _candidates(ram_images(), _roles(PROGRAM))
        self.assertEqual(locations, [EXPECTED])
        self.assertGreaterEqual(seeds, 1)

    def test_runnable_program_not_claimed(self):
        r = summarize(PROGRAM, ram_images())
        self.assertFalse(r["emulator_origin_authenticated"])
        self.assertFalse(r["actual_sh2_execution_observed"])
        self.assertFalse(r["inferred_load_base_observed_in_authenticated_execution"])

    def test_static_preflight_does_not_claim_ram_capture(self):
        r = static_preflight(PROGRAM)
        self.assertFalse(r["high_work_ram_bytes_supplied"])
        self.assertFalse(r["untrusted_ram_mapping_matches_at_expected_base"])
        self.assertEqual(r["static_sh2_role_count"], 12)

    def test_summarize_without_snapshot(self):
        r = summarize(PROGRAM)
        self.assertIsNone(r["expected_mapping_role_matches"])
        self.assertFalse(r["expected_mapping_uniquely_supported_by_supplied_snapshot"])

    def test_empty_or_wrong_program_rejected(self):
        with self.assertRaises(ValueError):
            summarize(bytes(len(PROGRAM)), ram_images())

    def test_no_code_in_supplied_snapshot(self):
        r = summarize(PROGRAM, bytes([0x5A])*HIGH_WORK_RAM_BYTES)
        self.assertEqual(r["expected_mapping_role_matches"], 0)
        self.assertEqual(r["complete_static_image_mapping_candidates"], 0)

    def test_relocated_program_not_confused_with_expected_base(self):
        alternative = EXPECTED + 0x4000
        r = summarize(PROGRAM, ram_images((alternative,)))
        self.assertEqual(r["expected_mapping_role_matches"], 0)
        self.assertEqual(r["complete_alternative_image_mapping_candidates"], 1)
        self.assertFalse(r["expected_mapping_uniquely_supported_by_supplied_snapshot"])

    def test_duplicate_full_program_rejects_unique_claim(self):
        alternative = EXPECTED + 0x4000
        r = summarize(PROGRAM, ram_images((EXPECTED, alternative)))
        self.assertEqual(r["complete_static_image_mapping_candidates"], 2)
        self.assertEqual(r["complete_alternative_image_mapping_candidates"], 1)
        self.assertFalse(r["expected_mapping_uniquely_supported_by_supplied_snapshot"])
        self.assertTrue(r["runtime_image_mapping_observed"])

    def test_one_corrupt_role_breaks_full_mapping(self):
        data = bytearray(ram_images())
        first, _ = _roles(PROGRAM)[0]
        data[EXPECTED + first] ^= 0x55
        r = summarize(PROGRAM, bytes(data))
        self.assertLess(r["expected_mapping_role_matches"], 12)
        self.assertFalse(r["expected_mapping_uniquely_supported_by_supplied_snapshot"])

    def test_mutated_writer_pc_rejected(self):
        data = bytearray(ram_images())
        first = _roles(PROGRAM)[2][0]
        data[EXPECTED + first] ^= 0x80
        r = summarize(PROGRAM, bytes(data))
        self.assertLess(r["expected_mapping_role_matches"], 12)

    def test_exact_size_enforced_short(self):
        with self.assertRaises(ValueError):
            summarize(PROGRAM, b"\0" * (HIGH_WORK_RAM_BYTES - 1))

    def test_exact_size_enforced_long(self):
        with self.assertRaises(ValueError):
            summarize(PROGRAM, b"\0" * (HIGH_WORK_RAM_BYTES + 1))

    def test_bytearray_rejected(self):
        with self.assertRaises(ValueError):
            summarize(PROGRAM, bytearray(HIGH_WORK_RAM_BYTES))

    def test_memoryview_rejected(self):
        with self.assertRaises(ValueError):
            summarize(PROGRAM, memoryview(bytes(HIGH_WORK_RAM_BYTES)))

    def test_score_at_expected_base(self):
        self.assertEqual(_score(ram_images(), _roles(PROGRAM), EXPECTED), 12)

    def test_score_at_mismatched_base(self):
        self.assertEqual(_score(ram_images(), _roles(PROGRAM), EXPECTED + 0x2000), 0)

    def test_score_does_not_overrun_snapshot(self):
        self.assertEqual(_score(ram_images(), _roles(PROGRAM), HIGH_WORK_RAM_BYTES), 0)

    def test_negative_base_not_accepted(self):
        self.assertEqual(_score(ram_images(), _roles(PROGRAM), -HIGH_WORK_RAM_BYTES), 0)

    def test_no_private_pc_exposed_in_aggregate_report(self):
        r = summarize(PROGRAM, ram_images())
        serialized = json.dumps(r)
        private = find_private_roles(PROGRAM)
        for pc in [private["gate"], private["jsr"], *private["stores"],
                   private["copy_rts"], private["submit_rts"]]:
            self.assertNotIn(str(pc), serialized)
            self.assertNotIn(hex(pc), serialized)
        for forbidden in ('"pc"', '"raw_code"', '"ram_address"',
                          '"image_start"', '"code_offset"', '"bytes"'):
            self.assertNotIn(forbidden, serialized)

    def test_pinned_sha_is_64_hex_characters(self):
        self.assertEqual(len(REFERENCE_ISO_SHA256), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in REFERENCE_ISO_SHA256))

    def test_wrong_iso_checksum_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "different.iso"
            p.write_bytes(b"not original")
            with self.assertRaises(ValueError):
                analyze_private(p)

    def test_oversized_iso_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "oversized.iso"
            with p.open("wb") as stream:
                stream.truncate(256*1024*1024 + 1)
            with self.assertRaises(ValueError):
                _iso_sha256(p)

    def test_empty_iso_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "empty.iso"
            p.write_bytes(b"")
            with self.assertRaises(ValueError):
                _iso_sha256(p)

    def test_wrong_ram_size_still_fails_with_static_program(self):
        with self.assertRaises(ValueError):
            summarize(PROGRAM, bytes(512))

    def test_static_pattern_diversity(self):
        self.assertGreaterEqual(static_preflight(PROGRAM)["unique_static_role_sample_patterns"], 4)


if __name__ == "__main__":
    unittest.main()
