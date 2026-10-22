"""Stage48 synthetic-only model tests; no original Saturn assets or RAM traces."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage48_vdp1_copy_witness import (
    VRAM_BYTES, COMMAND_BYTES, MAX_DESCRIPTORS,
    parse_manifest, audit_witness, load_manifest, run_private,
)


def manifest(records=None, **overrides):
    result = {
        "schema_version": 1,
        "status_before": -1,
        "status_after": 0,
        "pending_count_before": 2,
        "pending_count_after": 0,
        "descriptors": records if records is not None else [
            {"destination_index": 0, "copy_count": 1},
            {"destination_index": 8, "copy_count": 1},
        ],
    }
    result.update(overrides)
    return result


def snapshots(records=None, source=None):
    records = records if records is not None else manifest()["descriptors"]
    before = bytes(VRAM_BYTES)
    source = source if source is not None else bytes([1] * (sum(x["copy_count"] for x in records)*32))
    after = bytearray(before)
    pos = 0
    for x in records:
        count = x["copy_count"]*32
        off = x["destination_index"]*8
        after[off:off+count] = source[pos:pos+count]
        pos += count
    return before, bytes(after), source


class Stage48WitnessTests(unittest.TestCase):
    def report(self, obj=None, after=None, source=None):
        obj = obj if obj is not None else manifest()
        before, expected_after, expected_source = snapshots(obj["descriptors"])
        return audit_witness(obj, before, after if after is not None else expected_after,
                             source if source is not None else expected_source)

    def test_valid_two_descriptors_two_copies(self):
        r = self.report()
        self.assertEqual(r["descriptor_count"], 2)
        self.assertEqual(r["commands_expected_by_descriptors"], 2)
        self.assertTrue(r["pending_count_matches_commands_not_descriptors"])

    def test_exact_vram_reconstruction(self):
        r = self.report()
        self.assertTrue(r["predicted_vram_equals_after_dump"])
        self.assertEqual(r["predicted_vs_observed_mismatching_vram_bytes"], 0)
        self.assertTrue(r["copy_path_consistent_with_observation"])

    def test_counter_after_must_be_zero_for_consistency(self):
        r = self.report(manifest(pending_count_after=2))
        self.assertFalse(r["post_return_zero_resets_observed_in_manifest"])
        self.assertFalse(r["copy_path_consistent_with_observation"])

    def test_status_after_must_be_zero(self):
        r = self.report(manifest(status_after=-1))
        self.assertFalse(r["copy_path_consistent_with_observation"])

    def test_flag_must_be_negative(self):
        r = self.report(manifest(status_before=0))
        self.assertFalse(r["negative_flag_and_nonzero_count_observed_in_manifest"])
        self.assertFalse(r["copy_path_consistent_with_observation"])

    def test_global_count_must_be_nonzero(self):
        r = self.report(manifest(pending_count_before=0))
        self.assertFalse(r["copy_path_consistent_with_observation"])

    def test_per_descriptor_count_budget_mismatch(self):
        r = self.report(manifest(pending_count_before=1))
        self.assertFalse(r["pending_count_matches_commands_not_descriptors"])
        self.assertTrue(r["predicted_vram_equals_after_dump"])
        self.assertFalse(r["copy_path_consistent_with_observation"])

    def test_count_descriptors_not_same_as_commands(self):
        records = [{"destination_index": 0, "copy_count": 2}]
        r = self.report(manifest(records, pending_count_before=2))
        self.assertFalse(r["pending_count_equals_descriptor_count"])
        self.assertTrue(r["pending_count_matches_commands_not_descriptors"])

    def test_detect_outside_write(self):
        obj = manifest()
        b, a, src = snapshots()
        tampered = bytearray(a)
        tampered[0x8000] = 88
        r = audit_witness(obj, b, bytes(tampered), src)
        self.assertEqual(r["observed_changed_bytes_outside_expected_write_ranges"], 1)
        self.assertFalse(r["predicted_vram_equals_after_dump"])

    def test_detect_inside_wrong_byte(self):
        b, a, src = snapshots()
        tampered = bytearray(a)
        tampered[7] = 5
        r = audit_witness(manifest(), b, bytes(tampered), src)
        self.assertEqual(r["predicted_vs_observed_mismatching_vram_bytes"], 1)
        self.assertEqual(r["observed_changed_bytes_outside_expected_write_ranges"], 0)

    def test_source_capture_optional(self):
        before, after, _ = snapshots()
        r = audit_witness(manifest(), before, after)
        self.assertIsNone(r["predicted_vram_equals_after_dump"])
        self.assertFalse(r["private_source_capture_supplied"])
        self.assertFalse(r["copy_path_consistent_with_observation"])

    def test_identical_before_and_after_not_strong_witness(self):
        before = bytes(VRAM_BYTES)
        r = audit_witness(manifest(), before, before, bytes(64))
        self.assertTrue(r["predicted_vram_equals_after_dump"])
        self.assertFalse(r["copy_path_consistent_with_observation"])

    def test_wrong_source_size_rejected(self):
        before, after, _ = snapshots()
        with self.assertRaises(ValueError):
            audit_witness(manifest(), before, after, bytes(32))

    def test_short_before_dump_rejected(self):
        _, after, source = snapshots()
        with self.assertRaises(ValueError):
            audit_witness(manifest(), b"\0", after, source)

    def test_long_after_dump_rejected(self):
        before, after, source = snapshots()
        with self.assertRaises(ValueError):
            audit_witness(manifest(), before, after+b"\0", source)

    def test_reject_non_bytes_source(self):
        before, after, _ = snapshots()
        with self.assertRaises(ValueError):
            audit_witness(manifest(), before, after, bytearray(64))

    def test_uneven_destination_is_reported(self):
        records = [{"destination_index": 1, "copy_count": 1}]
        r = self.report(manifest(records, pending_count_before=1))
        self.assertEqual(r["destinations_not_32_byte_aligned"], 1)

    def test_overlapping_targets_apply_in_order(self):
        records = [
            {"destination_index": 0, "copy_count": 1},
            {"destination_index": 0, "copy_count": 1},
        ]
        source = bytes([1]*32 + [2]*32)
        b, a, _ = snapshots(records, source)
        r = audit_witness(manifest(records), b, a, source)
        self.assertEqual(r["overwritten_vram_bytes_in_overlap"], 32)
        self.assertTrue(r["predicted_vram_equals_after_dump"])

    def test_nonoverlapping_boundary(self):
        records = [{"destination_index": (VRAM_BYTES-32)//8, "copy_count": 1}]
        r = self.report(manifest(records, pending_count_before=1))
        self.assertTrue(r["predicted_vram_equals_after_dump"])

    def test_outside_vram_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest([{"destination_index": 65535, "copy_count": 2}]))

    def test_empty_descriptor_list_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest([]))

    def test_more_than_512_descriptors_rejected(self):
        records = [{"destination_index": 0, "copy_count": 1}]*(MAX_DESCRIPTORS + 1)
        with self.assertRaises(ValueError):
            parse_manifest(manifest(records))

    def test_up_to_512_allowed(self):
        records = [{"destination_index": 0, "copy_count": 1}]*MAX_DESCRIPTORS
        self.assertEqual(len(parse_manifest(manifest(records))["descriptors"]), 512)

    def test_oversized_total_rejected(self):
        records = [{"destination_index": 0, "copy_count": 16384},
                   {"destination_index": 0, "copy_count": 1}]
        with self.assertRaises(ValueError):
            parse_manifest(manifest(records))

    def test_negative_signed_copy_count_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest([{"destination_index": 0, "copy_count": -1}]))

    def test_zero_copy_count_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest([{"destination_index": 0, "copy_count": 0}]))

    def test_bool_is_not_valid_integer(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest(pending_count_before=True))

    def test_float_is_not_valid_integer(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest(status_before=-1.0))

    def test_invalid_version_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest(schema_version=2))

    def test_unknown_manifest_fields_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest(comment="private original instructions"))

    def test_unknown_descriptor_fields_rejected(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest([{"destination_index": 0, "copy_count": 1,
                                      "source_pointer": "private"}]))

    def test_wrong_status_range(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest(status_before=-129))

    def test_wrong_budget_range(self):
        with self.assertRaises(ValueError):
            parse_manifest(manifest(pending_count_before=65536))

    def test_no_raw_game_bytes_or_address_exposed(self):
        r = self.report()
        content = json.dumps(r)
        for key in ("source_pointer", "destination_index", "source_commands",
                    "raw_vram", "vram_offset", "pc", "raw_bytes"):
            self.assertNotIn('"'+key+'"', content)
        self.assertFalse(r["emulator_origin_authenticated"])
        self.assertFalse(r["stage45_46_runtime_execution_proven"])
        self.assertFalse(r["handler_39_to_vdp1_proven"])

    def test_private_file_roundtrip(self):
        b, a, src = snapshots()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [root / x for x in ("manifest.json", "before.bin", "after.bin", "source.bin")]
            paths[0].write_text(json.dumps(manifest()), encoding="utf-8")
            paths[1].write_bytes(b)
            paths[2].write_bytes(a)
            paths[3].write_bytes(src)
            out = run_private(*paths)
            self.assertTrue(out["copy_path_consistent_with_observation"])

    def test_manifest_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/"capture.json"
            p.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest(p)

    def test_manifest_size_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/"large.json"
            p.write_bytes(b" " * 262145)
            with self.assertRaises(ValueError):
                load_manifest(p)

    def test_private_binary_preflight_rejects_wrong_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/"manifest.json").write_text(json.dumps(manifest()), encoding="utf-8")
            (p/"before.bin").write_bytes(b"x")
            (p/"after.bin").write_bytes(bytes(VRAM_BYTES))
            with self.assertRaises(ValueError):
                run_private(p/"manifest.json", p/"before.bin", p/"after.bin")

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_cli_creates_private_0600_report(self):
        b, a, src = snapshots()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/"manifest.json").write_text(json.dumps(manifest()), encoding="utf-8")
            (p/"before.bin").write_bytes(b)
            (p/"after.bin").write_bytes(a)
            (p/"source.bin").write_bytes(src)
            report = p/"report.json"
            command = [sys.executable, str(Path(__file__).parents[1]/"tools"/"stage48_vdp1_copy_witness.py"),
                       "--manifest-private", str(p/"manifest.json"),
                       "--before-vram-private", str(p/"before.bin"),
                       "--after-vram-private", str(p/"after.bin"),
                       "--source-commands-private", str(p/"source.bin"),
                       "--output-private", str(report)]
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            self.assertTrue(json.loads(report.read_text())["predicted_vram_equals_after_dump"])
            duplicate = subprocess.run(command, capture_output=True)
            self.assertNotEqual(duplicate.returncode, 0)


if __name__ == '__main__':
    unittest.main()
