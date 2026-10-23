"""Stage107 synthetic fixtures only: not emulator/runtime evidence."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stage107_private_runtime_slot_witness import (
    SOURCE_ISO_SHA256, SOURCE_ISO_SIZE, KNOWN_EXTERNAL_BIOS, audit,
    safe_result, EvidenceError,
)


def fake_trace(session, base_cycle):
    events = []
    for i, kind in enumerate(("slot_read", "call_entry", "call_return")):
        events.append({"kind": kind, "cycle": base_cycle + i, "call_id": "call_0001",
                       "slot_address": "0x00001000", "caller_pc": "0x00001234",
                       "target_address": "0x00004567", "r13": "0x00000001"})
    return {"schema_version": 1, "session_id": session,
            "source_iso_sha256": SOURCE_ISO_SHA256,
            "emulator_build_sha256": "a" * 64,
            "bios_sha256": KNOWN_EXTERNAL_BIOS["E"], "events": events}


def fixtures(folder):
    pair = [fake_trace("session_001A", 100), fake_trace("session_002B", 200)]
    manifest = {"schema_version": 1, "source_iso": {"sha256": SOURCE_ISO_SHA256,
                 "size_bytes": SOURCE_ISO_SIZE}, "emulator": {
                     "name": "synthetic-test", "version": "0.0", "build_sha256": "a" * 64,
                     "bios_mode": "external", "bios_region": "E",
                     "bios_sha256": KNOWN_EXTERNAL_BIOS["E"]}, "captures": {}}
    paths = []
    for k, d in zip(("a", "b"), pair):
        path = folder / (k + ".json")
        paths.append(path)
        path.write_text(json.dumps(d), encoding="utf8")
        data = path.read_bytes()
        manifest["captures"][k] = {"sha256": hashlib.sha256(data).hexdigest(),
                                   "size_bytes": len(data)}
    mf = folder / "manifest.json"
    mf.write_text(json.dumps(manifest), encoding="utf8")
    return mf, paths, manifest, pair


def save(folder, m, paths, pairs):
    for k, p, data in zip(("a", "b"), paths, pairs):
        p.write_text(json.dumps(data), encoding="utf8")
        payload = p.read_bytes()
        m["captures"][k] = {"sha256": hashlib.sha256(payload).hexdigest(),
                             "size_bytes": len(payload)}
    (folder / "manifest.json").write_text(json.dumps(m), encoding="utf8")


class Stage107CaptureWitnessTests(unittest.TestCase):
    def test_valid_synthetic_pair_only_internal_consistency(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, _, _ = fixtures(Path(temp))
            a = audit(mf, *paths)["analysis"]
            self.assertTrue(a["provided_capture_pair_hashes_verified"])
            self.assertTrue(a["same_slot_and_target_in_both_supplied_captures"])
            self.assertEqual(a["total_matching_calls_in_supplied_captures"], 2)
            self.assertFalse(a["runtime_execution_independently_authenticated"])
            self.assertFalse(a["runtime_target_independently_identified_as_sys_chgscuim"])
            self.assertFalse(a["specific_bios_r13_preservation_independently_proven"])

    def test_corrupted_trace_bytes_fail_even_if_json_still_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, _, _ = fixtures(Path(temp))
            paths[0].write_bytes(paths[0].read_bytes() + b" ")
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["capture_checksum_mismatch"])

    def test_wrong_iso_identity_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            m["source_iso"]["sha256"] = "b" * 64
            save(Path(temp), m, paths, pairs)
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["iso_identity_mismatch"])

    def test_hle_cannot_claim_real_external_bios(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            m["emulator"]["bios_mode"] = "hle"
            save(Path(temp), m, paths, pairs)
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["hle_bios_does_not_prove_external_bios_behavior"])

    def test_different_session_ids_required(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            pairs[1]["session_id"] = pairs[0]["session_id"]
            save(Path(temp), m, paths, pairs)
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["session_ids_not_independent"])

    def test_different_targets_fail_even_if_each_trace_self_consistent(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            for e in pairs[1]["events"]:
                e["target_address"] = "0x00006789"
            save(Path(temp), m, paths, pairs)
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["inter_session_target_mismatch"])

    def test_r13_change_before_return_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            pairs[0]["events"][2]["r13"] = "0x00000002"
            save(Path(temp), m, paths, pairs)
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["r13_modified_in_capture"])

    def test_broken_cycle_order_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            pairs[0]["events"][2]["cycle"] = 100
            save(Path(temp), m, paths, pairs)
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["event_cycle_order_invalid"])

    def test_wrong_call_identity_in_return_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            pairs[0]["events"][2]["call_id"] = "call_other"
            save(Path(temp), m, paths, pairs)
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["call_identity_mismatch"])

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, _, _ = fixtures(Path(temp))
            text = mf.read_text()
            mf.write_text(text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1))
            self.assertEqual(safe_result(mf, *paths)["analysis"]["validation_error_codes"],
                             ["duplicate_json_key"])

    def test_no_private_values_in_safe_error(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            pairs[0]["events"][0]["target_address"] = "0xaaaaaaaa"
            save(Path(temp), m, paths, pairs)
            out = json.dumps(safe_result(mf, *paths))
            self.assertNotIn("0xaaaaaaaa", out)
            self.assertNotIn("0x00001000", out)
            self.assertIn("call_identity_mismatch", out)

    def test_rejects_extra_raw_capture_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            mf, paths, m, pairs = fixtures(Path(temp))
            pairs[0]["events"][0]["ram_bytes"] = "deadbeef"
            save(Path(temp), m, paths, pairs)
            out = json.dumps(safe_result(mf, *paths))
            self.assertIn("event_fields_invalid", out)
            self.assertNotIn("deadbeef", out)


if __name__ == '__main__':
    unittest.main()