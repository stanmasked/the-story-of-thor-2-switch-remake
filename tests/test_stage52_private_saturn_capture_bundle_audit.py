"""Stage52 tests use generated RAM/VRAM, fabricated trace and synthetic SH-2."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage50_sh2_load_mapping_evidence import PROGRAM, ram_images
from test_stage48_vdp1_copy_witness import manifest, snapshots
from test_stage49_sh2_vdp1_trace_contract import valid_events
from stage51_saturn_boot_first_read_map import analyze_private as check_private_boot
from stage52_private_saturn_capture_bundle_audit import (
    MAX_SESSION_BYTES, validate_session, load_session, verify_hashes,
    digest_file, audit_bundle, run_private,
)


def fake_session(**overrides):
    fake = "a" * 64
    result = {
        "schema_version": 1,
        "emulator": {
            "name": "SyntheticSaturnTest",
            "version": "0.1-test",
            "build_sha256": fake,
            "bios_mode": "hle",
            "bios_sha256": None,
        },
        "capture": {
            "frame_before": 100,
            "frame_after": 101,
            "cycle_ram": 990,
            "cycle_vram_before": 1000,
            "cycle_trace_start": 1001,
            "cycle_trace_end": 1500,
            "cycle_vram_after": 1501,
        },
        "artifacts": {
            "high_ram": fake, "vram_before": fake, "vram_after": fake,
            "trace_jsonl": fake, "descriptor_manifest": fake,
            "source_commands": fake,
        },
    }
    result.update(overrides)
    return result


def case(source=True, verified=True, boot=True, session=None):
    m = manifest()
    before, after, src = snapshots(source=bytes(range(64)))
    events = valid_events()
    return audit_bundle(
        PROGRAM, ram_images(), before, after, m, events,
        src if source else None, fake_session() if session is None else session,
        verified_hashes=verified, boot_metadata_matches=boot,
    )


class Stage52BundleTests(unittest.TestCase):
    def test_joint_synthetic_pass_is_only_offline(self):
        r = case()
        self.assertTrue(r["all_operator_supplied_offline_checks_consistent"])
        self.assertFalse(r["authenticated_emulator_trace_observed"])
        self.assertFalse(r["sh2_gameplay_execution_proven"])

    def test_expected_store_count(self):
        r = case()
        self.assertEqual(r["expected_32bit_store_events"], 16)
        self.assertEqual(r["copied_32byte_commands"], 2)

    def test_no_artifact_checksum_validation_not_complete(self):
        r = case(verified=False)
        self.assertFalse(r["artifact_hashes_match_local_files"])
        self.assertFalse(r["all_operator_supplied_offline_checks_consistent"])

    def test_no_boot_metadata_not_complete(self):
        self.assertFalse(case(boot=False)["all_operator_supplied_offline_checks_consistent"])

    def test_trace_source_disagrees_with_vram_capture(self):
        b, a, src = snapshots()
        r = audit_bundle(PROGRAM, ram_images(), b, a, manifest(),
                         valid_events(), src, fake_session(), True, True)
        self.assertTrue(r["vdp1_command_snapshot_matches_stage48"])
        self.assertFalse(r["sh2_instruction_events_match_stage49"])
        self.assertFalse(r["all_operator_supplied_offline_checks_consistent"])

    def test_no_source_not_complete(self):
        r = case(source=False)
        self.assertFalse(r["source_command_capture_supplied"])
        self.assertFalse(r["all_operator_supplied_offline_checks_consistent"])

    def test_corrupt_ram_prevents_joint_match(self):
        before, after, src = snapshots(source=bytes(range(64)))
        r = audit_bundle(PROGRAM, bytes(0x100000), before, after, manifest(),
                         valid_events(), src, fake_session(), True, True)
        self.assertFalse(r["high_ram_mapping_uniquely_matches_stage50"])
        self.assertFalse(r["all_operator_supplied_offline_checks_consistent"])

    def test_corrupt_vram_prevents_joint_match(self):
        before, after, src = snapshots(source=bytes(range(64)))
        wrong = bytearray(after)
        wrong[9000] = 1
        r = audit_bundle(PROGRAM, ram_images(), before, bytes(wrong),
                         manifest(), valid_events(), src, fake_session(), True, True)
        self.assertFalse(r["vdp1_command_snapshot_matches_stage48"])
        self.assertEqual(r["unexplained_changed_vram_bytes"], 1)

    def test_bad_instruction_pc_prevents_joint_match(self):
        e = valid_events()
        e[2]["pc"] += 2
        b, a, src = snapshots(source=bytes(range(64)))
        r = audit_bundle(PROGRAM, ram_images(), b, a, manifest(),
                         e, src, fake_session(), True, True)
        self.assertFalse(r["sh2_instruction_events_match_stage49"])
        self.assertFalse(r["all_operator_supplied_offline_checks_consistent"])

    def test_wrong_r5_descriptor_count_prevents_joint_match(self):
        m = manifest(pending_count_before=1)
        e = valid_events(m)
        b, a, src = snapshots(source=bytes(range(64)))
        r = audit_bundle(PROGRAM, ram_images(), b, a, m, e, src,
                         fake_session(), True, True)
        self.assertFalse(r["vdp1_command_snapshot_matches_stage48"])

    def test_not_exporting_private_trace_addresses(self):
        r = case()
        txt = json.dumps(r)
        for field in ('"pc"', '"dest"', '"value"', '"raw_ram"', '"raw_code"',
                      '"bios_sha256"', '"build_sha256"', '"frame_before"'):
            self.assertNotIn(field, txt)
        self.assertFalse(r["private_game_bytes_or_addresses_exported"])

    def test_valid_hle_session(self):
        self.assertEqual(validate_session(fake_session())["schema_version"], 1)

    def test_valid_external_bios_session(self):
        s = fake_session()
        s["emulator"]["bios_mode"] = "external"
        s["emulator"]["bios_sha256"] = "1"*64
        self.assertEqual(validate_session(s)["emulator"]["bios_mode"], "external")

    def test_external_bios_requires_checksum(self):
        s = fake_session()
        s["emulator"]["bios_mode"] = "external"
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_hle_cannot_claim_external_bios_checksum(self):
        s = fake_session()
        s["emulator"]["bios_sha256"] = "f"*64
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_bad_hash_rejected(self):
        s = fake_session()
        s["artifacts"]["high_ram"] = "notahash"
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_uppercase_hash_rejected(self):
        s = fake_session()
        s["artifacts"]["high_ram"] = "ABCDEF"*10+"ABCD"
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_extra_session_fields_rejected(self):
        s = fake_session(unexpected="private")
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_bool_frame_rejected(self):
        s = fake_session()
        s["capture"]["frame_before"] = False
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_swapped_frame_rejected(self):
        s = fake_session()
        s["capture"]["frame_before"] = 999
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_capture_cycles_out_of_order(self):
        s = fake_session()
        s["capture"]["cycle_trace_start"] = 990
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_zero_length_trace_cycle_rejected(self):
        s = fake_session()
        s["capture"]["cycle_trace_end"] = s["capture"]["cycle_trace_start"]
        with self.assertRaises(ValueError):
            validate_session(s)

    def test_emulator_identity_is_self_declared(self):
        r = case()
        self.assertTrue(r["emulator_build_sha256_declared_by_operator"])
        self.assertFalse(r["authenticated_emulator_trace_observed"])
        self.assertFalse(r["boot_file_transfer_dynamically_verified"])

    def test_duplicate_session_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"session.json"
            p.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_session(p)

    def test_session_size_limit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"session.json"
            p.write_bytes(b"x"*(MAX_SESSION_BYTES+1))
            with self.assertRaises(ValueError):
                load_session(p)

    def test_source_may_be_absent_from_manifest(self):
        s = fake_session()
        s["artifacts"]["source_commands"] = None
        self.assertIsNone(validate_session(s)["artifacts"]["source_commands"])

    def test_files_verify_all_six_hashes(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            keys = ("high_ram", "vram_before", "vram_after", "trace_jsonl",
                    "descriptor_manifest", "source_commands")
            paths = {}
            s = fake_session()
            for i, key in enumerate(keys):
                paths[key] = p / (key + ".private")
                paths[key].write_bytes(bytes([i])*100)
                s["artifacts"][key] = digest_file(paths[key])
            self.assertTrue(verify_hashes(s, paths))
            paths["trace_jsonl"].write_bytes(b"x")
            with self.assertRaises(ValueError):
                verify_hashes(s, paths)

    def test_missing_source_rejected_when_hash_declared(self):
        s = fake_session()
        with self.assertRaises(ValueError):
            verify_hashes(s, dict.fromkeys(s["artifacts"], None))

    def test_unexpected_supplied_source_rejected_when_hash_null(self):
        s = fake_session()
        s["artifacts"]["source_commands"] = None
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            paths = {}
            for key in s["artifacts"]:
                paths[key] = p/(key+".bin")
                paths[key].write_bytes(b"test")
                if key != "source_commands":
                    s["artifacts"][key] = digest_file(paths[key])
            with self.assertRaises(ValueError):
                verify_hashes(s, paths)

    def test_synthetic_disc_cannot_pass_original_iso_pin(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            fake_iso = p/"fake.iso"
            fake_iso.write_bytes(b"bad")
            with self.assertRaises(ValueError):
                check_private_boot(fake_iso)


if __name__ == "__main__":
    unittest.main()
