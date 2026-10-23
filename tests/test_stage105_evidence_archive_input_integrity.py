import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage105_evidence_archive_input_integrity import validate


def fixture(folder):
    s99 = {
        "schema_version": 1,
        "stage": "stage99_callee_register_preservation_audit",
        "analysis": {
            "private_addresses_or_code_offsets_emitted": False,
            "second_writer_source_register_seeded_to_one": True,
            "pre_store_call_count": 3,
            "second_writer_is_final_call_delay_slot": True,
            "first_callee_has_unresolved_indirect_pointer_call": True,
            "first_callee_direct_r13_write_count": 0,
            "loader_wrapper_normal_success_path_preserves_r13": True,
            "pre_store_call_summaries": [
                {"role": "in_image_direct_callee", "r13_preservation_proven": True},
            ],
        },
    }
    s103 = {
        "schema_version": 1,
        "stage": "stage103_sys_chgscuim_argument_audit",
        "analysis": {
            "private_addresses_or_code_offsets_emitted": False,
            "documented_sys_chgscuim_argument_shape_compatible": True,
            "all_scanned_slot_call_pairs_resolved": 11,
        },
    }
    paths = []
    sources = {}
    for label, doc in (("stage99", s99), ("stage103", s103)):
        p = folder / (label + ".json")
        p.write_text(json.dumps(doc), encoding="utf-8")
        paths.append(p)
        sources[label] = {
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "size_bytes": p.stat().st_size,
            "source_commit": "a" * 40,
        }
    manifest = {
        "source_iso": {"sha256": "b" * 64, "size_bytes": 106954752},
        "sources": sources,
    }
    mp = folder / "manifest.json"
    mp.write_text(json.dumps(manifest), encoding="utf-8")
    return paths[0], paths[1], mp, manifest


class Stage105IntegrityGateTests(unittest.TestCase):
    def test_valid_inputs_support_only_conditional_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b, m, _ = fixture(Path(temp))
            result = validate(a, b, m)["analysis"]
            self.assertTrue(result["inputs_verified"])
            self.assertTrue(result["evidence_gate_executed_on_verified_inputs"])
            self.assertTrue(result["conditional_static_claim_supported"])
            self.assertFalse(result["runtime_r13_preservation_confirmed"])
            self.assertFalse(result["unconditional_r13_one_proven"])

    def test_changed_bytes_fail_checksum(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b, m, _ = fixture(Path(temp))
            a.write_bytes(a.read_bytes() + b" ")
            result = validate(a, b, m)["analysis"]
            self.assertFalse(result["inputs_verified"])
            self.assertIn("stage99_sha256_mismatch_or_missing", result["validation_error_codes"])

    def test_wrong_stage_is_rejected_even_if_hashes_updated(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b, m, manifest = fixture(Path(temp))
            doc = json.loads(b.read_text())
            doc["stage"] = "stage99_callee_register_preservation_audit"
            b.write_text(json.dumps(doc))
            manifest["sources"]["stage103"]["sha256"] = hashlib.sha256(b.read_bytes()).hexdigest()
            manifest["sources"]["stage103"]["size_bytes"] = b.stat().st_size
            m.write_text(json.dumps(manifest))
            result = validate(a, b, m)["analysis"]
            self.assertIn("stage103_stage_or_schema_mismatch", result["validation_error_codes"])

    def test_missing_provenance_commit_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b, m, manifest = fixture(Path(temp))
            del manifest["sources"]["stage99"]["source_commit"]
            m.write_text(json.dumps(manifest))
            result = validate(a, b, m)["analysis"]
            self.assertFalse(result["evidence_gate_executed_on_verified_inputs"])

    def test_private_payload_field_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b, m, manifest = fixture(Path(temp))
            doc = json.loads(a.read_text())
            doc["analysis"]["raw_bytes"] = "should not appear"
            a.write_text(json.dumps(doc))
            manifest["sources"]["stage99"]["sha256"] = hashlib.sha256(a.read_bytes()).hexdigest()
            manifest["sources"]["stage99"]["size_bytes"] = a.stat().st_size
            m.write_text(json.dumps(manifest))
            result = validate(a, b, m)["analysis"]
            self.assertIn("stage99_forbidden_raw_field", result["validation_error_codes"])
            self.assertNotIn("should not appear", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
