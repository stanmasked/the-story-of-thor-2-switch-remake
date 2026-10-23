import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage106_private_aggregate_replay import (
    assert_outside_git_tree, file_sha256, git_blob_sha1, replay,
)


class Stage106PrivateReplayTests(unittest.TestCase):
    def test_git_blob_matches_standard_format(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "script.py"
            p.write_bytes(b"print('hello')\n")
            expected = hashlib.sha1(b"blob 15\x00print('hello')\n").hexdigest()
            self.assertEqual(git_blob_sha1(p), expected)

    def test_bad_iso_fails_before_destination_created(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            image = root / "source.iso"
            image.write_bytes(b"synthetic-iso")
            output = root / "private-reports"
            with self.assertRaisesRegex(ValueError, "pinned identity"):
                replay(image, output, "a" * 64, 13, {}, {})
            self.assertFalse(output.exists())

    def test_rejects_destination_inside_git_worktree(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".git").mkdir()
            with self.assertRaisesRegex(ValueError, "outside Git"):
                assert_outside_git_tree(root / "results")

    def test_synthetic_replay_saves_manifest_and_runs_gate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            image = root / "fake.iso"
            image.write_bytes(b"synthetic fixture only")
            tool_dir = root / "tools"
            tool_dir.mkdir()
            commits = {"stage99": "a" * 40, "stage103": "b" * 40}
            blobs = {}
            for label, filename in (
                ("stage99", "stage99_callee_register_preservation_audit.py"),
                ("stage103", "stage103_sys_chgscuim_argument_audit.py"),
            ):
                p = tool_dir / filename
                p.write_text("print('synthetic')\n", encoding="utf-8")
                blobs[label] = git_blob_sha1(p)
            stage99 = {
                "schema_version": 1, "stage": "stage99_callee_register_preservation_audit",
                "analysis": {
                    "private_addresses_or_code_offsets_emitted": False,
                    "second_writer_source_register_seeded_to_one": True,
                    "pre_store_call_count": 3,
                    "second_writer_is_final_call_delay_slot": True,
                    "first_callee_has_unresolved_indirect_pointer_call": True,
                    "first_callee_direct_r13_write_count": 0,
                    "loader_wrapper_normal_success_path_preserves_r13": True,
                    "pre_store_call_summaries": [
                        {"role": "in_image_direct_callee", "r13_preservation_proven": True}
                    ],
                },
            }
            stage103 = {
                "schema_version": 1, "stage": "stage103_sys_chgscuim_argument_audit",
                "analysis": {
                    "private_addresses_or_code_offsets_emitted": False,
                    "documented_sys_chgscuim_argument_shape_compatible": True,
                    "all_scanned_slot_call_pairs_resolved": 11,
                },
            }
            def fake_subprocess(argv, **kwargs):
                doc = stage99 if "stage99_" in argv[1] else stage103
                Path(argv[-1]).write_text(json.dumps(doc), encoding="utf-8")
                return CompletedProcess(argv, 0, "", "")
            dest = root / "evidence"
            with patch("stage106_private_aggregate_replay.subprocess.run", side_effect=fake_subprocess):
                result = replay(image, dest, file_sha256(image), image.stat().st_size,
                                commits, blobs, tool_dir)
            self.assertTrue(result["source_iso_verified"])
            self.assertTrue(result["gate"]["inputs_verified"])
            self.assertTrue(result["gate"]["conditional_static_claim_supported"])
            self.assertFalse(result["gate"]["runtime_r13_preservation_confirmed"])
            self.assertEqual(
                json.loads((dest / "00_Manifest_and_SHA256" / "stage106_rederived_manifest.json").read_text())
                ["sources"]["stage99"]["analyzer_git_blob_sha1"], blobs["stage99"]
            )
            with self.assertRaises(FileExistsError):
                with patch("stage106_private_aggregate_replay.subprocess.run", side_effect=fake_subprocess):
                    replay(image, dest, file_sha256(image), image.stat().st_size,
                           commits, blobs, tool_dir)


if __name__ == "__main__":
    unittest.main()
