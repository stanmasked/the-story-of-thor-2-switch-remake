#!/usr/bin/env python3
"""Stage106 private-only re-derivation of the original Stage99/103 aggregate JSON.

Run this on a protected machine with the original unmodified ISO and the exact
public analyzer source blobs identified in the private Stage99/103 manifests.
Never upload ISO/payloads/raw traces to GitHub Actions; CI uses fixtures only.
Outputs are *new re-derived files*, not the missing historical originals.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from stage105_evidence_archive_input_integrity import validate

SHA256 = re.compile(r"^[0-9a-f]{64}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")
STAGES = {
    "stage99": "stage99_callee_register_preservation_audit.py",
    "stage103": "stage103_sys_chgscuim_argument_audit.py",
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1(path: Path) -> str:
    content = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def assert_outside_git_tree(path: Path) -> None:
    resolved = path.resolve()
    if any((parent / ".git").exists() for parent in (resolved, *resolved.parents)):
        raise ValueError("private evidence destination must be outside Git working tree")


def replay(
    image: Path,
    dest: Path,
    iso_hash: str,
    iso_size: int,
    commits: dict[str, str],
    blobs: dict[str, str],
    scripts_dir: Path | None = None,
) -> dict:
    if not SHA256.fullmatch(iso_hash) or type(iso_size) is not int or iso_size <= 0:
        raise ValueError("invalid pinned ISO identity")
    if not image.is_file() or image.stat().st_size != iso_size or file_sha256(image) != iso_hash:
        raise ValueError("private ISO does not match pinned identity")
    assert_outside_git_tree(dest)
    scripts_dir = scripts_dir or Path(__file__).resolve().parent
    for label, script in STAGES.items():
        if not SHA1.fullmatch(commits[label]) or not SHA1.fullmatch(blobs[label]):
            raise ValueError(label + ": invalid provenance")
        if git_blob_sha1(scripts_dir / script) != blobs[label]:
            raise ValueError(label + ": analyzer blob differs from archived source")
    if dest.exists():
        raise FileExistsError("destination already exists; never overwrite private evidence")

    report_dir = dest / "03_Aggregate_Reports"
    manifest_dir = dest / "00_Manifest_and_SHA256"
    report_dir.mkdir(parents=True)
    manifest_dir.mkdir(parents=True)
    outputs = {}
    sources = {}
    for label, script in STAGES.items():
        path = report_dir / (label + "_stage106_rederived.json")
        result = subprocess.run(
            [sys.executable, str(scripts_dir / script), str(image), "-o", str(path)],
            cwd=scripts_dir, capture_output=True, text=True, check=False,
            timeout=180,
        )
        # Deliberately avoid logging stdout/stderr: even an exception could
        # contain local private paths, trace details or instruction bytes.
        if result.returncode != 0 or not path.is_file():
            raise RuntimeError(label + ": analyzer execution failed")
        outputs[label] = path
        sources[label] = {
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
            "source_commit": commits[label],
            "analyzer_git_blob_sha1": blobs[label],
            "rederived_from_original_iso": True,
        }
    manifest = {
        "source_iso": {"sha256": iso_hash, "size_bytes": iso_size},
        "sources": sources,
        "provenance_note": (
            "Stage106 re-derived using the original analyzer Git blobs; "
            "these are not recovered copies of the historical aggregate JSON."
        ),
    }
    manifest_path = manifest_dir / "stage106_rederived_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    gate = validate(outputs["stage99"], outputs["stage103"], manifest_path)
    gate_path = report_dir / "stage106_stage105_gate.json"
    gate_path.write_text(json.dumps(gate, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if not gate["analysis"]["inputs_verified"]:
        raise RuntimeError("Stage105 integrity gate rejected private re-derived inputs")
    return {
        "source_iso_verified": True,
        "rederived_not_original_archived_files": True,
        "saved_outputs_sha256": {label: sources[label]["sha256"] for label in STAGES},
        "gate": gate["analysis"],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("private_iso", type=Path)
    p.add_argument("private_destination", type=Path)
    p.add_argument("--iso-sha256", required=True)
    p.add_argument("--iso-size", type=int, required=True)
    p.add_argument("--stage99-source-commit", required=True)
    p.add_argument("--stage103-source-commit", required=True)
    p.add_argument("--stage99-analyzer-blob", required=True)
    p.add_argument("--stage103-analyzer-blob", required=True)
    a = p.parse_args()
    result = replay(
        a.private_iso, a.private_destination, a.iso_sha256, a.iso_size,
        {"stage99": a.stage99_source_commit, "stage103": a.stage103_source_commit},
        {"stage99": a.stage99_analyzer_blob, "stage103": a.stage103_analyzer_blob},
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
