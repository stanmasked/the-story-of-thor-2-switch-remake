#!/usr/bin/env python3
"""Stage105: fail-closed provenance and integrity checks for the Stage104 evidence gate.

Input is exactly two saved, sanitized JSON artifacts (Stage99 and Stage103),
plus a manifest recording SHA-256, sizes, source ISO identity and tool commits.
Never reads or exports ROM/ISO data and never prints source JSON contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from stage104_r13_abi_evidence_gate import evaluate

EXPECTED_STAGES = {
    "stage99": "stage99_callee_register_preservation_audit",
    "stage103": "stage103_sys_chgscuim_argument_audit",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_KEYS = {"raw_bytes", "instruction_bytes", "ram_dump", "code_offsets", "private_path", "iso_payload"}


def validate(stage99_path: Path, stage103_path: Path, manifest_path: Path) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sources = manifest.get("sources", {})
    errors = []
    docs = {}

    iso_identity = manifest.get("source_iso", {})
    if not (isinstance(iso_identity.get("sha256"), str)
            and SHA256.fullmatch(iso_identity["sha256"])
            and isinstance(iso_identity.get("size_bytes"), int)
            and iso_identity["size_bytes"] > 0):
        errors.append("missing_source_iso_identity")

    for label, path in (("stage99", stage99_path), ("stage103", stage103_path)):
        info = sources.get(label, {})
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        byte_size = path.stat().st_size
        if not (isinstance(info.get("sha256"), str)
                and SHA256.fullmatch(info["sha256"])
                and info["sha256"] == digest):
            errors.append(label + "_sha256_mismatch_or_missing")
        if type(info.get("size_bytes")) is not int or info["size_bytes"] != byte_size:
            errors.append(label + "_size_mismatch_or_missing")
        if not (isinstance(info.get("source_commit"), str)
                and re.fullmatch(r"[0-9a-f]{40}", info["source_commit"])):
            errors.append(label + "_source_commit_missing")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError):
            errors.append(label + "_not_valid_utf8_json")
            continue
        if doc.get("stage") != EXPECTED_STAGES[label] or doc.get("schema_version") != 1:
            errors.append(label + "_stage_or_schema_mismatch")
        analysis = doc.get("analysis", {})
        if not isinstance(analysis, dict) or analysis.get("private_addresses_or_code_offsets_emitted") is not False:
            errors.append(label + "_privacy_marker_missing")
        if isinstance(analysis, dict) and any(k in analysis for k in FORBIDDEN_KEYS):
            errors.append(label + "_forbidden_raw_field")
        docs[label] = doc

    evidence_available = not errors and len(docs) == 2
    gated = evaluate(docs["stage99"], docs["stage103"]) if evidence_available else None
    return {
        "schema_version": 1,
        "stage": "stage105_evidence_archive_input_integrity",
        "analysis": {
            "inputs_verified": evidence_available,
            "source_iso_identity_recorded": "missing_source_iso_identity" not in errors,
            "evidence_gate_executed_on_verified_inputs": gated is not None,
            "conditional_static_claim_supported": (
                gated["analysis"]["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
                if gated is not None else False
            ),
            "runtime_target_confirmed": False,
            "runtime_r13_preservation_confirmed": False,
            "unconditional_r13_one_proven": False,
            "validation_error_codes": sorted(set(errors)),
            "private_addresses_or_code_offsets_emitted": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage99_report", type=Path)
    parser.add_argument("stage103_report", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    result = validate(args.stage99_report, args.stage103_report, args.manifest)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if not result["analysis"]["inputs_verified"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
