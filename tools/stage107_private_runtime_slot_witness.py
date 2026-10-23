#!/usr/bin/env python3
"""Stage107 private SH-2 service-slot capture pair consistency verifier.

Consumes exactly two private instrumented runtime traces plus a SHA-256 manifest.
No ISO, BIOS, RAM dump, emulator binary, raw code, addresses or register values
are ever emitted. A capture pair can be fabricated; this CANNOT authenticate
emulator execution or independently name the BIOS function as SYS_CHGSCUIM.
Only sanitized aggregate status/error codes may be committed to public CI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SOURCE_ISO_SHA256 = "25b0b2774d4621bd9f95a01fc5420ded37b481b61b3cdf515360d82b2cb7bb0d"
SOURCE_ISO_SIZE = 106_954_752
KNOWN_EXTERNAL_BIOS = {
    "E": "96e106f740ab448cf89f0dd49dfbac7fe5391cb6bd6e14ad5e3061c13330266f",
    "J": "dcfef4b99605f872b6c3b6d05c045385cdea3d1b702906a0ed930df7bcb7deac",
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ADDR = re.compile(r"0x[0-9a-f]{8}\Z")
IDENT = re.compile(r"[a-zA-Z0-9_-]{8,64}\Z")
MAX_MANIFEST = 4096
MAX_TRACE = 131072
MAX_CALLS_PER_SESSION = 64


class EvidenceError(ValueError):
    """Codes must not include private file names, offsets, or event values."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise EvidenceError(code)


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    output: dict = {}
    for key, value in pairs:
        _require(key not in output, "duplicate_json_key")
        output[key] = value
    return output


def _exact(obj: object, keys: set[str], code: str) -> dict:
    _require(type(obj) is dict and set(obj) == keys, code)
    return obj


def _sha(value: object) -> bool:
    return type(value) is str and SHA256.fullmatch(value) is not None


def _digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load(path: Path, max_bytes: int) -> dict:
    try:
        _require(path.is_file() and not path.is_symlink(), "not_regular_capture_file")
        _require(0 < path.stat().st_size <= max_bytes, "capture_size_invalid")
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates)
        _require(type(data) is dict, "invalid_capture_document")
        return data
    except EvidenceError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise EvidenceError("capture_document_unreadable") from None


def _manifest(m: dict) -> dict:
    _exact(m, {"schema_version", "source_iso", "emulator", "captures"}, "manifest_fields_invalid")
    _require(type(m["schema_version"]) is int and m["schema_version"] == 1, "manifest_schema_invalid")
    iso = _exact(m["source_iso"], {"sha256", "size_bytes"}, "iso_identity_fields_invalid")
    _require(iso["sha256"] == SOURCE_ISO_SHA256 and type(iso["size_bytes"]) is int and
             iso["size_bytes"] == SOURCE_ISO_SIZE, "iso_identity_mismatch")
    emu = _exact(m["emulator"], {"name", "version", "build_sha256", "bios_mode", "bios_region", "bios_sha256"}, "emulator_fields_invalid")
    for field in ("name", "version"):
        _require(type(emu[field]) is str and 1 <= len(emu[field]) <= 80 and emu[field] == emu[field].strip(), "emulator_identity_invalid")
    _require(_sha(emu["build_sha256"]), "emulator_build_identity_invalid")
    _require(emu["bios_mode"] == "external", "hle_bios_does_not_prove_external_bios_behavior")
    _require(type(emu["bios_region"]) is str and emu["bios_region"] == "E" and
             emu["bios_sha256"] == KNOWN_EXTERNAL_BIOS["E"], "external_bios_identity_mismatch")
    caps = _exact(m["captures"], {"a", "b"}, "capture_manifest_fields_invalid")
    for name in ("a", "b"):
        rec = _exact(caps[name], {"sha256", "size_bytes"}, "capture_metadata_fields_invalid")
        _require(_sha(rec["sha256"]) and type(rec["size_bytes"]) is int and
                 1 <= rec["size_bytes"] <= MAX_TRACE, "capture_metadata_invalid")
    _require(caps["a"]["sha256"] != caps["b"]["sha256"], "duplicate_capture_hash")
    return m


def _trace(trace: dict, manifest: dict) -> dict:
    _exact(trace, {"schema_version", "session_id", "source_iso_sha256", "emulator_build_sha256",
                   "bios_sha256", "events"}, "trace_fields_invalid")
    _require(type(trace["schema_version"]) is int and trace["schema_version"] == 1, "trace_schema_invalid")
    _require(type(trace["session_id"]) is str and IDENT.fullmatch(trace["session_id"]) is not None, "session_id_invalid")
    _require(trace["source_iso_sha256"] == SOURCE_ISO_SHA256 and
             trace["emulator_build_sha256"] == manifest["emulator"]["build_sha256"] and
             trace["bios_sha256"] == manifest["emulator"]["bios_sha256"], "trace_provenance_mismatch")
    events = trace["events"]
    _require(type(events) is list and 3 <= len(events) <= MAX_CALLS_PER_SESSION * 3
             and len(events) % 3 == 0, "trace_event_count_invalid")
    prev_cycle = -1
    calls = []
    for i, event in enumerate(events):
        e = _exact(event, {"kind", "cycle", "call_id", "slot_address", "caller_pc",
                           "target_address", "r13"}, "event_fields_invalid")
        expected_kind = ("slot_read", "call_entry", "call_return")[i % 3]
        _require(e["kind"] == expected_kind, "event_order_invalid")
        _require(type(e["cycle"]) is int and 0 <= e["cycle"] < (1 << 63)
                 and e["cycle"] > prev_cycle, "event_cycle_order_invalid")
        prev_cycle = e["cycle"]
        _require(type(e["call_id"]) is str and IDENT.fullmatch(e["call_id"]) is not None,
                 "call_id_invalid")
        for field in ("slot_address", "caller_pc", "target_address", "r13"):
            _require(type(e[field]) is str and ADDR.fullmatch(e[field]) is not None, "event_hex_field_invalid")
        _require(e["target_address"] != "0x00000000", "null_target_invalid")
        if i % 3 == 2:
            before, entry, returned = events[i - 2:i + 1]
            for field in ("call_id", "slot_address", "caller_pc", "target_address"):
                _require(before[field] == entry[field] == returned[field], "call_identity_mismatch")
            _require(entry["r13"] == returned["r13"], "r13_modified_in_capture")
            _require(all(call["call_id"] != returned["call_id"] for call in calls), "duplicate_call_id")
            calls.append(returned)
    _require(len({c["slot_address"] for c in calls}) == 1 and
             len({c["target_address"] for c in calls}) == 1, "intra_session_target_inconsistent")
    return {"session_id": trace["session_id"], "slot": calls[0]["slot_address"],
            "target": calls[0]["target_address"], "call_count": len(calls)}


def audit(manifest_path: Path, trace_a_path: Path, trace_b_path: Path) -> dict:
    """Only successful, internally consistent input is reported; never public runtime proof."""
    m = _manifest(_load(manifest_path, MAX_MANIFEST))
    _require(trace_a_path.resolve() != trace_b_path.resolve(), "capture_paths_identical")
    summaries = []
    for label, path in (("a", trace_a_path), ("b", trace_b_path)):
        _require(path.is_file() and not path.is_symlink(), "not_regular_capture_file")
        _require(path.stat().st_size == m["captures"][label]["size_bytes"] and
                 _digest_file(path) == m["captures"][label]["sha256"], "capture_checksum_mismatch")
        summaries.append(_trace(_load(path, MAX_TRACE), m))
    _require(summaries[0]["session_id"] != summaries[1]["session_id"], "session_ids_not_independent")
    _require(summaries[0]["slot"] == summaries[1]["slot"] and
             summaries[0]["target"] == summaries[1]["target"], "inter_session_target_mismatch")
    return {
        "schema_version": 1,
        "stage": "stage107_private_runtime_slot_witness",
        "analysis": {
            "provided_capture_pair_hashes_verified": True,
            "distinct_session_ids_and_capture_hashes": True,
            "claimed_external_bios_hash_matches_known_reference": True,
            "same_slot_and_target_in_both_supplied_captures": True,
            "r13_preserved_in_supplied_call_return_events": True,
            "total_matching_calls_in_supplied_captures": sum(s["call_count"] for s in summaries),
            "runtime_execution_independently_authenticated": False,
            "runtime_target_independently_identified_as_sys_chgscuim": False,
            "specific_bios_r13_preservation_independently_proven": False,
            "raw_register_values_or_addresses_emitted": False,
        },
    }


def safe_result(manifest_path: Path, a: Path, b: Path) -> dict:
    try:
        return audit(manifest_path, a, b)
    except EvidenceError as ex:
        code = str(ex)
    except (OSError, TypeError, OverflowError):
        code = "invalid_or_missing_capture_input"
    return {"schema_version": 1, "stage": "stage107_private_runtime_slot_witness",
                "analysis": {"provided_capture_pair_hashes_verified": False,
                             "runtime_execution_independently_authenticated": False,
                             "runtime_target_independently_identified_as_sys_chgscuim": False,
                             "specific_bios_r13_preservation_independently_proven": False,
                             "validation_error_codes": [code],
                             "raw_register_values_or_addresses_emitted": False}}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("manifest", type=Path)
    p.add_argument("private_capture_a", type=Path)
    p.add_argument("private_capture_b", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    out = safe_result(args.manifest, args.private_capture_a, args.private_capture_b)
    rendered = json.dumps(out, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if out["analysis"].get("provided_capture_pair_hashes_verified") is not True:
        raise SystemExit(2)


if __name__ == "__main__":
    main()