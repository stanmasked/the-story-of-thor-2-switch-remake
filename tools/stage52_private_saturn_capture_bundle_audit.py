#!/usr/bin/env python3
"""Stage52: privacy-preserving joint audit of operator-provided Saturn captures.

Combines Stage50 load-map, Stage48 VDP1 VRAM reconstruction and Stage49 SH-2
event-order checks, with strict file digests and capture-order metadata.
An operator manifest can be fabricated: this NEVER authenticates execution.
No original ISO, BIOS, RAM, VRAM, PC, event words or source data are exported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from stage18_writer_guard_flow import iso_file_payload
from stage48_vdp1_copy_witness import (
    VRAM_BYTES, COMMAND_BYTES, load_manifest, audit_witness,
)
from stage49_sh2_vdp1_trace_contract import (
    MAX_COMMANDS_IN_TRACE, MAX_TRACE_BYTES, load_jsonl, compare_trace,
)
from stage50_sh2_load_mapping_evidence import (
    HIGH_WORK_RAM_BYTES, summarize as summarize_ram,
)
from stage51_saturn_boot_first_read_map import analyze_private as check_private_boot

MAX_SESSION_BYTES = 8192
MAX_CYCLE = (1 << 63) - 1
HASH_FIELDS = (
    "high_ram", "vram_before", "vram_after", "trace_jsonl",
    "descriptor_manifest", "source_commands",
)
ARTIFACT_NAMES = {
    "high_ram", "vram_before", "vram_after", "trace_jsonl",
    "descriptor_manifest", "source_commands",
}
SESSION_FIELDS = frozenset({"schema_version", "emulator", "capture", "artifacts"})
EMULATOR_FIELDS = frozenset({
    "name", "version", "build_sha256", "bios_mode", "bios_sha256",
})
CAPTURE_FIELDS = frozenset({
    "frame_before", "frame_after", "cycle_ram",
    "cycle_vram_before", "cycle_trace_start", "cycle_trace_end",
    "cycle_vram_after",
})


def _whole(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_CYCLE:
        raise ValueError("invalid unsigned session number: " + label)
    return value


def _sha(value: object, field: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("invalid lowercase SHA-256: " + field)
    return value


def _strict_fields(value: object, allowed: frozenset | set, label: str) -> dict:
    if type(value) is not dict or set(value) != set(allowed):
        raise ValueError("incorrect keys in private session " + label)
    return value


def validate_session(value: object) -> dict:
    root = _strict_fields(value, SESSION_FIELDS, "root")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValueError("unsupported session schema version")
    emu = _strict_fields(root["emulator"], EMULATOR_FIELDS, "emulator")
    for k in ("name", "version"):
        v = emu[k]
        if type(v) is not str or not 1 <= len(v) <= 80 or v != v.strip():
            raise ValueError("invalid emulator metadata")
    _sha(emu["build_sha256"], "emulator build")
    if emu["bios_mode"] not in ("hle", "external"):
        raise ValueError("BIOS mode must be hle or external")
    _sha(emu["bios_sha256"], "BIOS hash", optional=emu["bios_mode"] == "hle")
    if emu["bios_mode"] == "hle" and emu["bios_sha256"] is not None:
        raise ValueError("HLE mode must not claim a dumped external BIOS")
    times = _strict_fields(root["capture"], CAPTURE_FIELDS, "capture")
    for k in CAPTURE_FIELDS:
        _whole(times[k], k)
    if times["frame_before"] > times["frame_after"]:
        raise ValueError("frame indices are reversed")
    if not (times["cycle_ram"] <= times["cycle_vram_before"]
            <= times["cycle_trace_start"] < times["cycle_trace_end"]
            <= times["cycle_vram_after"]):
        raise ValueError("SH-2 capture cycle ordering is inconsistent")
    hashes = _strict_fields(root["artifacts"], ARTIFACT_NAMES, "artifacts")
    for k in HASH_FIELDS:
        _sha(hashes[k], "artifact " + k, optional=k == "source_commands")
    return root


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate session JSON key")
        out[k] = v
    return out


def load_session(path: Path) -> dict:
    if not 1 <= path.stat().st_size <= MAX_SESSION_BYTES:
        raise ValueError("capture session manifest size invalid")
    return validate_session(json.loads(path.read_text(encoding="utf-8"),
                                       object_pairs_hook=_unique_keys))


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_hashes(session: dict, paths: dict) -> bool:
    session = validate_session(session)
    if set(paths) != ARTIFACT_NAMES:
        raise ValueError("not all capture file slots are supplied")
    for k in HASH_FIELDS:
        path = paths[k]
        expected = session["artifacts"][k]
        if k == "source_commands" and expected is None:
            if path is not None:
                raise ValueError("source bytes supplied but session claims none")
            continue
        if not isinstance(path, Path):
            raise ValueError("missing private capture file: " + k)
        if digest_file(path) != expected:
            raise ValueError("capture artifact SHA-256 mismatch: " + k)
    return True


def audit_bundle(program: bytes, ram: bytes, before: bytes, after: bytes,
                 manifest: dict, events: list[dict], sources: bytes | None,
                 session: dict, verified_hashes: bool = False,
                 boot_metadata_matches: bool = False) -> dict:
    """Offline consistency only; callable for *synthetic* fixtures in CI."""
    session = validate_session(session)
    ram_result = summarize_ram(program, ram)
    vram_result = audit_witness(manifest, before, after, sources)
    trace_result = compare_trace(program, manifest, events, sources)
    timeline = session["capture"]
    has_source = sources is not None
    internal = bool(
        verified_hashes and boot_metadata_matches and
        ram_result["expected_mapping_uniquely_supported_by_supplied_snapshot"] and
        vram_result["copy_path_consistent_with_observation"] and
        trace_result["full_offline_trace_contract_matches"]
    )
    return {
        "schema_version": 1,
        "stage": "stage52_private_saturn_capture_bundle_audit",
        "emulator_build_sha256_declared_by_operator": True,
        "declared_bios_mode": session["emulator"]["bios_mode"],
        "declared_frame_order_valid": timeline["frame_before"] <= timeline["frame_after"],
        "declared_cycle_order_valid": True,
        "artifact_hashes_match_local_files": bool(verified_hashes),
        "original_iso_boot_mapping_matches_stage51": bool(boot_metadata_matches),
        "high_ram_mapping_uniquely_matches_stage50": bool(
            ram_result["expected_mapping_uniquely_supported_by_supplied_snapshot"]),
        "vdp1_command_snapshot_matches_stage48": bool(
            vram_result["copy_path_consistent_with_observation"]),
        "sh2_instruction_events_match_stage49": bool(
            trace_result["full_offline_trace_contract_matches"]),
        "source_command_capture_supplied": has_source,
        "descriptor_count": vram_result["descriptor_count"],
        "copied_32byte_commands": vram_result["commands_expected_by_descriptors"],
        "expected_32bit_store_events": trace_result["expected_32bit_vram_stores"],
        "unexplained_changed_vram_bytes":
            vram_result["observed_changed_bytes_outside_expected_write_ranges"],
        "mismatched_trace_event_roles": trace_result["mismatched_roles_or_event_count"],
        "mismatched_trace_store_addresses": trace_result["mismatched_vram_destinations"],
        "mismatched_trace_source_values": trace_result["mismatched_32bit_values"],
        "all_operator_supplied_offline_checks_consistent": internal,
        "authenticated_emulator_trace_observed": False,
        "boot_file_transfer_dynamically_verified": False,
        "sh2_gameplay_execution_proven": False,
        "handler_39_link_proven": False,
        "private_game_bytes_or_addresses_exported": False,
        "limitations": [
            "Session hashes prove file consistency, not trustworthy capture origin.",
            "Emulator name, version, build hash, BIOS mode, frame and cycle metadata are self-declared.",
            "A generated or modified RAM snapshot can match static code without executing it.",
            "Offline SH-2 event logs and VDP1 differences cannot attest real hardware execution.",
            "This is an audit gate for a future real capture, not a captured Saturn trace.",
        ],
    }


def run_private(iso: Path, session_path: Path, ram: Path,
                before: Path, after: Path, manifest_path: Path,
                trace_path: Path, source_path: Path | None) -> dict:
    session = load_session(session_path)
    paths = {
        "high_ram": ram, "vram_before": before, "vram_after": after,
        "descriptor_manifest": manifest_path, "trace_jsonl": trace_path,
        "source_commands": source_path,
    }
    if ram.stat().st_size != HIGH_WORK_RAM_BYTES:
        raise ValueError("High Work RAM requires a full 1-MiB dump")
    if before.stat().st_size != VRAM_BYTES or after.stat().st_size != VRAM_BYTES:
        raise ValueError("VDP1 VRAM snapshots must both be 524288 bytes")
    if trace_path.stat().st_size > MAX_TRACE_BYTES:
        raise ValueError("raw SH-2 trace exceeds safe input size")
    manifest = load_manifest(manifest_path)
    command_count = sum(item["copy_count"] for item in manifest["descriptors"])
    if command_count > MAX_COMMANDS_IN_TRACE:
        raise ValueError("trace command budget exceeded")
    if source_path is not None and source_path.stat().st_size != command_count * COMMAND_BYTES:
        raise ValueError("source commands do not match descriptor counts")
    verify_hashes(session, paths)
    boot = check_private_boot(iso)
    if not boot["independent_boot_metadata_supports_static_load_base"]:
        raise ValueError("original Saturn first-read mapping does not match the SH-2 load model")
    program = iso_file_payload(iso)
    return audit_bundle(
        program, ram.read_bytes(), before.read_bytes(), after.read_bytes(),
        manifest, load_jsonl(trace_path),
        source_path.read_bytes() if source_path is not None else None,
        session, verified_hashes=True, boot_metadata_matches=True,
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-private", type=Path, required=True)
    p.add_argument("--session-private", type=Path, required=True)
    p.add_argument("--high-ram-private", type=Path, required=True)
    p.add_argument("--before-vram-private", type=Path, required=True)
    p.add_argument("--after-vram-private", type=Path, required=True)
    p.add_argument("--manifest-private", type=Path, required=True)
    p.add_argument("--trace-jsonl-private", type=Path, required=True)
    p.add_argument("--source-commands-private", type=Path)
    p.add_argument("--output-private", type=Path)
    args = p.parse_args()
    report = run_private(args.iso_private, args.session_private, args.high_ram_private,
                         args.before_vram_private, args.after_vram_private,
                         args.manifest_private, args.trace_jsonl_private,
                         args.source_commands_private)
    encoded = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output_private:
        fd = os.open(args.output_private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
