#!/usr/bin/env python3
"""Stage49: privately compare a normalized SH-2 instruction trace with Stage45/46.

This is an *offline plausibility check*: an operator-supplied JSONL event file
is NOT authenticated emulator output. PC and VDP1 addresses are never exported.
Original ISO, VRAM and source commands must remain outside public GitHub.
"""
from __future__ import annotations

import argparse
from itertools import zip_longest
import json
import os
from pathlib import Path

from stage18_writer_guard_flow import iso_file_payload
from stage45_vdp1_command_copy import find_vdp1_writers
from stage46_vdp1_submit_gate import find_submit_gates
from stage48_vdp1_copy_witness import (
    COMMAND_BYTES, VRAM_BYTES, parse_manifest, load_manifest,
)

SH2_LOAD_BASE = 0x06004000
VDP1_VRAM_BASE = 0x25C00000
STORE_OFFSETS_FROM_LOAD = (20, 22, 28, 30, 36, 38, 44, 46)
MAX_COMMANDS_IN_TRACE = 4096
MAX_TRACE_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = MAX_COMMANDS_IN_TRACE * COMMAND_BYTES
MAX_EVENTS = 2 + MAX_COMMANDS_IN_TRACE * 8 + 2
FIELDS = {
    "gate": frozenset(("role", "pc", "status", "pending_count")),
    "jsr": frozenset(("role", "pc", "r5")),
    "store": frozenset(("role", "pc", "dest", "value")),
    "copy_rts": frozenset(("role", "pc", "r5")),
    "submit_rts": frozenset(("role", "pc", "status", "pending_count")),
}


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _validate_event(value: object) -> dict:
    if type(value) is not dict or type(value.get("role")) is not str or value["role"] not in FIELDS:
        raise ValueError("unknown or invalid trace event role")
    if set(value) != FIELDS[value["role"]]:
        raise ValueError("trace event keys do not match role schema")
    for key in ("pc", "dest", "value"):
        if key in value and not _bounded_int(value[key], 0, 0xFFFFFFFF):
            raise ValueError("invalid unsigned instruction or word field")
    for key in ("status",):
        if key in value and not _bounded_int(value[key], -128, 127):
            raise ValueError("invalid signed byte field")
    for key in ("pending_count", "r5"):
        if key in value and not _bounded_int(value[key], 0, 65535):
            raise ValueError("invalid register / counter field")
    return value


def find_private_roles(program: bytes) -> dict:
    """Return private instruction PCs only to the caller, never in summaries."""
    writers = find_vdp1_writers(program)
    gates = find_submit_gates(program)
    if len(writers) != 1 or len(gates) != 1:
        raise ValueError("expected exactly one static Stage45 writer and Stage46 gate")
    writer, gate = writers[0], gates[0]
    if gate["writer_entry"] != writer["entry"]:
        raise ValueError("Stage46 gate does not target Stage45 writer")
    return {
        "gate": SH2_LOAD_BASE + gate["start"] + 0x08,
        "jsr": SH2_LOAD_BASE + gate["start"] + 0x22,
        "stores": tuple(SH2_LOAD_BASE + writer["load"] + offset
                        for offset in STORE_OFFSETS_FROM_LOAD),
        "copy_rts": SH2_LOAD_BASE + writer["load"] + 64,
        "submit_rts": SH2_LOAD_BASE + gate["start"] + 0x36,
    }


def expected_events(program: bytes, metadata: dict,
                    sources: bytes | None = None) -> list[dict]:
    """Internal-only expected normalized events for one complete submit call.

    The PC mapping is from a privately loaded Saturn binary, not hardcoded
    offsets. There is no address output or debugging metadata in summaries.
    """
    manifest = parse_manifest(metadata)
    roles = find_private_roles(program)
    records = manifest["descriptors"]
    total = sum(d["copy_count"] for d in records)
    if total > MAX_COMMANDS_IN_TRACE:
        raise ValueError("trace command budget exceeds local bound")
    if sources is not None and (type(sources) is not bytes or len(sources) != total * COMMAND_BYTES):
        raise ValueError("source command file length/type mismatch")
    results = [
        {"role": "gate", "pc": roles["gate"],
         "status": manifest["status_before"],
         "pending_count": manifest["pending_count_before"]},
        {"role": "jsr", "pc": roles["jsr"],
         "r5": manifest["pending_count_before"]},
    ]
    cursor = 0
    for record in records:
        for k in range(record["copy_count"]):
            base = VDP1_VRAM_BASE + record["destination_index"] * 8 + k * COMMAND_BYTES
            for i, pc in enumerate(roles["stores"]):
                event = {"role": "store", "pc": pc, "dest": base + i * 4, "value": None}
                if sources is not None:
                    offset = cursor + i * 4
                    event["value"] = int.from_bytes(sources[offset:offset+4], "big")
                results.append(event)
            cursor += COMMAND_BYTES
    results.extend([
        {"role": "copy_rts", "pc": roles["copy_rts"], "r5": 0},
        {"role": "submit_rts", "pc": roles["submit_rts"],
         "status": manifest["status_after"],
         "pending_count": manifest["pending_count_after"]},
    ])
    return results


def compare_trace(program: bytes, metadata: dict,
                  events: list[dict], sources: bytes | None = None) -> dict:
    """Validate ordering, private original-code PCs and each MOV.L VRAM store."""
    expected = expected_events(program, metadata, sources)
    if type(events) is not list or len(events) > MAX_EVENTS:
        raise ValueError("trace event count exceeds local audit limit")
    mismatches = {"event_roles": 0, "pc": 0, "destination": 0,
                  "values": 0, "registers": 0}
    checked = 0
    for actual, want in zip_longest(events, expected):
        if actual is None or want is None:
            mismatches["event_roles"] += 1
            continue
        actual = _validate_event(actual)
        if actual["role"] != want["role"]:
            mismatches["event_roles"] += 1
            continue
        if actual["pc"] != want["pc"]:
            mismatches["pc"] += 1
        if actual["role"] == "store":
            checked += 1
            if actual["dest"] != want["dest"]:
                mismatches["destination"] += 1
            if sources is not None and actual["value"] != want["value"]:
                mismatches["values"] += 1
        else:
            for key in ("r5", "status", "pending_count"):
                if key in want and actual[key] != want[key]:
                    mismatches["registers"] += 1

    m = parse_manifest(metadata)
    copied_commands = sum(d["copy_count"] for d in m["descriptors"])
    budget_agrees = m["pending_count_before"] == len(m["descriptors"])
    gate_enabled = m["status_before"] < 0 and m["pending_count_before"] > 0
    post_reset = m["status_after"] == 0 and m["pending_count_after"] == 0
    shape_pass = all(mismatches[k] == 0 for k in ("event_roles", "pc", "destination", "registers"))
    values_pass = None if sources is None else mismatches["values"] == 0
    full_pass = shape_pass and values_pass is True and budget_agrees and gate_enabled and post_reset

    return {
        "schema_version": 1,
        "stage": "stage49_sh2_vdp1_trace_contract",
        "expected_trace_events": len(expected),
        "observed_trace_events": len(events),
        "expected_32bit_vram_stores": 8 * copied_commands,
        "observed_store_events_with_expected_role": checked,
        "mismatched_roles_or_event_count": mismatches["event_roles"],
        "mismatched_static_program_counters": mismatches["pc"],
        "mismatched_vram_destinations": mismatches["destination"],
        "mismatched_32bit_values": mismatches["values"] if sources is not None else None,
        "mismatched_register_or_flag_observations": mismatches["registers"],
        "command_source_bytes_supplied_privately": sources is not None,
        "pending_budget_equals_descriptor_count": budget_agrees,
        "total_inner_loop_commands": copied_commands,
        "initial_negative_flag_and_nonzero_pending": gate_enabled,
        "final_flag_and_pending_count_are_zero": post_reset,
        "static_opcode_pc_and_write_order_match": shape_pass,
        "source_word_values_match": values_pass,
        "full_offline_trace_contract_matches": full_pass,
        "emulator_trace_authenticity_verified": False,
        "sh2_load_base_verified_in_live_emulator": False,
        "sh2_runtime_execution_proven": False,
        "handler_39_link_proven": False,
        "raw_addresses_or_original_code_exported": False,
        "limitations": [
            "Event records are untrusted operator-supplied JSONL, not authenticated emulator instrumentation.",
            "SH-2 load base 0x06004000 is statically inferred and still needs emulator validation.",
            "Only one call to the statically identified Stage46 submit path is modeled.",
            "Other SH-2 instructions and delay slots between recorded roles are not covered.",
            "A complete offline match is insufficient to prove real gameplay execution.",
            "No full address, instruction byte, VRAM dump or source word appears in this report.",
        ],
    }


def load_jsonl(path: Path) -> list[dict]:
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise ValueError("private event trace is too large")
    items = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            if len(items) >= MAX_EVENTS:
                raise ValueError("too many private trace events")
            def unique_keys(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError("duplicate key in private event")
                    result[key] = item
                return result
            items.append(_validate_event(json.loads(line, object_pairs_hook=unique_keys)))
    return items


def run_private(image: Path, manifest: Path, trace_jsonl: Path,
                source_commands: Path | None = None) -> dict:
    meta = load_manifest(manifest)
    total = sum(record["copy_count"] for record in meta["descriptors"])
    if total > MAX_COMMANDS_IN_TRACE:
        raise ValueError("private copy count exceeds trace limit")
    if source_commands is not None and source_commands.stat().st_size != total * COMMAND_BYTES:
        raise ValueError("private source capture size mismatch")
    program = iso_file_payload(image)
    trace = load_jsonl(trace_jsonl)
    source = source_commands.read_bytes() if source_commands is not None else None
    return compare_trace(program, meta, trace, source)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iso-private", type=Path, required=True)
    p.add_argument("--manifest-private", type=Path, required=True)
    p.add_argument("--trace-jsonl-private", type=Path, required=True)
    p.add_argument("--source-commands-private", type=Path)
    p.add_argument("--output-private", type=Path,
                   help="Create a NEW owner-only metadata file, without overwriting")
    args = p.parse_args()
    result = run_private(args.iso_private, args.manifest_private,
                         args.trace_jsonl_private, args.source_commands_private)
    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output_private:
        fd = os.open(args.output_private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
