#!/usr/bin/env python3
"""Derive PRIVATE Saturn debugger watchpoints and audit supplied register snapshots.

No emulator is launched here. Validated user-supplied snapshots are not an
independent attestation of runtime execution. Never commit the private manifest.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import CODE_LOAD_BASE, movl_literal
from stage36_dispatch_index_audit import _pointer_table, match_indexed_dispatch
from stage39_writer_function_dispatch import find_writer_entries
from stage40_pool_clone_audit import inspect_writer_clone
from stage41_pool_readers import pool_base

DISPATCH_ENTRY_BACK = {"table_start": 0x90, "selected_cell": 0xD0}
DISPATCH_JMP_FORWARD = {"table_start": 4, "selected_cell": 8}
DISPATCH_PROLOGUES = {
    "table_start": (0x2FE6, 0x6E43, 0x4F22),
    "selected_cell": (0x2FE6, 0x6E43, 0x2FD6, 0x2FC6, 0x4F22),
}


def derive_private_manifest(code: bytes, disc_sha256: str) -> dict:
    """Return absolute debugger PCs for local use only; NEVER expose publicly."""
    pool = pool_base(code)
    table = _pointer_table(code)
    writers = [w for w in find_writer_entries(code)
               if inspect_writer_clone(code, w["entry"]) is not None]
    if pool is None or table is None or len(writers) != 1:
        raise ValueError("Stage35/40/41 prerequisites did not match this image")
    if pool[1:] != (276, 43) or table["entries"] != 68:
        raise ValueError("Unexpected pool or table size")
    writer = writers[0]
    copy_call = movl_literal(code, writer["entry"] + 0x78)
    if copy_call is None or copy_call[2] != 3:
        raise ValueError("Missing Stage40 copy-helper PC literal")
    if (be16(code, writer["store"]) != 0xE07E
            or be16(code, writer["store"]+2) != 0x0E35):
        raise ValueError("Missing exact word-index store")
    dispatchers = {}
    for name, target_ptr in (
            ("table_start", CODE_LOAD_BASE+table["table_start"]),
            ("selected_cell", CODE_LOAD_BASE+table["entry_cell"])):
        matches = []
        for pos in range(12, len(code)-12, 2):
            if match_indexed_dispatch(code, pos, target_ptr) is None:
                continue
            entry = pos - DISPATCH_ENTRY_BACK[name]
            expected = DISPATCH_PROLOGUES[name]
            if entry < 0 or any(be16(code, entry + 2*i) != op
                                for i, op in enumerate(expected)):
                continue
            matches.append({
                "entry_pc": CODE_LOAD_BASE+entry,
                "jump_pc": CODE_LOAD_BASE+pos+DISPATCH_JMP_FORWARD[name],
                "jump_target_register": "r3" if name == "table_start" else "r2",
            })
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one validated {name} dispatcher")
        dispatchers[name] = matches[0]
    function39 = int.from_bytes(
        code[table["entry_cell"]:table["entry_cell"]+4], "big")
    if not CODE_LOAD_BASE <= function39 < CODE_LOAD_BASE+len(code):
        raise ValueError("Invalid function-39 address")
    return {
        "schema": "stage43_private_watchpoints_v1",
        "source": "static_analysis_of_private_original_ISO",
        "disc_sha256": disc_sha256,
        "pool_base": pool[0],
        "pool_stride": pool[1],
        "pool_count": pool[2],
        "function_39_runtime_address": function39,
        "slot_return_pc": CODE_LOAD_BASE+writer["entry"]+0x6E,
        "copy_entry_pc": copy_call[1],
        "index_store_pc": CODE_LOAD_BASE+writer["store"]+2,
        "dispatchers": dispatchers,
        "warning": "PRIVATE: game-specific runtime PC/memory addresses; never commit",
    }


def slot_number(pointer: object, manifest: dict) -> int | None:
    if type(pointer) is not int:
        return None
    delta = pointer - manifest["pool_base"]
    if delta < 0 or delta % manifest["pool_stride"]:
        return None
    slot = delta // manifest["pool_stride"]
    return slot if slot < manifest["pool_count"] else None


def inspect_snapshots(manifest: dict, samples: object) -> dict:
    """Check debugger stops and register values, not their factual provenance.

    Strict route: cloned index=38 may choose function39 only from table start.
    Selected-cell routing requires an explicitly captured subsequent 16-bit
    index change 38->0 on the SAME object's +126 memory word.
    """
    generic = {"supplied_snapshots_consistent": False,
               "real_emulator_execution_attested": False,
               "real_vdp1_output_attested": False}
    if not isinstance(samples, list):
        return {**generic, "reason": "snapshots_must_be_list", "snapshots_checked": 0}
    if len(samples) not in (5,6):
        return {**generic, "reason": "incomplete_or_extra_events",
                "snapshots_checked": len(samples)}
    if not all(isinstance(ev, dict) for ev in samples):
        return {**generic, "reason": "invalid_record", "snapshots_checked": len(samples)}
    if [ev.get("event") for ev in samples[:3]] != [
            "slot-return", "copy-entry", "index-store-pre"]:
        return {**generic, "reason": "incorrect_event_order",
                "snapshots_checked": len(samples)}
    if len(samples) == 6:
        wanted = ["index-word-change", "dispatch-entry", "dispatch-jmp-pre"]
        if [ev.get("event") for ev in samples[3:]] != wanted:
            return {**generic, "reason": "incorrect_event_order",
                    "snapshots_checked": len(samples)}
    elif [ev.get("event") for ev in samples[3:]] != [
            "dispatch-entry", "dispatch-jmp-pre"]:
        return {**generic, "reason": "incorrect_event_order",
                "snapshots_checked": len(samples)}
    times = [ev.get("cycle") for ev in samples]
    if any(type(t) is not int or t < 0 for t in times) or times != sorted(set(times)):
        return {**generic, "reason": "invalid_cycle_order",
                "snapshots_checked": len(samples)}
    first, second, third = samples[:3]
    selected = first.get("r0")
    num = slot_number(selected, manifest)
    if first.get("pc") != manifest["slot_return_pc"] or num is None:
        return {**generic, "reason": "allocator_pc_or_slot_mismatch",
                "snapshots_checked": len(samples)}
    if (second.get("pc") != manifest["copy_entry_pc"]
            or second.get("r5") != selected
            or type(second.get("r4")) is not int or second["r4"] == 0):
        return {**generic, "reason": "copy_pc_or_pointer_mismatch",
                "snapshots_checked": len(samples)}
    if (third.get("pc") != manifest["index_store_pc"]
            or third.get("r14") != selected or third.get("r3") != 38):
        return {**generic, "reason": "writer_pc_pointer_or_constant_mismatch",
                "snapshots_checked": len(samples)}
    changed = len(samples) == 6
    if changed:
        ev = samples[3]
        if (ev.get("address") != selected+126 or ev.get("width_bytes") != 2
                or ev.get("old_value") != 38 or ev.get("new_value") != 0
                or type(ev.get("pc")) is not int):
            return {**generic, "reason": "unverified_index_change",
                    "snapshots_checked": len(samples)}
    ent, jump = samples[-2:]
    route = ent.get("anchor")
    info = manifest["dispatchers"].get(route)
    if (info is None or (route == "selected_cell" and not changed)
            or (route == "table_start" and changed)):
        return {**generic, "reason":
                "index38_requires_table_start_or_explicit_rewrite",
                "snapshots_checked": len(samples)}
    value = 0 if changed else 38
    if (ent.get("pc") != info["entry_pc"] or ent.get("r4") != selected
            or ent.get("index_word") != value):
        return {**generic, "reason": "dispatcher_entry_or_memory_mismatch",
                "snapshots_checked": len(samples)}
    if (jump.get("pc") != info["jump_pc"] or jump.get("r14") != selected
            or jump.get("index_word") != value
            or jump.get(info["jump_target_register"])
               != manifest["function_39_runtime_address"]):
        return {**generic, "reason": "indirect_jump_or_target_mismatch",
                "snapshots_checked": len(samples)}
    return {**generic, "supplied_snapshots_consistent": True,
            "snapshots_checked": len(samples),
            "matched_physical_slot": True, "reached_function_39_as_supplied": True,
            "route": route, "explicit_index_rewrite_supplied": changed,
            "reason": None,
            "note": "Untrusted supplied snapshots; consistency is not authenticated execution"}


def _write_private_json(path: Path, value: dict) -> None:
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    except BaseException:
        try: os.close(fd)
        except OSError: pass
        raise


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("--manifest-private", type=Path, required=True,
                   help="LOCAL private file containing game-specific debugger addresses")
    p.add_argument("--snapshots-private", type=Path,
                   help="LOCAL debugger observations (never put in git)")
    p.add_argument("-o", "--summary", type=Path)
    args = p.parse_args()
    disc_hash = hashlib.sha256(args.image.read_bytes()).hexdigest()
    manifest = derive_private_manifest(iso_file_payload(args.image), disc_hash)
    _write_private_json(args.manifest_private, manifest)
    result = {
        "stage": "stage43", "watchpoint_manifest_created": True,
        "watchpoint_roles": 7, "pool_slots": manifest["pool_count"],
        "pool_stride": manifest["pool_stride"],
        "original_disc_sha256_matches_reference":
            disc_hash == "25b0b2774d4621bd9f95a01fc5420ded37b481b61b3cdf515360d82b2cb7bb0d",
        "emulator_executed": False, "runtime_attested": False,
        "private_positions_not_emitted": True,
    }
    if args.snapshots_private:
        supplied = json.loads(args.snapshots_private.read_text(encoding="utf-8"))
        events = supplied.get("snapshots") if isinstance(supplied, dict) else supplied
        result["supplied_snapshot_validation"] = inspect_snapshots(manifest, events)
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.summary:
        args.summary.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
