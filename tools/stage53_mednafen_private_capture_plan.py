#!/usr/bin/env python3
"""Stage53: create a PRIVATE Sega Saturn debugger capture plan from pinned ISO.

Derives exact SH-2 breakpoint PCs and RAM addresses from 0TH2.BIN. These
sensitive values are written ONLY to a new owner-only local file; stdout
receives aggregate status without PCs, executable offsets, words or bytes.

The plan is NOT a debugger plugin, emulator run, runtime trace or proof of
actual execution. Follow the verified Mednafen debugger manual separately.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from stage18_writer_guard_flow import iso_file_payload
from stage46_vdp1_submit_gate import find_submit_gates
from stage49_sh2_vdp1_trace_contract import find_private_roles
from stage51_saturn_boot_first_read_map import analyze_private as verify_private_iso

ROLE_LABELS = ("gate", "jsr", "copy_store_0", "copy_store_1",
               "copy_store_2", "copy_store_3", "copy_store_4",
               "copy_store_5", "copy_store_6", "copy_store_7",
               "copy_rts", "submit_rts")
RAM_DUMP_START = 0x06000000
RAM_DUMP_BYTES = 0x100000
VDP1_DUMP_START = 0x25C00000
VDP1_DUMP_BYTES = 0x80000
REFERENCE_DOC = "https://mednafen.github.io/documentation/debugger.html"


def _hex(value: int) -> str:
    return f"{value:08X}"


def capture_plan(program: bytes) -> dict:
    """Private capture instructions with original-code PCs; never publish output."""
    roles = find_private_roles(program)
    gates = find_submit_gates(program)
    if len(gates) != 1:
        raise ValueError("expected a unique Stage46 submit gate in program")
    gate = gates[0]
    entries = [("gate", roles["gate"]), ("jsr", roles["jsr"])]
    entries += [(f"copy_store_{i}", pc)
                for i, pc in enumerate(roles["stores"])]
    entries += [("copy_rts", roles["copy_rts"]),
                ("submit_rts", roles["submit_rts"])]
    if tuple(label for label, _ in entries) != ROLE_LABELS:
        raise ValueError("inconsistent Stage49 role ordering")
    if len(set(pc for _, pc in entries)) != len(ROLE_LABELS):
        raise ValueError("SH-2 breakpoint PCs are not distinct")
    return {
        "schema_version": 1,
        "stage": "stage53_mednafen_private_breakpoint_capture_plan",
        "contains_private_code_addresses": True,
        "debugger": "Mednafen Sega Saturn (ss), manual",
        "debugger_manual": REFERENCE_DOC,
        "confirmed_boot_first_read_base": "06004000",
        "sh2_pc_breakpoints_in_role_order": [
            {"role": label, "pc_hex": _hex(pc)} for label, pc in entries
        ],
        "stage46_private_global_watch_addresses": {
            "signed_status_byte_hex": _hex(gate["status_address"]),
            "pending_descriptor_count_u16_hex": _hex(gate["count_address"]),
            "descriptor_buffer_pointer_hex": _hex(gate["source_address"]),
            "last_submitted_pointer_hex": _hex(gate["last_submitted_pointer_address"]),
        },
        "dump_ranges": [
            {"purpose": "stage50_high_work_ram", "start_hex": _hex(RAM_DUMP_START),
             "byte_count_hex": f"{RAM_DUMP_BYTES:X}",
             "mednafen_memory_editor_D_example":
                 f"{_hex(RAM_DUMP_START)} +{RAM_DUMP_BYTES:X} highram.private-snapshot"},
            {"purpose": "stage48_vdp1_vram_before",
             "start_hex": _hex(VDP1_DUMP_START),
             "byte_count_hex": f"{VDP1_DUMP_BYTES:X}",
             "mednafen_memory_editor_D_example":
                 f"{_hex(VDP1_DUMP_START)} +{VDP1_DUMP_BYTES:X} before.vram"},
            {"purpose": "stage48_vdp1_vram_after",
             "start_hex": _hex(VDP1_DUMP_START),
             "byte_count_hex": f"{VDP1_DUMP_BYTES:X}",
             "mednafen_memory_editor_D_example":
                 f"{_hex(VDP1_DUMP_START)} +{VDP1_DUMP_BYTES:X} after.vram"},
        ],
        "documented_mednafen_shortcuts": {
            "master_debugger": "ALT+D",
            "cpu_debugger": "ALT+1",
            "memory_editor": "ALT+3",
            "pc_breakpoint_toggle": "SPACE on selected instruction in CPU debugger",
            "memory_dump": "D in memory editor, start +count filename",
            "read_breakpoints": "SHIFT+R in CPU debugger",
            "write_breakpoints": "SHIFT+W in CPU debugger",
        },
        "operator_checklist": [
            "Load the private original Saturn disc in the emulator; do not upload BIOS/ISO.",
            "Record emulator version, binary SHA-256, BIOS mode and session ID privately.",
            "Pause the master SH-2 CPU; confirm which address space the editor is using.",
            "For RAM, attempt the high-work-RAM dump; verify the returned file is exactly 1048576 bytes.",
            "Check Stage50 against actual RAM data before interpreting PC breakpoints.",
            "Place PC breakpoints at the listed instruction addresses; record observed register values.",
            "If the memory editor exposes CPU-mapped VDP1 VRAM, dump before/after at 0x25C00000.",
            "If the selected memory domain does not contain those addresses, stop; do not substitute an ISO file.",
            "Record eight 32-bit stores for every copied command; R2 counts commands, R5 descriptors.",
            "Capture source commands and construct private Stage48/49 input files.",
            "Use Stage52 to verify hashes and internal consistency. A match is NOT execution attestation.",
        ],
        "actual_emulator_run_performed": False,
        "high_ram_snapshot_captured": False,
        "vdp1_snapshot_captured": False,
        "sh2_events_captured": False,
        "limitations": [
            "This private watchlist was derived statically from original executable bytes.",
            "Mednafen debugger documentation describes shortcuts and dumps, not an automatic trace export.",
            "Memory domains and physical address mapping must be independently confirmed in the emulator.",
            "Mednafen's debugger does not promise the cycle timestamps required by Stage52.",
            "This file includes original-specific code locations; never commit or paste it publicly.",
        ],
    }


def public_summary(plan: dict, original_verified: bool = False) -> dict:
    """Only safe aggregate metadata can appear in terminal / public CI logs."""
    return {
        "schema_version": 1,
        "stage": "stage53_mednafen_capture_plan",
        "original_disc_verified": bool(original_verified),
        "pc_breakpoint_roles_prepared": len(plan["sh2_pc_breakpoints_in_role_order"]),
        "private_global_watch_addresses_prepared":
            len(plan["stage46_private_global_watch_addresses"]),
        "dump_ranges_prepared": len(plan["dump_ranges"]),
        "mednafen_debugger_user_guide_linked": True,
        "private_watchlist_file_created_by_helper": False,
        "actual_emulator_run_performed": False,
        "verified_ram_or_vram_snapshot_available": False,
        "sh2_execution_proven": False,
        "raw_pc_or_original_game_bytes_exported_to_stdout": False,
    }


def write_plan_private(path: Path, plan: dict) -> None:
    encoded = json.dumps(plan, indent=2, ensure_ascii=False) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(encoded)


def run_private(original_iso: Path, output: Path) -> dict:
    boot = verify_private_iso(original_iso)
    if not boot["independent_boot_metadata_supports_static_load_base"]:
        raise ValueError("original Saturn disc boot mapping does not support Stage49 base")
    data = iso_file_payload(original_iso)
    plan = capture_plan(data)
    write_plan_private(output, plan)
    safe = public_summary(plan, original_verified=True)
    safe["private_watchlist_file_created_by_helper"] = True
    return safe


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--iso-private", type=Path, required=True)
    ap.add_argument("--output-private", type=Path, required=True,
                    help="NEW owner-only file outside GitHub with sensitive SH-2 PCs")
    args = ap.parse_args()
    print(json.dumps(run_private(args.iso_private, args.output_private),
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
