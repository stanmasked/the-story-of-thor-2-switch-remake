#!/usr/bin/env python3
"""Stage86: characterize SET00..SET07 and identify large multimedia containers.

Reports aggregate SH-2-like patterns, slot-dispatch candidates, filename-string
counts and large-file signatures. Pattern density does not prove execution.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16
from stage35_table_tail_link import movl_literal
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage75_indirect_services_count_provenance import (
    LENGTH_SOURCE_GLOBAL,
    _direct_store_sites,
    _resolve_callback,
    _slot_dispatch_sites,
)
from stage76_length_field_feedback_cfg import _find_routine_prologues
from stage79_expanded_store_alias_audit import scan_store_aliases
from stage81_callback64_callsite_census import literal_backed_jsr_sites
from stage83_unpaired_callback_context_audit import generic_prologue_candidates
from stage85_disc_slot_writer_census import MAX_FILE_SIZE, SECTOR, SERVICE_SLOT_A, SERVICE_SLOT_B


def read_root_payloads(image: Path, max_file_size: int = MAX_FILE_SIZE) -> dict:
    image_size = image.stat().st_size
    with image.open("rb") as stream:
        stream.seek(16 * SECTOR)
        pvd = stream.read(SECTOR)
        if pvd[:7] != b"\x01CD001\x01":
            raise ValueError("Not a supported ISO9660 volume")
        root_extent = int.from_bytes(pvd[158:162], "little")
        root_length = int.from_bytes(pvd[166:170], "little")
        if root_extent * SECTOR + root_length > image_size:
            raise ValueError("Root directory out of bounds")
        stream.seek(root_extent * SECTOR)
        directory = stream.read(root_length)
        entries = []
        index = 0
        while index < len(directory):
            record_length = directory[index]
            if record_length == 0:
                index = (index // SECTOR + 1) * SECTOR
                continue
            record = directory[index:index + record_length]
            index += record_length
            if len(record) < 34 or record[32] == 0:
                continue
            name = record[33:33 + record[32]].split(b";")[0]
            if name in (b"\x00", b"\x01") or record[25] & 0x02:
                continue
            extent = int.from_bytes(record[2:6], "little")
            size = int.from_bytes(record[10:14], "little")
            if extent * SECTOR + size > image_size:
                continue
            entries.append((name.decode("ascii", "replace"), extent, size))

        payloads = {}
        prefixes = {}
        skipped = 0
        for name, extent, size in entries:
            stream.seek(extent * SECTOR)
            if size <= max_file_size:
                payload = stream.read(size)
                if len(payload) == size:
                    payloads[name] = payload
            else:
                skipped += 1
                prefixes[name] = stream.read(min(64, size))
        return {
            "entries": entries,
            "payloads": payloads,
            "large_prefixes": prefixes,
            "root_file_count": len(entries),
            "full_payloads_scanned": len(payloads),
            "large_files_prefix_scanned": len(prefixes),
            "large_files_skipped_from_code_scan": skipped,
        }


def _literal_ref_count(data: bytes, target: int) -> int:
    return sum(
        1 for pos in range(0, len(data) - 5, 2)
        if (literal := movl_literal(data, pos)) is not None
        and literal[1] == target
    )


def summarize_set_payload(
    name: str,
    data: bytes,
    writer_address: int | None = None,
    callback_address: int | None = None,
) -> dict:
    halfwords = [be16(data, pos) for pos in range(0, len(data) - 1, 2)]
    slot_a = scan_store_aliases(data, SERVICE_SLOT_A)
    slot_b = scan_store_aliases(data, SERVICE_SLOT_B)
    result = {
        "file": name,
        "size_bytes": len(data),
        "pc_relative_movl_like_halfwords": sum(op >> 12 == 0xD for op in halfwords),
        "jsr_like_halfwords": sum((op & 0xF0FF) == 0x400B for op in halfwords),
        "jmp_like_halfwords": sum((op & 0xF0FF) == 0x402B for op in halfwords),
        "rts_like_halfwords": sum(op == 0x000B for op in halfwords),
        "bra_bsr_like_halfwords": sum(op >> 12 in (0xA, 0xB) for op in halfwords),
        "generic_stack_prologue_candidates": len(generic_prologue_candidates(data)),
        "slot_a_pc_literal_refs": _literal_ref_count(data, SERVICE_SLOT_A),
        "slot_b_pc_literal_refs": _literal_ref_count(data, SERVICE_SLOT_B),
        "slot_a_indirect_dispatch_candidates": len(_slot_dispatch_sites(data, SERVICE_SLOT_A)),
        "slot_b_indirect_dispatch_candidates": len(_slot_dispatch_sites(data, SERVICE_SLOT_B)),
        "slot_a_bounded_store_candidates": slot_a["exact_target_store_candidates"],
        "slot_b_bounded_store_candidates": slot_b["exact_target_store_candidates"],
        "writer_target_literal_jsr_sites": (
            len(literal_backed_jsr_sites(data, writer_address))
            if writer_address is not None else 0
        ),
        "callback_target_literal_jsr_sites": (
            len(literal_backed_jsr_sites(data, callback_address))
            if callback_address is not None else 0
        ),
        "runtime_execution_proven": False,
    }
    return result


def analyze(image: Path) -> dict:
    root = read_root_payloads(image)
    payloads = root["payloads"]
    main = payloads.get("0TH2.BIN", b"")
    callback_entry, _, callback_chain = _resolve_callback(main) if main else (None, None, False)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_chain and callback_entry is not None else None
    )
    source_stores = set(_direct_store_sites(main, LENGTH_SOURCE_GLOBAL)) if main else set()
    prologues = _find_routine_prologues(main) if main else []
    candidates = [pos for pos in prologues if source_stores and pos < min(source_stores)]
    writer_entry = max(candidates) if candidates else None
    writer_address = (
        CODE_LOAD_ADDRESS + writer_entry if writer_entry is not None else None
    )

    set_results = []
    for n in range(8):
        name = f"SET{n:02d}.BIN"
        if name in payloads:
            set_results.append(
                summarize_set_payload(
                    name, payloads[name], writer_address, callback_address
                )
            )

    low = payloads.get("TH2.LOW", b"")
    set_name_mentions = {
        "main_executable_mentions_set00_to_set05": sum(
            main.count(f"SET{n:02d}.BIN".encode()) for n in range(6)
        ),
        "low_module_mentions_set07": low.count(b"SET07.BIN"),
    }
    large_results = {
        name: {
            "size_bytes": next(size for file_name, _, size in root["entries"] if file_name == name),
            "prefix_magic": prefix[:4].decode("ascii", "replace"),
            "recognized_film_magic": prefix[:4] == b"FILM",
            "full_payload_scanned_for_code": False,
        }
        for name, prefix in root["large_prefixes"].items()
    }
    return {
        "schema_version": 1,
        "stage": "stage86_set_module_signature_audit",
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "root_file_count": root["root_file_count"],
            "small_file_payloads_scanned": root["full_payloads_scanned"],
            "large_files_prefix_scanned_only": root["large_files_prefix_scanned"],
            "large_files_skipped_from_code_scan": root["large_files_skipped_from_code_scan"],
            "set_file_signatures": set_results,
            "filename_string_mentions": set_name_mentions,
            "large_file_signatures": large_results,
            "set07_execution_role_confirmed": False,
            "all_set_file_entrypoints_resolved": False,
            "runtime_pointer_registration_proven": False,
            "runtime_callback_execution_confirmed": False,
            "runtime_dma_completion_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
