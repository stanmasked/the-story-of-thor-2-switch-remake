#!/usr/bin/env python3
"""Stage75: audit dynamic service slots and provenance of the VDP1 length word.

The original Saturn ISO stays local. Output is aggregate-only and contains no
RAM addresses, code offsets, instruction words, or copyrighted payload bytes.
Static register-flow evidence is not a runtime trace.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal
from stage46_vdp1_submit_gate import find_submit_gates
from stage71_callback_dispatch_chain import (
    CODE_LOAD_ADDRESS,
    TARGET_CALLBACK_ID,
    _find_negative_writer_registrations,
)
from stage74_scu_dma_handler_audit import _audit_command_count

SERVICE_SLOT_A = 0x06000300
SERVICE_SLOT_B = 0x06000310
LENGTH_SOURCE_GLOBAL = 0x0609BA7C
DMA_MODE_REGISTER = 0x25FE000C


def _word(data: bytes, pos: int) -> int:
    return be16(data, pos)


def _pc_literal_sites(data: bytes, value: int) -> list[tuple[int, int, int]]:
    """Return instruction position, literal position, and destination register."""
    result = []
    for pos in range(0, len(data) - 1, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == value:
            result.append((pos, literal[0], literal[2]))
    return result


def _may_write_register(opcode: int, register: int) -> bool:
    group = opcode >> 12
    destination = (opcode >> 8) & 0xF
    # Deliberately conservative: false positives suppress a provenance claim.
    if group in (0x3, 0x4, 0x5, 0x6, 0x7, 0x9, 0xD, 0xE):
        return destination == register
    if group == 0x0:
        return (
            (opcode & 0xF00F in (0x000C, 0x000D, 0x000E) and destination == register)
            or (destination == register and (opcode & 0x00FF) in (
                0x0002, 0x0012, 0x0022, 0x0032, 0x0042,
                0x000A, 0x001A, 0x002A, 0x0029,
            ))
        )
    if group == 0x2:
        return destination == register and (opcode & 0xF) in (0x9, 0xA, 0xB, 0xD)
    return False


def _is_indirect_call(opcode: int, register: int) -> bool:
    return (
        ((opcode & 0xF0FF) in (0x400B, 0x402B))
        and ((opcode >> 8) & 0xF) == register
    )


def _slot_dispatch_sites(data: bytes, slot_address: int) -> list[tuple[int, int]]:
    """Find slot dereference followed by JSR/JMP through the loaded pointer."""
    sites = set()
    for load_pos, _, slot_reg in _pc_literal_sites(data, slot_address):
        stop = min(len(data) - 1, load_pos + 0x30)
        for read_pos in range(load_pos + 2, stop, 2):
            read_op = _word(data, read_pos)
            if read_op & 0xF00F != 0x6002:
                continue  # MOV.L @Rm,Rn only
            base_reg = (read_op >> 4) & 0xF
            target_reg = (read_op >> 8) & 0xF
            if base_reg != slot_reg:
                continue
            for branch_pos in range(read_pos + 2, min(stop, read_pos + 0x16), 2):
                if _is_indirect_call(_word(data, branch_pos), target_reg):
                    sites.add((load_pos, branch_pos))
                    break
            if any(
                _may_write_register(_word(data, q), slot_reg)
                for q in range(load_pos + 2, read_pos, 2)
            ):
                break
            break
    return sorted(sites)


def _direct_store_sites(data: bytes, address: int) -> list[int]:
    """Find local byte/word/long stores through a register loaded with address."""
    stores = set()
    for load_pos, _, base_reg in _pc_literal_sites(data, address):
        for pos in range(load_pos + 2, min(len(data) - 1, load_pos + 0x22), 2):
            opcode = _word(data, pos)
            if (
                opcode & 0xF00F in (0x2000, 0x2001, 0x2002)
                and ((opcode >> 8) & 0xF) == base_reg
            ):
                stores.add(pos)
                break
            if _may_write_register(opcode, base_reg):
                break
    return sorted(stores)


def _count_length_assignments(
    data: bytes, count_address: int, callback_address: int
) -> list[dict]:
    """Recognize count-word stores in the JSR delay slot of callback ID64."""
    found = []
    for count_load_pos, _, count_reg in _pc_literal_sites(data, count_address):
        callback_pos = count_load_pos + 2
        callback_literal = movl_literal(data, callback_pos)
        if callback_literal is None or callback_literal[1] != callback_address:
            continue
        callback_reg = callback_literal[2]
        call_pos = callback_pos + 2
        if _word(data, call_pos) != (0x400B | (callback_reg << 8)):
            continue
        store_pos = call_pos + 2
        store = _word(data, store_pos)
        if store & 0xF00F != 0x2001 or ((store >> 8) & 0xF) != count_reg:
            continue
        source_reg = (store >> 4) & 0xF
        read_pos = count_load_pos - 2
        read_op = _word(data, read_pos) if read_pos >= 0 else 0
        source_read_verified = (
            read_op & 0xF00F == 0x6001
            and ((read_op >> 8) & 0xF) == source_reg
            and ((read_op >> 4) & 0xF) == 4
        )
        source_global = None
        if source_read_verified:
            candidates = [
                item for item in _pc_literal_sites(data, LENGTH_SOURCE_GLOBAL)
                if item[2] == 4 and count_load_pos - 0x40 <= item[0] < read_pos
            ]
            if candidates:
                nearest = max(candidates, key=lambda item: item[0])
                if not any(
                    _may_write_register(_word(data, q), 4)
                    for q in range(nearest[0] + 2, read_pos, 2)
                ):
                    source_global = LENGTH_SOURCE_GLOBAL
        found.append({
            "store_pos": store_pos,
            "source_read_verified": source_read_verified,
            "source_is_known_global": source_global is not None,
            "source_is_preexisting_pointer": source_read_verified and source_global is None,
        })
    # One literal-load instruction can only describe one callback store.
    by_store = {item["store_pos"]: item for item in found}
    return [by_store[pos] for pos in sorted(by_store)]


def _audit_length_source_writers(data: bytes, source_address: int) -> dict:
    stores = _direct_store_sites(data, source_address)
    r10_zero_seeded = 0
    for store_pos in stores:
        store = _word(data, store_pos)
        if store & 0xF00F != 0x2001:
            continue
        source_reg = (store >> 4) & 0xF
        if source_reg != 10:
            continue
        base_reg = (store >> 8) & 0xF
        matching_loads = [
            item for item in _pc_literal_sites(data, source_address)
            if item[2] == base_reg and store_pos - 0x22 <= item[0] < store_pos
        ]
        if not matching_loads:
            continue
        seed_candidates = [
            pos for pos in range(max(0, store_pos - 0x1000), store_pos, 2)
            if _word(data, pos) == 0xEA00
        ]
        if not seed_candidates:
            continue
        seed_pos = max(seed_candidates)
        if any(
            _may_write_register(_word(data, pos), 10)
            for pos in range(seed_pos + 2, store_pos, 2)
        ):
            continue
        # This is a local linear data-flow result only; indirect callee effects
        # and alternate entry paths are not treated as resolved.
        r10_zero_seeded += 1
    return {
        "length_source_global_direct_word_writer_signatures": len(stores),
        "length_source_global_writer_r10_zero_seeded_sites": r10_zero_seeded,
        "length_source_global_writer_values_resolved": False,
    }


def _resolve_callback(data: bytes) -> tuple[int | None, int | None, bool]:
    gates = find_submit_gates(data)
    if len(gates) != 1:
        return None, None, False
    status_address = gates[0].get("status_address")
    if status_address is None:
        return None, None, False
    registrations, _ = _find_negative_writer_registrations(data, status_address)
    targets = [
        item for item in registrations
        if item.get("callback_id") == TARGET_CALLBACK_ID
    ]
    if len(targets) != 1:
        return None, None, False
    callback_entry = targets[0].get("callback_entry")
    if not isinstance(callback_entry, int) or callback_entry < 0:
        return None, None, False
    count_literal = movl_literal(data, callback_entry + 0x18)
    if count_literal is None or count_literal[2] != 2:
        return callback_entry, None, False
    return callback_entry, count_literal[1], True


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    callback_entry, count_address, callback_chain_verified = _resolve_callback(data)
    callback_address = (
        CODE_LOAD_ADDRESS + callback_entry
        if callback_entry is not None and callback_chain_verified else None
    )
    assignments = (
        _count_length_assignments(data, count_address, callback_address)
        if count_address is not None and callback_address is not None else []
    )
    known_global_paths = sum(item["source_is_known_global"] for item in assignments)
    pointer_paths = sum(item["source_is_preexisting_pointer"] for item in assignments)
    source_read_sites = sum(item["source_read_verified"] for item in assignments)

    count_audit = (
        _audit_command_count(data, count_address)
        if count_address is not None else {}
    )
    slot_a = _slot_dispatch_sites(data, SERVICE_SLOT_A)
    slot_b = _slot_dispatch_sites(data, SERVICE_SLOT_B)
    slot_a_stores = _direct_store_sites(data, SERVICE_SLOT_A)
    slot_b_stores = _direct_store_sites(data, SERVICE_SLOT_B)
    source_writers = _audit_length_source_writers(data, LENGTH_SOURCE_GLOBAL)
    d0md_sites = _pc_literal_sites(data, DMA_MODE_REGISTER)

    return {
        "schema_version": 1,
        "stage": "stage75_indirect_services_count_provenance",
        "target_file": "0TH2.BIN",
        "analysis": {
            "callback_id64_chain_verified": callback_chain_verified,
            "length_count_callback_assignment_sites": len(assignments),
            "length_count_assignment_delay_slot_stores_verified": (
                len(assignments) == 2 and source_read_sites == 2
            ),
            "length_count_assignments_from_known_global_word": known_global_paths,
            "length_count_assignments_from_preexisting_pointer_word": pointer_paths,
            "length_count_assignment_source_reads_verified": source_read_sites,
            "length_source_global_direct_word_writer_signatures": source_writers[
                "length_source_global_direct_word_writer_signatures"
            ],
            "length_source_global_writer_r10_zero_seeded_sites": source_writers[
                "length_source_global_writer_r10_zero_seeded_sites"
            ],
            "length_source_global_writer_values_resolved": source_writers[
                "length_source_global_writer_values_resolved"
            ],
            "service_slot_a_literal_reference_sites": len(_pc_literal_sites(data, SERVICE_SLOT_A)),
            "service_slot_b_literal_reference_sites": len(_pc_literal_sites(data, SERVICE_SLOT_B)),
            "service_slot_a_indirect_dispatch_sites": len(slot_a),
            "service_slot_b_indirect_dispatch_sites": len(slot_b),
            "service_slot_direct_store_signatures_found": len(set(slot_a_stores + slot_b_stores)),
            "service_slot_initialization_resolved_in_game_image": False,
            "dma_mode_register_absolute_literal_load_sites": len(d0md_sites),
            "dma_mode_configuration_path_resolved": False,
            "length_count_increment_sites_guarded_by_limit": count_audit.get(
                "command_count_increment_sites_guarded_by_limit", 0
            ),
            "length_count_guard_limits": count_audit.get(
                "command_count_guard_limits", []
            ),
            "length_count_increment_sites_after_local_zero_reset": count_audit.get(
                "command_count_increment_sites_after_local_zero_reset", 0
            ),
            "length_count_assignments_with_unresolved_value_origin": count_audit.get(
                "command_count_unresolved_register_assignment_sites", 0
            ),
            "global_length_count_upper_bound_proven": count_audit.get(
                "command_count_global_upper_bound_proven", False
            ),
            "runtime_service_targets_resolved": False,
            "runtime_dma_completion_confirmed": False,
            "same_frame_submit_timing_confirmed": False,
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
