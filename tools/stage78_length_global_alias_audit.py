#!/usr/bin/env python3
"""Stage78: bounded alias-store audit for the transfer-length source field.

The original Saturn ISO remains local. The report is aggregate-only; it does
not emit RAM addresses, instruction offsets, raw instructions, or game assets.
The scan is intentionally bounded and does not claim a complete alias proof.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage75_indirect_services_count_provenance import (
    LENGTH_SOURCE_GLOBAL,
    _count_length_assignments,
    _direct_store_sites,
    _may_write_register,
    _resolve_callback,
)

SOURCE_FIELD_START = LENGTH_SOURCE_GLOBAL
SOURCE_FIELD_END = SOURCE_FIELD_START + 2
NEARBY_POINTER_VALUES = (
    0x0609BA70, 0x0609BA74, 0x0609BA78,
    0x0609BA7C, 0x0609BA7E, 0x0609BA80,
)


def _word(data: bytes, pos: int) -> int:
    return be16(data, pos)


def _is_jsr(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x400B


def _is_jmp(opcode: int) -> bool:
    return (opcode & 0xF0FF) == 0x402B


def _is_rts(opcode: int) -> bool:
    return opcode == 0x000B


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _overlaps_source_field(address: int, width: int) -> bool:
    return address < SOURCE_FIELD_END and address + width > SOURCE_FIELD_START


def _store_effect(
    data: bytes, pos: int, registers: tuple[int | None, ...],
    initial_pointer_value: int,
) -> tuple[tuple[int, int, str] | None, tuple[int, int, str] | None]:
    opcode = _word(data, pos)
    group = opcode >> 12
    base_register = (opcode >> 8) & 0xF
    base_value = registers[base_register]
    source_field_store = None
    unresolved_indexed = None

    if group == 0x2 and (opcode & 0xF) in (0, 1, 2):
        width = {0: 1, 1: 2, 2: 4}[opcode & 0xF]
        if base_value is not None and _overlaps_source_field(base_value, width):
            source_field_store = (pos, width, "direct", base_value, base_value)
    elif group == 0x2 and (opcode & 0xF) in (4, 5, 6):
        width = {4: 1, 5: 2, 6: 4}[opcode & 0xF]
        if base_value is not None and _overlaps_source_field(base_value - width, width):
            source_field_store = (pos, width, "predecrement", base_value, base_value - width)
    elif group == 0x1:
        width = 4
        address = None if base_value is None else base_value + (opcode & 0xF) * 4
        if address is not None and _overlaps_source_field(address, width):
            source_field_store = (pos, width, "long-displacement", base_value, address)
    elif group == 0x8 and base_register not in (4, 5, 8, 9, 11, 13, 15):
        width = 1
        address = None if base_value is None else base_value + (opcode & 0xF)
        if address is not None and _overlaps_source_field(address, width):
            source_field_store = (pos, width, "byte-displacement", base_value, address)
    elif group == 0 and (opcode & 0xF) in (4, 5, 15):
        width = {4: 1, 5: 2, 15: 4}[opcode & 0xF]
        index_value = registers[0]
        if base_value is not None and index_value is not None:
            if _overlaps_source_field(base_value + index_value, width):
                source_field_store = (pos, width, "indexed", base_value, base_value + index_value)
        elif base_value is not None and abs(base_value - SOURCE_FIELD_START) <= 0x40:
            unresolved_indexed = (pos, initial_pointer_value, "unknown-index")

    return source_field_store, unresolved_indexed


def _update_registers(
    data: bytes, pos: int, registers: tuple[int | None, ...]
) -> tuple[int | None, ...]:
    values = list(registers)
    opcode = _word(data, pos)
    group = opcode >> 12
    destination = (opcode >> 8) & 0xF
    source = (opcode >> 4) & 0xF
    low = opcode & 0xF

    literal = movl_literal(data, pos)
    if literal is not None:
        values[literal[2]] = literal[1]
        return tuple(values)

    if group == 0xE:  # MOV #imm,Rn
        values[destination] = _signed8(opcode & 0xFF)
        return tuple(values)

    if group == 0x2 and low in (4, 5, 6):  # MOV.B/W/L Rm,@-Rn
        base = values[destination]
        width = {4: 1, 5: 2, 6: 4}[low]
        values[destination] = None if base is None else base - width
        return tuple(values)

    if group == 0x6:
        if low == 3:  # MOV Rm,Rn
            values[destination] = values[source]
        elif low in (0, 1, 2):  # MOV.B/W/L @Rm,Rn
            values[destination] = None
        elif low in (4, 5, 6):  # MOV.B/W/L @Rm+,Rn
            values[destination] = None
            base = values[source]
            width = {4: 1, 5: 2, 6: 4}[low]
            values[source] = None if base is None else base + width
        elif _may_write_register(opcode, destination):
            values[destination] = None
        return tuple(values)

    if group == 0x7:  # ADD #imm,Rn
        current = values[destination]
        values[destination] = (
            None if current is None else current + _signed8(opcode & 0xFF)
        )
        return tuple(values)

    if group == 0x3 and low in (0x8, 0xC):  # SUB/ADD Rm,Rn
        left, right = values[destination], values[source]
        if left is None or right is None:
            values[destination] = None
        else:
            values[destination] = left - right if low == 0x8 else left + right
        return tuple(values)

    if group == 0x9:  # MOV.W @(disp,PC),Rn
        literal_pos = ((pos + 4) & ~1) + (opcode & 0xFF) * 2
        if literal_pos + 2 <= len(data):
            values[destination] = int.from_bytes(
                data[literal_pos:literal_pos + 2], "big", signed=True
            )
        else:
            values[destination] = None
        return tuple(values)

    if group == 0xC and (opcode & 0xFF00) in (0xC400, 0xC500, 0xC600):
        values[0] = None
        return tuple(values)

    for register in range(16):
        if _may_write_register(opcode, register):
            values[register] = None
    if group == 0x6 and low in (4, 5, 6):
        base = values[source]
        width = {4: 1, 5: 2, 6: 4}[low]
        values[source] = None if base is None else base + width
    return tuple(values)


def _execute_and_scan(
    data: bytes, pos: int, registers: tuple[int | None, ...],
    initial_pointer_value: int,
) -> tuple[tuple[int | None, ...], set[tuple[int, int, str]], set[tuple[int, int, str]]]:
    store, unresolved = _store_effect(data, pos, registers, initial_pointer_value)
    updated = _update_registers(data, pos, registers)
    stores = {store} if store is not None else set()
    unresolved_sites = {unresolved} if unresolved is not None else set()
    return updated, stores, unresolved_sites


def _scan_alias_stores_from_load(
    data: bytes, load_pos: int, base_value: int, base_register: int,
    max_span: int = 0x200, max_states: int = 20_000,
) -> dict:
    registers: list[int | None] = [None] * 16
    registers[base_register] = base_value
    initial = tuple(registers)
    start = load_pos + 2
    end = min(len(data) - 2, load_pos + max_span)
    queue = deque([(start, initial)])
    visited = set()
    stores = set()
    unresolved_indexed = set()
    backward_edges_skipped = 0
    call_boundaries = 0

    def execute_delay(delay_pos: int, state: tuple[int | None, ...]):
        if delay_pos < start or delay_pos > end or delay_pos + 2 > len(data):
            return state
        new_state, found, unknown = _execute_and_scan(
            data, delay_pos, state, base_value
        )
        stores.update(found)
        unresolved_indexed.update(unknown)
        return new_state

    while queue and len(visited) < max_states:
        pos, state = queue.popleft()
        if pos < start or pos > end or pos + 2 > len(data):
            continue
        key = (pos, state)
        if key in visited:
            continue
        visited.add(key)
        opcode = _word(data, pos)
        branch = branch_destination(pos, opcode)

        if branch is not None:
            kind, destination = branch
            if kind == "BRA":
                delay_state = execute_delay(pos + 2, state)
                if start <= destination <= end:
                    if destination >= pos:
                        queue.append((destination, delay_state))
                    else:
                        backward_edges_skipped += 1
                continue
            if kind == "BSR":
                delay_state = execute_delay(pos + 2, state)
                values = list(delay_state)
                for register in range(8):
                    values[register] = None
                call_boundaries += 1
                if pos + 4 <= end:
                    queue.append((pos + 4, tuple(values)))
                continue
            if kind.endswith("/S"):
                delay_state = execute_delay(pos + 2, state)
                if start <= destination <= end:
                    if destination >= pos:
                        queue.append((destination, delay_state))
                    else:
                        backward_edges_skipped += 1
                if pos + 4 <= end:
                    queue.append((pos + 4, delay_state))
                continue
            if start <= destination <= end:
                if destination >= pos:
                    queue.append((destination, state))
                else:
                    backward_edges_skipped += 1
            if pos + 2 <= end:
                queue.append((pos + 2, state))
            continue

        if _is_jsr(opcode):
            delay_state = execute_delay(pos + 2, state)
            values = list(delay_state)
            for register in range(8):
                values[register] = None
            call_boundaries += 1
            if pos + 4 <= end:
                queue.append((pos + 4, tuple(values)))
            continue

        if _is_jmp(opcode) or _is_rts(opcode):
            execute_delay(pos + 2, state)
            continue

        next_state, found, unknown = _execute_and_scan(
            data, pos, state, base_value
        )
        stores.update(found)
        unresolved_indexed.update(unknown)
        if pos + 2 <= end:
            queue.append((pos + 2, next_state))

    return {
        "stores": stores,
        "unresolved_indexed": unresolved_indexed,
        "visited_state_count": len(visited),
        "backward_edges_skipped": backward_edges_skipped,
        "call_boundaries": call_boundaries,
        "state_limit_reached": bool(queue) and len(visited) >= max_states,
    }


def _literal_load_sites(data: bytes, value: int) -> list[tuple[int, int]]:
    result = []
    for pos in range(0, len(data) - 1, 2):
        literal = movl_literal(data, pos)
        if literal is not None and literal[1] == value:
            result.append((pos, literal[2]))
    return result


def _raw_pointer_occurrences(data: bytes, value: int) -> tuple[int, int]:
    pattern = value.to_bytes(4, "big")
    positions = set()
    start = 0
    while True:
        found = data.find(pattern, start)
        if found < 0:
            break
        positions.add(found)
        start = found + 1
    literal_positions = {
        literal[0] for pos in range(0, len(data) - 1, 2)
        if (literal := movl_literal(data, pos)) is not None and literal[1] == value
    }
    return len(positions), len(positions - literal_positions)


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    _, count_address, callback_chain = _resolve_callback(data)
    target_literal_sites = _literal_load_sites(data, SOURCE_FIELD_START)
    source_store_sites = _direct_store_sites(data, SOURCE_FIELD_START)
    count_copy_sites = _count_length_assignments(data, count_address)
    all_store_sites = set()
    neighbor_alias_sites = set()
    unresolved_indexed_sites = set()
    total_visited = 0
    paths_truncated = 0
    backward_edges_skipped = 0
    call_boundaries = 0

    for base_value in NEARBY_POINTER_VALUES:
        for load_pos, base_register in _literal_load_sites(data, base_value):
            result = _scan_alias_stores_from_load(
                data, load_pos, base_value, base_register
            )
            total_visited += result["visited_state_count"]
            paths_truncated += int(result["state_limit_reached"])
            backward_edges_skipped += result["backward_edges_skipped"]
            call_boundaries += result["call_boundaries"]
            for pos, width, kind, effective_base, effective_address in result["stores"]:
                store_record = (pos, width, kind, effective_base, effective_address)
                all_store_sites.add(store_record)
                if effective_base != SOURCE_FIELD_START:
                    neighbor_alias_sites.add(store_record)
            unresolved_indexed_sites.update(result["unresolved_indexed"])

    widths = {
        "byte": sum(1 for _, width, _, _, _ in all_store_sites if width == 1),
        "word": sum(1 for _, width, _, _, _ in all_store_sites if width == 2),
        "long": sum(1 for _, width, _, _, _ in all_store_sites if width == 4),
    }
    raw_occurrences, unmatched_raw_occurrences = _raw_pointer_occurrences(
        data, SOURCE_FIELD_START
    )
    return {
        "schema_version": 1,
        "stage": "stage78_length_global_alias_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            "callback_id64_chain_verified": callback_chain,
            "source_global_pc_literal_reference_sites": len(target_literal_sites),
            "source_global_direct_store_signatures": len(source_store_sites),
            "callback_length_field_copy_sites": len(count_copy_sites),
            "source_global_literal_references_classified": (
                len(target_literal_sites) == len(source_store_sites) + len(count_copy_sites)
            ),
            "source_global_store_sites_found_in_bounded_alias_walk": len(all_store_sites),
            "source_global_store_width_counts": widths,
            "neighbor_base_alias_store_sites_found": len(neighbor_alias_sites),
            "unresolved_indexed_store_candidates": len(unresolved_indexed_sites),
            "source_global_raw_pointer_word_occurrences": raw_occurrences,
            "unmatched_embedded_pointer_word_occurrences": unmatched_raw_occurrences,
            "bounded_alias_walk_visited_state_count": total_visited,
            "bounded_alias_walk_backward_edges_skipped": backward_edges_skipped,
            "bounded_alias_walk_call_boundaries": call_boundaries,
            "bounded_alias_walk_state_limit_paths": paths_truncated,
            "all_source_global_writers_proven": False,
            "table_based_alias_paths_excluded": False,
            "source_global_initialization_order_proven": False,
            "global_length_count_upper_bound_proven": False,
            "runtime_callback_invocation_confirmed": False,
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
