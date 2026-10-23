#!/usr/bin/env python3
"""Stage79: expanded SH-2 store-mode and pointer-alias census.

Aggregate-only analysis for the length-source field. The bounded linear scan
is deliberately not an exhaustive interprocedural memory/alias proof.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal
from stage75_indirect_services_count_provenance import (
    LENGTH_SOURCE_GLOBAL,
    _may_write_register,
)


def _store_shape(opcode: int):
    """Return (mode, base register, width, displacement, indexed) or None."""
    low = opcode & 0xF
    base = (opcode >> 8) & 0xF

    # MOV.{B,W,L} Rm,@Rn
    if opcode & 0xF00F in (0x2000, 0x2001, 0x2002):
        width = {0: 1, 1: 2, 2: 4}[low]
        return "indirect", base, width, 0, False

    # MOV.{B,W,L} Rm,@-Rn
    if opcode & 0xF00F in (0x2004, 0x2005, 0x2006):
        width = {4: 1, 5: 2, 6: 4}[low]
        return "predecrement", base, width, -width, False

    # MOV.{B,W,L} Rm,@(R0,Rn)
    if opcode & 0xF00F in (0x0004, 0x0005, 0x0006):
        width = {4: 1, 5: 2, 6: 4}[low]
        return "indexed_r0", base, width, 0, True

    # MOV.W Rm,@(disp,Rn): 1000 nnnn 1mmm dddd
    if opcode & 0xF080 == 0x8080:
        return "displacement_word", base, 2, (opcode & 0xF) * 2, False

    # MOV.L Rm,@(disp,Rn): 0001 nnnn mmmm dddd
    if opcode >> 12 == 0x1:
        return "displacement_long", base, 4, (opcode & 0xF) * 4, False

    return None


def _is_control_transfer(opcode: int) -> bool:
    return (
        opcode >> 12 in (0xA, 0xB)
        or opcode in (0x000B, 0x002B)
        or opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00)
        or opcode & 0xF0FF in (0x400B, 0x402B)
    )


def _signed8(value: int) -> int:
    return value - 256 if value & 0x80 else value


def _scan_from_literal(
    data: bytes,
    start: int,
    literal_value: int,
    pointer_reg: int,
    target: int,
    radius: int,
    window: int,
) -> tuple[dict[int, tuple[str, bool]], set[int]]:
    """Scan one bounded linear path; return store sites and unresolved indexed sites."""
    regs: dict[int, int] = {pointer_reg: literal_value}
    adjusted: dict[int, bool] = {pointer_reg: False}
    stores: dict[int, tuple[str, bool]] = {}
    indexed_unknown: set[int] = set()
    stop = min(len(data) - 1, start + window * 2)

    def inspect_store(pos: int, opcode: int) -> None:
        shape = _store_shape(opcode)
        if shape is None:
            return
        mode, base_reg, width, displacement, indexed = shape
        if base_reg not in regs:
            return
        base_value = regs[base_reg]
        if indexed:
            if 0 in regs:
                effective = base_value + regs[0]
            else:
                if abs(base_value - target) <= radius:
                    indexed_unknown.add(pos)
                return
        else:
            effective = base_value + displacement
        if effective == target:
            stores[pos] = (mode, adjusted.get(base_reg, False) or base_value != literal_value)
        if mode == "predecrement":
            regs[base_reg] = base_value - width
            adjusted[base_reg] = adjusted.get(base_reg, False) or base_value != literal_value

    pos = start + 2
    while pos < stop:
        opcode = be16(data, pos)
        inspect_store(pos, opcode)

        # An explicit PC-relative literal load can seed or replace an alias.
        literal = movl_literal(data, pos)
        if literal is not None:
            regs[literal[2]] = literal[1]
            adjusted[literal[2]] = literal[1] != target
            pos += 2
            continue

        # ADD #imm,Rn propagates a known pointer value.
        if opcode >> 12 == 0x7:
            reg = (opcode >> 8) & 0xF
            if reg in regs:
                regs[reg] = (regs[reg] + _signed8(opcode & 0xFF)) & 0xFFFFFFFF
                adjusted[reg] = True
            pos += 2
            continue

        # MOV Rm,Rn copies known address aliases without consuming the source.
        if opcode >> 12 == 0x6 and opcode & 0xF == 0x3:
            dst = (opcode >> 8) & 0xF
            src = (opcode >> 4) & 0xF
            if src in regs:
                regs[dst] = regs[src]
                adjusted[dst] = adjusted.get(src, False) or regs[src] != target
            elif dst in regs:
                del regs[dst]
                adjusted.pop(dst, None)
            pos += 2
            continue

        if _is_control_transfer(opcode):
            delay_pos = pos + 2
            if delay_pos + 2 <= len(data):
                inspect_store(delay_pos, be16(data, delay_pos))
            break

        # Conservatively drop any pointer aliases that an instruction may
        # overwrite; store instructions themselves have no destination alias.
        for reg in tuple(regs):
            if _may_write_register(opcode, reg):
                regs.pop(reg, None)
                adjusted.pop(reg, None)
        pos += 2

    return stores, indexed_unknown


def scan_store_aliases(
    data: bytes,
    target: int = LENGTH_SOURCE_GLOBAL,
    radius: int = 16,
    window: int = 64,
) -> dict:
    stores: dict[int, tuple[str, bool]] = {}
    unresolved_indexed: set[int] = set()
    literal_sites = 0
    for pos in range(0, len(data) - 5, 2):
        literal = movl_literal(data, pos)
        if literal is None or abs(literal[1] - target) > radius:
            continue
        literal_sites += 1
        found, indexed = _scan_from_literal(
            data, pos, literal[1], literal[2], target, radius, window
        )
        for store_pos, detail in found.items():
            stores[store_pos] = detail
        unresolved_indexed.update(indexed)

    modes = Counter(mode for mode, _ in stores.values())
    return {
        "nearby_pc_literal_pointer_load_sites": literal_sites,
        "exact_target_store_candidates": len(stores),
        "store_candidates_by_mode": dict(sorted(modes.items())),
        "store_candidates_requiring_pointer_arithmetic_or_alias": sum(
            alias for _, alias in stores.values()
        ),
        "unresolved_indexed_store_candidates": len(unresolved_indexed),
        "all_store_writers_resolved": False,
        "arbitrary_register_arithmetic_and_interprocedural_aliases_excluded": False,
        "runtime_initialization_order_proven": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    return {
        "schema_version": 1,
        "stage": "stage79_expanded_store_alias_audit",
        "target_file": "0TH2.BIN",
        "analysis": {
            **scan_store_aliases(data),
            "global_length_upper_bound_proven": False,
            "runtime_callback_order_proven": False,
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
