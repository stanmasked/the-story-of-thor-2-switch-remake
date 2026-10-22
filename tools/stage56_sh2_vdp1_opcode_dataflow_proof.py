#!/usr/bin/env python3
"""Stage56: independently decode the Stage45 SH-2 VDP1 longword dataflow.

Only bounded STATIC program decoding and synthetic reconstruction. This is
not an emulator and does not attest any original game instructions executed.
Never exports original code bytes, executable positions or source values.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage45_vdp1_command_copy import (
    find_vdp1_writers, bf_destination, VRAM_BASE, COMMAND_BYTES,
)
from stage48_vdp1_copy_witness import (
    VRAM_BYTES, INDEX_UNIT_BYTES, parse_manifest,
)
from stage49_sh2_vdp1_trace_contract import (
    find_private_roles, STORE_OFFSETS_FROM_LOAD, MAX_COMMANDS_IN_TRACE,
)
from stage50_sh2_load_mapping_evidence import REFERENCE_ISO_SHA256, _iso_sha256

COPY_FIRST = 16
COPY_LAST = 46
EXPECTED_WORDS = 8


def decode_copy_words(program: bytes) -> dict:
    """Track R0/R14 load provenance through the 16 unrolled SH-2 ops.

    SH-2 MOV.L formats used:
      0110nnnnmmmm0010 -> MOV.L @Rm,Rn
      0101nnnnmmmmdddd -> MOV.L @(disp*4,Rm),Rn
      0010nnnnmmmm0010 -> MOV.L Rm,@Rn
      0001nnnnmmmmdddd -> MOV.L Rm,@(disp*4,Rn)
    """
    writers = find_vdp1_writers(program)
    if len(writers) != 1:
        raise ValueError("one original-style VDP1 writer is required")
    w = writers[0]
    load = w["load"]
    registers = {}
    pairs = []
    load_registers = []
    for off in range(COPY_FIRST, COPY_LAST + 1, 2):
        opcode = be16(program, load + off)
        n, m = (opcode >> 8) & 15, (opcode >> 4) & 15
        high = opcode & 0xF000
        if opcode & 0xF00F == 0x6002:
            if m != 3:
                raise ValueError("unrolled source must be R3")
            registers[n] = 0
            load_registers.append(n)
        elif high == 0x5000:
            if m != 3:
                raise ValueError("indexed longword must use source R3")
            registers[n] = opcode & 15
            load_registers.append(n)
        elif opcode & 0xF00F == 0x2002:
            if n != 1 or m not in registers:
                raise ValueError("unrolled direct store must target R1 and loaded source")
            pairs.append((registers[m], 0, off))
        elif high == 0x1000:
            if n != 1 or m not in registers:
                raise ValueError("unrolled displacement store must target R1")
            pairs.append((registers[m], opcode & 15, off))
        else:
            raise ValueError("unrecognized SH-2 opcode in 32-byte writer")

    if len(pairs) != EXPECTED_WORDS or len(load_registers) != EXPECTED_WORDS:
        raise ValueError("unrolled loop must contain eight loads and eight stores")
    if [(source, dest) for source, dest, _ in pairs] != [
            (i, i) for i in range(EXPECTED_WORDS)]:
        raise ValueError("source and destination longword offsets are not sequential")
    if len(set(off for _, _, off in pairs)) != EXPECTED_WORDS:
        raise ValueError("duplicate store instruction offsets")
    # Check inner/outer ADD #-1 and CMP/EQ are on R2/R5, and branch targets.
    if any(be16(program, load + off) != word for off, word in (
            (48, 0x7320), (50, 0x72FF), (52, 0x7120),
            (54, 0x3260), (58, 0x75FF), (60, 0x3560))):
        raise ValueError("SH-2 source/destination pointer and R2/R5 loop semantics changed")
    if (bf_destination(load + 56, be16(program, load + 56)) != load + COPY_FIRST
            or bf_destination(load + 62, be16(program, load + 62)) != load + 2):
        raise ValueError("inner or outer SH-2 branch target mismatch")
    return {
        "source_word_indices": tuple(x for x, _, _ in pairs),
        "destination_word_indices": tuple(y for _, y, _ in pairs),
        "store_offsets_from_vdp1_literal_load": tuple(off for _, _, off in pairs),
        "inner_command_count_register": "R2",
        "outer_descriptor_count_register": "R5",
        "source_pointer_step_bytes": COMMAND_BYTES,
        "vdp1_destination_step_bytes": COMMAND_BYTES,
        "vdp1_destination_index_unit_bytes": INDEX_UNIT_BYTES,
    }


def compare_trace_roles(program: bytes) -> bool:
    """Independent decode agrees with the older Stage49 hardcoded PC-role list."""
    decoded = decode_copy_words(program)
    roles = find_private_roles(program)
    writers = find_vdp1_writers(program)
    base_pc = roles["stores"][0] - decoded["store_offsets_from_vdp1_literal_load"][0]
    return (decoded["store_offsets_from_vdp1_literal_load"]
            == tuple(STORE_OFFSETS_FROM_LOAD)
            and tuple(base_pc + off
                      for off in decoded["store_offsets_from_vdp1_literal_load"])
            == tuple(roles["stores"])
            and len(writers) == 1)


def simulate_from_decoded(program: bytes, metadata: dict,
                         source_commands: bytes) -> list[tuple[int, int]]:
    """Private in-memory word stores. Does not perform CPU runtime execution."""
    decoded = decode_copy_words(program)
    manifest = parse_manifest(metadata)
    records = manifest["descriptors"]
    total = sum(d["copy_count"] for d in records)
    if (type(source_commands) is not bytes or total > MAX_COMMANDS_IN_TRACE
            or len(source_commands) != total * COMMAND_BYTES):
        raise ValueError("private source command length exceeds bounded contract")
    if manifest["pending_count_before"] != len(records):
        raise ValueError("R5 outer-loop count must equal number of descriptors")
    output = []
    cursor = 0
    for record in records:
        for k in range(record["copy_count"]):
            vram_byte_offset = (record["destination_index"] * INDEX_UNIT_BYTES
                                + k * decoded["vdp1_destination_step_bytes"])
            for source_i, destination_i in zip(decoded["source_word_indices"],
                                               decoded["destination_word_indices"]):
                src = cursor + source_i * 4
                dest = vram_byte_offset + destination_i * 4
                if dest + 4 > VRAM_BYTES:
                    raise ValueError("simulated VDP1 store extends outside VRAM")
                output.append((dest, int.from_bytes(source_commands[src:src+4], "big")))
            cursor += COMMAND_BYTES
    return output


def summarize_static(program: bytes, metadata: dict | None = None,
                     source_commands: bytes | None = None) -> dict:
    decode = decode_copy_words(program)
    if not compare_trace_roles(program):
        raise ValueError("independently decoded SH-2 stores disagree with Stage49 roles")
    if (metadata is None) != (source_commands is None):
        raise ValueError("source bytes and metadata must be supplied together")
    checked = None
    records = None
    if metadata is not None:
        records = len(parse_manifest(metadata)["descriptors"])
        checked = len(simulate_from_decoded(program, metadata, source_commands))
    return {
        "schema_version": 1,
        "stage": "stage56_sh2_vdp1_opcode_dataflow_proof",
        "unique_static_writer_pattern_confirmed": True,
        "sh2_longword_loads_decoded": EXPECTED_WORDS,
        "sh2_longword_stores_decoded": EXPECTED_WORDS,
        "source_longword_offsets_contiguous": True,
        "destination_longword_offsets_contiguous": True,
        "source_word_order_matches_destination_order": True,
        "decoded_pc_roles_match_stage49": True,
        "inner_loop_register": decode["inner_command_count_register"],
        "outer_loop_register": decode["outer_descriptor_count_register"],
        "source_step_bytes_per_command": decode["source_pointer_step_bytes"],
        "vdp1_step_bytes_per_command": decode["vdp1_destination_step_bytes"],
        "private_descriptors_replayed": records,
        "private_32bit_store_events_replayed": checked,
        "original_gameplay_execution_observed": False,
        "saturn_emulator_trace_authenticated": False,
        "handler_39_to_vdp1_proven": False,
        "original_executable_positions_or_code_exported": False,
        "limitations": [
            "Decodes a restricted known SH-2 instruction sequence, not all CPU instructions.",
            "Instruction semantics are checked statically; CPU execution was not recorded.",
            "Private optional replay uses operator-supplied source commands, never live GPU evidence.",
            "Original copyrighted instruction bytes and source words are not printed.",
        ],
    }


def run_private(iso: Path) -> dict:
    if _iso_sha256(iso) != REFERENCE_ISO_SHA256:
        raise ValueError("private Saturn ISO SHA-256 does not match pinned reference")
    return summarize_static(iso_file_payload(iso))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso-private", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run_private(args.iso_private), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
