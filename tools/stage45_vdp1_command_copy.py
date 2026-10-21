#!/usr/bin/env python3
"""Stage45: bounded SH-2 audit of direct 32-byte VDP1 VRAM command copies.

Only aggregate counts are emitted. No original program positions or bytes.
A static memory writer is not proof of game execution or handler 39 ownership.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import CODE_LOAD_BASE, movl_literal
from stage44_vdp1_vram_audit import hardware_literal_counts

VRAM_BASE = 0x25C00000
COMMAND_BYTES = 32
# Eight 32-bit longwords copied from source R3 into destination R1.
# Keys are byte distances from PC-relative MOV.L loading VRAM base into R7.
UNROLLED_COPY = {
    16: 0x6032, 18: 0x5E31, 20: 0x2102, 22: 0x11E1,
    24: 0x5032, 26: 0x5E33, 28: 0x1102, 30: 0x11E3,
    32: 0x5034, 34: 0x5E35, 36: 0x1104, 38: 0x11E5,
    40: 0x5036, 42: 0x5E37, 44: 0x1106, 46: 0x11E7,
}
SETUP = {
    -4: 0x2FE6, -2: 0xE600, 2: 0x6346, 4: 0x6145,
    6: 0x611D, 8: 0x4108, 10: 0x4100, 12: 0x317C,
    14: 0x6245,
}
LOOP = {
    48: 0x7320, 50: 0x72FF, 52: 0x7120, 54: 0x3260,
    58: 0x75FF, 60: 0x3560, 64: 0x000B, 66: 0x6EF6,
}


def bf_destination(pos: int, opcode: int) -> int | None:
    """SH-2 BF disp8: target = PC+4 + 2*signed8."""
    if pos < 0 or pos & 1 or opcode & 0xFF00 != 0x8B00:
        return None
    disp = opcode & 0xFF
    if disp & 0x80:
        disp -= 256
    return pos + 4 + 2 * disp


def match_vdp1_writer(data: bytes, load: int) -> dict | None:
    """Verify VRAM pointer -> R1 destination, eight stores and two BF loops."""
    if load < 4 or load & 1 or load + 68 > len(data):
        return None
    literal = movl_literal(data, load)
    if literal is None or literal[1] != VRAM_BASE or literal[2] != 7:
        return None
    if any(be16(data, load + off) != op for off, op in SETUP.items()):
        return None
    if any(be16(data, load + off) != op for off, op in UNROLLED_COPY.items()):
        return None
    if any(be16(data, load + off) != op for off, op in LOOP.items()):
        return None
    if bf_destination(load+56, be16(data, load+56)) != load+16:
        return None
    if bf_destination(load+62, be16(data, load+62)) != load+2:
        return None
    return {
        "entry": load - 4,
        "load": load,
        "source_ptr_register": "R3",
        "destination_ptr_register": "R1",
        "base_address_register": "R7",
        "command_destination_index_from": "unsigned16(MOV.W @R4+,R1)",
        "inner_command_count_from": "signed16(MOV.W @R4+,R2)",
        "outer_record_count_register": "R5",
        "longword_writes_per_command": 8,
        "bytes_per_command": COMMAND_BYTES,
        "destination_offset_scale": 8,
        "inner_loop_target_verified": True,
        "outer_loop_target_verified": True,
    }


def find_vdp1_writers(data: bytes) -> list[dict]:
    out = []
    for pos in range(4, len(data) - 68, 2):
        found = match_vdp1_writer(data, pos)
        if found is not None:
            out.append(found)
    return out


def find_indirect_writer_callers(data: bytes, entry: int) -> list[dict]:
    """PC-relative target load -> stack save R4 -> JSR target register."""
    result = []
    expected = CODE_LOAD_BASE + entry
    for pos in range(0, len(data) - 8, 2):
        info = movl_literal(data, pos)
        if info is None or info[1] != expected:
            continue
        reg = info[2]
        if (be16(data, pos+2) != 0x2F42
                or be16(data, pos+4) != (0x400B | reg << 8)
                or be16(data, pos+6) != 0x0009):
            continue
        result.append({"load": pos, "jsr": pos+4,
                       "preserves_incoming_r4_before_call": True})
    return result


def summarize(data: bytes) -> dict:
    original = hardware_literal_counts(data)
    writers = find_vdp1_writers(data)
    caller_counts = [len(find_indirect_writer_callers(data, w["entry"]))
                     for w in writers]
    return {
        "vdp1_base_address_literal_loads": original[
            "pc_relative_loads_vdp1_vram_base"],
        "exact_command_vram_copy_writers": len(writers),
        "pc_literal_resolved_jsr_callers_to_copy_writers": sum(caller_counts),
        "matched_writers_have_8_longword_stores": len(writers),
        "bytes_per_unrolled_copy": COMMAND_BYTES if writers else None,
        "command_address_base": "VDP1_VRAM" if writers else None,
        "command_address_offset_multiplier": 8 if writers else None,
        "destination_index_from_unsigned_word": bool(writers),
        "source_address_from_input_record": bool(writers),
        "inner_count_from_input_record_word": bool(writers),
        "outer_count_from_caller_r5": bool(writers),
        "verified_inner_and_outer_branch_targets": bool(writers),
        "matched_callers_save_r4_before_indirect_jsr": sum(caller_counts),
        "executed_during_actual_gameplay": False,
        "copy_invoked_by_function_39_verified": False,
        "specific_vdp1_commands_captured": False,
        "interpretation": (
            "A bounded SH-2 routine computes the destination VRAM address "
            "as VDP1_base plus unsigned 16-bit index times eight, copies "
            "eight 32-bit words from a source pointer into that address, "
            "and advances by 32 bytes in a nested two-counter loop. A "
            "PC-literal-resolved indirect JSR to that writer also exists."
        ) if writers else "No exact 32-byte writer signature matched.",
        "limitations": [
            "A syntactic memory-write path is not a recorded hardware event.",
            "Input counts are not known and may be invalid at runtime.",
            "Only one supported SH-2 writer pattern is recognized.",
            "No relation to function 39, 276-byte clones, or sprite pixels proved.",
            "No original executable positions or game bytes emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version": 1, "stage": "stage45_vdp1_command_copy",
            "target_file": "0TH2.BIN",
            "analysis": summarize(iso_file_payload(image))}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    rendered = json.dumps(analyze(args.image), ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
