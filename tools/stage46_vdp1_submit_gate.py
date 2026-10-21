#!/usr/bin/env python3
"""Stage46: audit the flag/count gate submitting prepared VDP1 command records.

Bounded SH-2 static evidence only: not a runtime trace or handler-39 linkage.
Only aggregate metadata; no original executable offsets/bytes or RAM addresses.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal
from stage45_vdp1_command_copy import find_vdp1_writers, find_indirect_writer_callers

GATE_TEMPLATE = {
    0x00:0x4F22,0x04:0x7FFC,0x06:0x6320,0x08:0x4311,
    0x0A:0x8912,0x0C:0xE100,0x10:0x2310,
    0x14:0x6501,0x16:0x625F,0x18:0x2228,0x1A:0x890A,
    0x20:0x2F42,0x22:0x420B,0x24:0x0009,0x26:0x63F2,
    0x28:0xE100,0x2C:0x2232,0x30:0x2311,
    0x32:0x7F04,0x34:0x4F26,0x36:0x000B,0x38:0x0009,
}
LOADING_REGS = {0x02:2,0x0E:3,0x12:0,0x1C:4,0x1E:2,0x2A:2,0x2E:3}


def bt_target(pos: int, opcode: int) -> int | None:
    if pos < 0 or pos & 1 or opcode & 0xFF00 != 0x8900:
        return None
    delta = opcode & 255
    if delta & 128:
        delta -= 256
    return pos + 4 + 2 * delta


def match_submit_gate(data: bytes, start: int, writer_entry: int) -> dict | None:
    if start < 0 or start & 1 or start+0x3A > len(data):
        return None
    if any(be16(data,start+off)!=op for off,op in GATE_TEMPLATE.items()):
        return None
    ptrs={}
    for offset,reg in LOADING_REGS.items():
        lit=movl_literal(data,start+offset)
        if lit is None or lit[2]!=reg:
            return None
        ptrs[offset]=lit[1]
    if (ptrs[0x02]!=ptrs[0x0E]
            or ptrs[0x12]!=ptrs[0x2E]
            or ptrs[0x1E]!=0x06004000+writer_entry
            or ptrs[0x1C]==ptrs[0x02]
            or ptrs[0x1C]==ptrs[0x12]):
        return None
    for offset,alignment in ((0x02,1),(0x12,2),(0x1C,4),(0x2A,4)):
        value=ptrs[offset]
        if not (0x06000000<=value<0x06100000) or value%alignment:
            return None
    if (bt_target(start+0x0A,be16(data,start+0x0A))!=start+0x32
            or bt_target(start+0x1A,be16(data,start+0x1A))!=start+0x32):
        return None
    return {
        "start":start,"writer_entry":writer_entry,
        "status_address":ptrs[0x02],"count_address":ptrs[0x12],
        "source_address":ptrs[0x1C],
        "last_submitted_pointer_address":ptrs[0x2A],
        "signed_status_must_be_negative":True,
        "status_cleared_before_count_check":True,
        "count_is_nonzero_after_unsigned_16_extension":True,
        "source_buffer_passed_as_r4":True,
        "count_passed_in_r5":True,
        "store_source_pointer_after_jsr":True,
        "reset_pending_count_after_jsr":True,
    }


def find_submit_gates(data: bytes) -> list[dict]:
    found=[]
    for writer in find_vdp1_writers(data):
        for call in find_indirect_writer_callers(data,writer["entry"]):
            gate=match_submit_gate(data,call["load"]-0x1E,writer["entry"])
            if gate is not None:
                found.append(gate)
    return found


def ptr_load_count(data: bytes, target: int) -> int:
    return sum(1 for pos in range(0,len(data)-5,2)
               if (lit:=movl_literal(data,pos)) is not None and lit[1]==target)


def summarize(data: bytes) -> dict:
    gates=find_submit_gates(data)
    gate=gates[0] if gates else None
    return {
        "verified_submit_gate_signatures":len(gates),
        "gates_with_negative_signed_byte_flag":sum(
            x["signed_status_must_be_negative"] for x in gates),
        "gates_with_unsigned_nonzero_record_count":sum(
            x["count_is_nonzero_after_unsigned_16_extension"] for x in gates),
        "status_cleared_before_count_test":bool(
            gate and gate["status_cleared_before_count_check"]),
        "command_source_r4_from_pc_literal":bool(
            gate and gate["source_buffer_passed_as_r4"]),
        "command_count_r5_from_global_word":bool(
            gate and gate["count_passed_in_r5"]),
        "source_base_pc_literal_loads":ptr_load_count(
            data,gate["source_address"]) if gate else 0,
        "status_byte_pointer_pc_literal_loads":ptr_load_count(
            data,gate["status_address"]) if gate else 0,
        "pending_count_pointer_pc_literal_loads":ptr_load_count(
            data,gate["count_address"]) if gate else 0,
        "committed_pointer_saved_after_copy":bool(
            gate and gate["store_source_pointer_after_jsr"]),
        "pending_count_cleared_after_copy":bool(
            gate and gate["reset_pending_count_after_jsr"]),
        "input_record_field_layout":(
            "u32 source_pointer, u16 vram_index, i16 command_count"
            if gate else None),
        "input_record_width_bytes":8 if gate else None,
        "destination_offset_unit_bytes":8 if gate else None,
        "vdp1_command_copy_size_bytes":32 if gate else None,
        "record_count_capacity_or_upper_bound_proven":False,
        "live_vdp1_command_output_proven":False,
        "handler_39_producer_identity_proven":False,
        "interpretation": (
            "A negative signed-byte status enables submission. The status "
            "is cleared, then a 16-bit pending-record count is checked "
            "for zero after zero-extension. If nonzero, R4 points to an "
            "8-byte-per-record prepared buffer and R5 holds the count; "
            "Stage45's 32-byte VDP1 copier is called. Finally the "
            "buffer pointer is saved and the count reset."
        ) if gate else "No complete submit gate verified.",
        "limitations":[
            "Negative status and nonzero count are not range-safety proofs.",
            "The number of input records and bytes used per record at runtime is unknown.",
            "A static VRAM store path does not attest actual GPU execution.",
            "Neither command producer nor handler 39 is linked to this gate.",
            "No private executable positions, RAM addresses or game bytes emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version":1,"stage":"stage46_vdp1_submit_gate",
            "target_file":"0TH2.BIN",
            "analysis":summarize(iso_file_payload(image))}


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("-o","--output",type=Path)
    args=p.parse_args()
    rendered=json.dumps(analyze(args.image),indent=2,ensure_ascii=False)+"\n"
    if args.output:
        args.output.write_text(rendered,encoding="utf-8")
    else:
        print(rendered,end="")


if __name__=="__main__":
    main()
