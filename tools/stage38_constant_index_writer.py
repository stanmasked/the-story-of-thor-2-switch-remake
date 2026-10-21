#!/usr/bin/env python3
"""Stage38: audit constant-38 SH-2 store and its neighboring flag update.

Static executable pattern evidence; does not prove that the object reaches
the dispatcher at runtime. No private bytes or source offsets are emitted.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage36_dispatch_index_audit import _pointer_table, scan_dispatches


def candidate_store_pairs(data: bytes, base_register: int) -> list[dict]:
    """MOV #126,R0; MOV.W Rm,@(R0,Rbase) (syntactic candidates only)."""
    if not 0 <= base_register <= 15:
        raise ValueError("invalid SH-2 base register")
    return [
        {"position": p, "source_register": (be16(data,p+2)>>4)&15}
        for p in range(0,len(data)-3,2)
        if be16(data,p) == 0xE07E
        and (be16(data,p+2)&0xFF0F) == (base_register<<8 | 0x0005)
    ]


def adjacent_immediate_stores(data: bytes, base_register: int) -> list[dict]:
    """An immediate into the source register directly precedes a store pair."""
    result=[]
    for candidate in candidate_store_pairs(data,base_register):
        p=candidate["position"]
        if p < 2:
            continue
        immediate=be16(data,p-2)
        if (immediate & 0xFF00) != (0xE000 | candidate["source_register"]<<8):
            continue
        val=immediate&0xFF
        result.append({"position":p,"value":val-256 if val&0x80 else val})
    return result


def exact_slot39_writer(data: bytes, position: int) -> bool:
    """Seven-word straight-line constant-38 assignment, with flag byte store.

    None of the five intervening instructions writes R3 before the word
    store. SH-2 branch reachability and pointer identity remain unproved.
    """
    p=position
    if p < 10 or p & 1 or p+4 > len(data):
        return False
    return (
        be16(data,p-10)==0xE326           # MOV #38,R3
        and be16(data,p-8)&0xFF00==0xDC00 # MOV.L literal,R12
        and be16(data,p-6)==0xE219       # MOV #25,R2
        and be16(data,p-4)==0xCB09       # OR #9,R0
        and be16(data,p-2)==0x80E7       # MOV.B R0,@(7,R14)
        and be16(data,p)==0xE07E         # MOV #126,R0
        and be16(data,p+2)==0x0E35       # MOV.W R3,@(R0,R14)
    )


def summarize(data: bytes) -> dict:
    dispatch=scan_dispatches(data)
    table=_pointer_table(data)
    stores_r14=candidate_store_pairs(data,14)
    stores_r4=candidate_store_pairs(data,4)
    adjacent_r14=adjacent_immediate_stores(data,14)
    adjacent_r4=adjacent_immediate_stores(data,4)
    matching=[s for s in stores_r14 if exact_slot39_writer(data,s["position"])]
    selected=table["entry_index_zero_based"] if table is not None else None
    return {
        "linked_signed_dispatch_patterns":dispatch["complete_dispatch_patterns"],
        "linked_function_table_size":table["entries"] if table else None,
        "selected_function_slot_one_based":selected+1 if selected is not None else None,
        "candidate_store_pairs_via_R14_offset_126":len(stores_r14),
        "candidate_store_pairs_via_R4_offset_126":len(stores_r4),
        "immediate_adjacent_constant_stores_via_R14":len(adjacent_r14),
        "immediate_adjacent_constant_stores_via_R4":len(adjacent_r4),
        "adjacent_R14_constant_zero":sum(s["value"]==0 for s in adjacent_r14),
        "adjacent_R4_constant_zero":sum(s["value"]==0 for s in adjacent_r4),
        "exact_local_constant_38_and_flag_update_writers":len(matching),
        "confirmed_local_straight_line_R3_value":38 if matching else None,
        "verified_local_flag_byte_offset":7 if matching else None,
        "verified_local_index_word_offset":126 if matching else None,
        "writer_constant_equals_base_table_selected_index":bool(matching and selected==38),
        "writer_and_dispatcher_runtime_object_identity_verified":False,
        "interpretation":(
            "A seven-instruction straight-line SH-2 sequence stores constant "
            "38 to word [R14+126], while also updating byte [R14+7]. "
            "38 is the zero-based index of function entry 39 in the linked "
            "68-entry table. This does not prove an identical runtime R14 object."
        ) if matching else "No exact constant-38 writer cluster found.",
        "limitations":[
            "Candidate stores are opcode matches, not established runtime writes.",
            "The writer's R14 need not be the same object as dispatcher R14.",
            "The cluster's control-flow reachability is not established.",
            "Earlier index checks, VDP1 output and sprite decoding are unverified.",
            "No original executable positions, bytes or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version":1,"stage":"stage38_constant_index_writer",
            "target_file":"0TH2.BIN",
            "analysis":summarize(iso_file_payload(image))}


def main() -> None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image",type=Path)
    ap.add_argument("-o","--output",type=Path)
    args=ap.parse_args()
    rendered=json.dumps(analyze(args.image),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.write_text(rendered,encoding="utf-8")
    else:
        print(rendered)


if __name__=="__main__":
    main()
