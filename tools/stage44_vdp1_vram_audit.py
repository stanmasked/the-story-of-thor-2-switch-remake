#!/usr/bin/env python3
"""Stage44: static VDP1 pointer references and private offline VRAM audit.

The original Saturn ISO and all raw VRAM dumps remain LOCAL. JSON reports
only aggregate metadata; a dump is not authentication of gameplay execution.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from stage18_writer_guard_flow import iso_file_payload
from stage35_table_tail_link import movl_literal

VDP1_VRAM_BYTES = 0x80000
COMMAND_BYTES = 0x20
VDP1_BASES = (0x25C00000, 0x25D00000)
TYPE_NAMES = {
    0:"normal_sprite",1:"scaled_sprite",2:"distorted_sprite",
    4:"polygon",5:"polyline",6:"line",8:"user_clipping",
    9:"system_clipping",10:"local_coordinates",
}
JUMP_NAMES = (
    "next","assign","call","return","skip_next",
    "skip_assign","skip_call","skip_return",
)


def hardware_literal_counts(data: bytes) -> dict:
    counts: Counter[int] = Counter()
    for pos in range(0,len(data)-5,2):
        info = movl_literal(data,pos)
        if info is not None and info[1] in VDP1_BASES:
            counts[info[1]] += 1
    return {
        "pc_relative_loads_vdp1_vram_base":counts[VDP1_BASES[0]],
        "pc_relative_loads_vdp1_register_base":counts[VDP1_BASES[1]],
        "vdp1_memory_writes_from_game_confirmed":False,
        "scope":"syntactic_PC_relative_pointer_loads_only",
    }


def _word(data: bytes, position: int) -> int:
    return int.from_bytes(data[position:position+2],"big")


def parse_command_chain(vram: bytes, max_commands: int=4096) -> tuple[dict,set[int]]:
    """Parse 32-byte VDP1 command records with 1-level CALL/RETURN.

    Tracks command-list control flow but does not decode pixels, validate
    the entire Saturn VDP1 rasterizer, or attest actual VDP1 execution.
    """
    if len(vram) != VDP1_VRAM_BYTES:
        raise ValueError("VDP1 dump must be exactly 524288 bytes")
    if type(max_commands) is not int or not 1 <= max_commands <= 16384:
        raise ValueError("max_commands must be in 1..16384")
    pos = 0
    ret = None
    states:set[tuple[int,int|None]]=set()
    visited:set[int]=set()
    kinds:Counter[str]=Counter()
    jumps:Counter[str]=Counter()
    skipped=executed=unknown=zero_sizes=0
    termination="limit"
    for _ in range(max_commands):
        if pos < 0 or pos+COMMAND_BYTES > len(vram):
            termination="command_out_of_bounds"
            break
        if pos%COMMAND_BYTES:
            termination="unaligned_command_address"
            break
        state=(pos,ret)
        if state in states:
            termination="cycle"
            break
        states.add(state)
        visited.add(pos)
        ctrl=_word(vram,pos)
        if ctrl & 0x8000:
            termination="end_bit"
            break
        mode=(ctrl>>12)&7
        kind=ctrl&0xF
        jumps[JUMP_NAMES[mode]]+=1
        if mode&4:
            skipped+=1
        else:
            executed+=1
            kinds[TYPE_NAMES.get(kind,"unknown")]+=1
            if kind not in TYPE_NAMES:
                unknown+=1
            if kind in (0,1,2):
                size=_word(vram,pos+0x0A)
                if (((size>>8)&0x3F)*8)==0 or (size&0xFF)==0:
                    zero_sizes+=1
        variant=mode&3
        if variant==0:
            pos+=COMMAND_BYTES
        elif variant in (1,2):
            dest=_word(vram,pos+2)*8
            if variant==2:
                if ret is not None:
                    termination="nested_call_unsupported"
                    break
                ret=pos+COMMAND_BYTES
            pos=dest
        else:
            if ret is None:
                termination="return_without_call"
                break
            pos,ret=ret,None
    return ({
        "visited_distinct_command_entries":len(visited),
        "executed_non_end_entries":executed,
        "skipped_entries":skipped,
        "terminated_by":termination,
        "end_bit_reached":termination=="end_bit",
        "types_executed":dict(sorted(kinds.items())),
        "jump_modes":dict(sorted(jumps.items())),
        "unsupported_command_types":unknown,
        "sprite_size_zero_candidates":zero_sizes,
        "confirmed_hardware_execution":False,
        "rendered_pixels_produced":False,
    },visited)


def compare_vram_dumps(before: bytes, after: bytes,
                       max_commands: int=4096) -> dict:
    first,first_positions=parse_command_chain(before,max_commands)
    second,second_positions=parse_command_chain(after,max_commands)
    changed_bytes=sum(a!=b for a,b in zip(before,after))
    positions=first_positions|second_positions
    changed_slots=sum(
        before[p:p+COMMAND_BYTES]!=after[p:p+COMMAND_BYTES]
        for p in positions
    )
    return {
        "before_chain":first,
        "after_chain":second,
        "changed_vram_bytes":changed_bytes,
        "reachable_command_slots_compared":len(positions),
        "changed_reachable_command_slots":changed_slots,
        "dumps_are_identical":changed_bytes==0,
        "emulator_origin_authenticated":False,
        "changes_attributed_to_handler_39":False,
        "note":"Offline VRAM differences do not establish SH-2-to-VDP1 causality",
    }


def analyze(image: Path, before: Path|None=None,
            after: Path|None=None) -> dict:
    if (before is None)!=(after is None):
        raise ValueError("Before and after VRAM dumps must both be supplied")
    result={
        "schema_version":1,"stage":"stage44_vdp1_vram_audit",
        "target_file":"0TH2.BIN",
        "static_hardware_references":hardware_literal_counts(
            iso_file_payload(image)),
    }
    if before is not None:
        result["untrusted_offline_dump_comparison"]=compare_vram_dumps(
            before.read_bytes(),after.read_bytes())
    return result


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path)
    p.add_argument("--before-vram-private",type=Path)
    p.add_argument("--after-vram-private",type=Path)
    p.add_argument("-o","--output",type=Path)
    args=p.parse_args()
    encoded=json.dumps(analyze(args.image,args.before_vram_private,
                               args.after_vram_private),indent=2,
                       ensure_ascii=False)+"\n"
    if args.output:
        args.output.write_text(encoded,encoding="utf-8")
    else:
        print(encoded,end="")


if __name__=="__main__":
    main()
