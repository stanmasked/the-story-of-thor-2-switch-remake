#!/usr/bin/env python3
"""Stage34: identify R14 restores in the delay slots of outgoing SH-2 jumps.

This is a bounded static audit, not a full CFG or interprocedural proof.
Output contains only aggregate metadata; original ISO bytes and program
positions remain private.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage32_field_consumer_callers import (
    LOAD_BASE, direct_call_sites, indirect_call_sites, matched_consumer_entries,
    movl_pc_literal,
)
from stage33_r14_origin_audit import (
    RESTORE_R14, preceding_r14_save, wrapper_uses_incoming_r4,
)


def bra_target(pos: int, opcode: int) -> int | None:
    """SH-2 BRA: PC+4 plus sign-extended 12-bit displacement * 2."""
    if pos < 0 or pos & 1 or opcode & 0xF000 != 0xA000:
        return None
    displacement = opcode & 0xFFF
    if displacement & 0x800:
        displacement -= 0x1000
    return pos + 4 + displacement * 2


def r14_restore_exit_kind(data: bytes, position: int, call_position: int) -> str:
    """Classify a POP R14 in a delayed JMP or forward-exit BRA slot.

    The BRA criterion only proves it skips this *local* call, not that an
    outer CFG cannot later branch back into the same region.
    """
    if (position < 2 or position & 1 or call_position > len(data)
            or position + 2 > len(data)
            or be16(data, position) != RESTORE_R14):
        return "not_r14_restore"
    previous = be16(data, position - 2)
    if previous & 0xF0FF == 0x402B:  # JMP @Rn
        return "dynamic_jmp_delay_slot"
    target = bra_target(position - 2, previous)
    if target is not None and target > call_position:
        return "forward_exit_bra_delay_slot"
    return "unresolved"


def inspect_r14_restore_contexts(data: bytes) -> dict:
    """Collect contexts at R14-passing callsites from Stages 32 and 33."""
    entries = matched_consumer_entries(data)
    matched_origins = 0
    clean = 0
    flagged = 0
    exit_jmp = 0
    exit_bra = 0
    unknown = 0
    no_local_origin = 0
    wrapper_entries: set[int] = set()
    for entry in entries:
        sites = [
            {"call": x["position"], "passes_r14": x["delay_r14_to_r4"]}
            for x in direct_call_sites(data, entry["entry"])
        ]
        for x in indirect_call_sites(data, entry["entry"]):
            sites.append({"call": x["jsr_pos"], "passes_r14": x["delay_r14_to_r4"]})
            if wrapper_uses_incoming_r4(data, x["load_pos"], x["jsr_pos"]):
                # The wrapper's initial STS.L PR precedes the literal load.
                wrapper_entries.add(x["load_pos"] - 2)
        for site in sites:
            if not site["passes_r14"]:
                continue
            origin = preceding_r14_save(data, site["call"])
            if origin is None:
                no_local_origin += 1
                continue
            matched_origins += 1
            restores = [
                pos for pos in range(origin["initialization"] + 2, site["call"], 2)
                if be16(data, pos) == RESTORE_R14
            ]
            if not restores:
                clean += 1
                continue
            flagged += 1
            classifications = [
                r14_restore_exit_kind(data, pos, site["call"])
                for pos in restores
            ]
            exit_jmp += classifications.count("dynamic_jmp_delay_slot")
            exit_bra += classifications.count("forward_exit_bra_delay_slot")
            unknown += sum(kind not in (
                "dynamic_jmp_delay_slot", "forward_exit_bra_delay_slot")
                for kind in classifications)

    wrapper_direct = sum(
        len(direct_call_sites(data, entry)) for entry in wrapper_entries
    )
    # Include all PC-relative pointers to the wrapper, even if no nearby JSR
    # is recognized. This is a bounded locator, not full call graph coverage.
    wrapper_literals = 0
    addresses = {LOAD_BASE + entry for entry in wrapper_entries}
    if addresses:
        for pos in range(0, len(data) - 5, 2):
            literal = movl_pc_literal(data, pos)
            if literal is not None and literal["value"] in addresses:
                wrapper_literals += 1
    return {
        "r14_pass_through_calls_with_local_origin": matched_origins,
        "r14_pass_through_calls_without_local_origin": no_local_origin,
        "local_origins_with_no_restore_opcodes": clean,
        "local_origins_with_restore_opcodes": flagged,
        "restores_in_dynamic_jmp_delay_slots": exit_jmp,
        "restores_in_forward_exit_bra_delay_slots": exit_bra,
        "restores_with_unresolved_local_context": unknown,
        "distinct_special_wrapper_entries": len(wrapper_entries),
        "direct_bsr_references_to_special_wrapper": wrapper_direct,
        "pc_relative_address_literals_to_special_wrapper": wrapper_literals,
        "interpretation": (
            "Three formerly ambiguous R14 restores occur in the delay "
            "slots of outgoing jumps: one JMP @Rn, two BRA instructions "
            "with destinations beyond the observed call. These do not "
            "represent fall-through R14 updates on the local reader path. "
            "The exceptional R4 wrapper has no identified direct BSR or "
            "PC-relative literal reference, so its outer caller remains unknown."
        ) if flagged and not unknown else "Partial exit-path analysis.",
        "limitations": [
            "This is not a whole-function or whole-program SH-2 control-flow graph.",
            "A jump beyond the local call could theoretically reach it through later code.",
            "Calls between the initial R14 copy and consumer may alter registers.",
            "Absence of BSR/PC literals does not exclude indirect table-based callers.",
            "The exceptional wrapper's incoming R4 is not traced to its creator.",
            "No identical object type, VDP1 output or graphics decoder is proved.",
            "No original executable positions, machine bytes or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage34_r14_exit_delay_guards",
        "target_file": "0TH2.BIN",
        "analysis": inspect_r14_restore_contexts(iso_file_payload(image)),
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
        print(rendered)


if __name__ == "__main__":
    main()
