#!/usr/bin/env python3
"""Stage25: narrow SH-2 R4 argument preservation and first-factor mask path.

Private ISO is read locally; outputs only aggregate metadata, never original
program bytes, exact file positions, or game resources.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload
from stage24_loop_counter_probe import find_signed_descriptor_loops

PUSH_R13 = 0x2FD6
SAVE_INPUT_R4_IN_R13 = 0x6D43
FRAME_ALLOC = 0x7FA8
PASS_SAVED_INPUT_IN_R4 = 0x64D3
MASK_REWRITE = (0xE014, 0x61F3, 0x00FC, 0x7114, 0xC93F, 0x2100)


def is_explicit_branch(opcode: int) -> bool:
    """Recognize common SH-2 branches, register jumps and returns."""
    return (
        opcode & 0xF000 in (0xA000, 0xB000)
        or opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00)
        or opcode & 0xF0FF in (0x400B, 0x402B, 0x0003, 0x0023)
        or opcode in (0x000B, 0x002B)
    )


def signed_pc_relative_bsr_target(offset: int, opcode: int) -> int | None:
    """BSR signed 12-bit displacement; instruction has one delay slot."""
    if offset < 0 or offset % 2 or opcode & 0xF000 != 0xB000:
        return None
    displacement = opcode & 0x0FFF
    if displacement & 0x0800:
        displacement -= 0x1000
    return offset + 4 + displacement * 2


def find_input_preservation_paths(data: bytes) -> list[dict]:
    """Find entry R4->R13 and the later BSR delay-slot R13->R4.

    A helper call may clobber caller-saved R4: this does NOT prove R4 is
    unchanged after return from the helper.
    """
    matches = []
    for loop in find_signed_descriptor_loops(data):
        head = loop["head"]
        for pushed in range(max(0, head - 1024), head - 22, 2):
            if be16(data, pushed) != PUSH_R13:
                continue
            saves = [p for p in range(pushed + 2, min(pushed + 14, head - 2), 2)
                     if be16(data, p) == SAVE_INPUT_R4_IN_R13]
            if not saves:
                continue
            frames = [p for p in range(saves[0] + 2, min(saves[0] + 28, head - 2), 2)
                      if be16(data, p) == FRAME_ALLOC]
            if not frames:
                continue
            for call in range(frames[0] + 2, head - 2, 2):
                if be16(data, call + 2) != PASS_SAVED_INPUT_IN_R4:
                    continue
                target = signed_pc_relative_bsr_target(call, be16(data, call))
                if target is None or not (0 <= target < len(data)):
                    continue
                matches.append({"saved": saves[0], "call": call, "target": target})
    return matches


def mask_placement(data: bytes, head: int, tail: int) -> dict:
    """Check full stack-byte mask rewrite in branch-free loop prefix.

    Only a local linear path from the recognized head is established, not
    reachability of that head from every possible caller/entry.
    """
    masks = []
    for pos in range(head + 8, tail - 2, 2):
        if all(be16(data, pos - 8 + index * 2) == opcode
               for index, opcode in enumerate(MASK_REWRITE)):
            masks.append(pos)
    for mask_pos in masks:
        if not any(is_explicit_branch(be16(data, pos))
                   for pos in range(head, mask_pos, 2)):
            return {"mask_and_store": True, "prefix_unbranched": True}
    return {"mask_and_store": bool(masks), "prefix_unbranched": False}


def summarize_r4_provenance(data: bytes) -> dict:
    loops = find_signed_descriptor_loops(data)
    paths = find_input_preservation_paths(data)
    masks = [mask_placement(data, item["head"], item["tail"]) for item in loops]
    return {
        "complete_loop_signatures": len(loops),
        "saved_input_r4_in_r13_with_local_frame": len({p["saved"] for p in paths}),
        "relative_bsr_calls_passing_saved_pointer_in_delay_slot":
            len({p["call"] for p in paths}),
        "helper_targets_within_same_executable": len({p["target"] for p in paths}),
        "loop_heads_with_unbranched_prefix_to_mask":
            sum(m["prefix_unbranched"] for m in masks),
        "mask_and_byte_store_patterns_in_loop":
            sum(m["mask_and_store"] for m in masks),
        "interpretation": (
            "A function saves incoming R4 into R13, later uses R13 as the R4 "
            "argument in the delay slot of a BSR helper call. From the known "
            "loop head, no recognized control-flow instruction occurs before "
            "a full stack-byte mask-and-store using AND #0x3f."
        ),
        "limitations": [
            "The helper may clobber R4; its post-return value is not confirmed.",
            "The loop head may not be reached by all possible entry paths.",
            "This is a short opcode-pattern audit, not whole-program CFG or emulation.",
            "No program positions, original bytes or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {"schema_version": 1, "stage": "stage25_r4_helper_mask_prefix",
            "target_file": "0TH2.BIN",
            "analysis": summarize_r4_provenance(iso_file_payload(image))}


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
