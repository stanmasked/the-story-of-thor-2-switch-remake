#!/usr/bin/env python3
"""Stage24: recognize the signed byte-counter backedge of the VDP1 descriptor loop.

Analyzes the original ISO privately and emits aggregate metadata only.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from stage18_writer_guard_flow import be16, iso_file_payload

INIT = (0x8491, 0x63F3, 0x7338, 0x2300)
HEAD = (0x6291, 0xE03C, 0x0F25)
TAIL = (0xE038, 0x02FC, 0x72FF, 0xE038, 0x0F24,
        0xE038, 0x03FC, 0x4311)


def _words_match(data: bytes, pos: int, pattern: tuple[int, ...]) -> bool:
    return pos >= 0 and pos + len(pattern) * 2 <= len(data) and all(
        be16(data, pos + i * 2) == word for i, word in enumerate(pattern))


def relative_branch_destination(pos: int, opcode: int) -> int | None:
    """SH-2 signed PC-relative branch; BRA has a delay slot, BF does not."""
    if pos < 0 or pos & 1:
        return None
    if opcode & 0xF000 == 0xA000:
        delta = opcode & 0x0FFF
        if delta & 0x0800:
            delta -= 0x1000
        return pos + 4 + delta * 2
    if opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00):
        delta = opcode & 0xFF
        if delta & 0x80:
            delta -= 0x100
        return pos + 4 + delta * 2
    return None


def recognize_tail(data: bytes, offset: int, head: int) -> bool:
    if not _words_match(data, offset, TAIL):
        return False
    conditional_pos = offset + len(TAIL) * 2
    backward_pos = conditional_pos + 2
    delay_slot_pos = backward_pos + 2
    if delay_slot_pos + 2 > len(data):
        return False
    conditional = be16(data, conditional_pos)
    backward = be16(data, backward_pos)
    return (
        conditional & 0xFF00 == 0x8B00
        and backward & 0xF000 == 0xA000
        and be16(data, delay_slot_pos) == 0x0009
        and relative_branch_destination(conditional_pos, conditional) == delay_slot_pos + 2
        and relative_branch_destination(backward_pos, backward) == head
    )


def find_signed_descriptor_loops(data: bytes) -> list[dict]:
    """Recognize an initializer, loop head, exact signed tail and backedge."""
    results = []
    for head in range(0, len(data) - len(HEAD) * 2, 2):
        if not _words_match(data, head, HEAD):
            continue
        initializers = [
            pos for pos in range(max(0, head - 256), head - len(INIT) * 2 + 1, 2)
            if _words_match(data, pos, INIT)
        ]
        if not initializers:
            continue
        tails = [
            pos for pos in range(
                head + len(HEAD) * 2,
                min(len(data) - (len(TAIL) + 3) * 2, head + 1408) + 1, 2
            )
            if recognize_tail(data, pos, head)
        ]
        if not tails:
            continue
        tail = tails[0]
        results.append({
            "initializers": len(initializers),
            "head": head,
            "tail": tail,
            "mask_present": any(
                be16(data, pos) == 0xC93F
                for pos in range(head + len(HEAD) * 2, tail, 2)),
        })
    return results


def modeled_iterations(initial_byte: int) -> int:
    """Pure 8-bit decrement + signed-exit model, NOT emulator-observed timing."""
    if not (0 <= initial_byte <= 255):
        raise ValueError("initial_byte must fit in an unsigned byte")
    byte = initial_byte
    for iteration in range(1, 258):
        byte = (byte - 1) & 0xFF
        if byte & 0x80:
            return iteration
    raise AssertionError("no termination in bounded 8-bit model")


def summarize_loop_provenance(data: bytes) -> dict:
    matches = find_signed_descriptor_loops(data)
    return {
        "complete_counted_descriptor_loop_matches": len(matches),
        "loop_counter_initial_source": "u8(memory[R4+1])" if matches else None,
        "loop_counter_stack_field": "SP+56" if matches else None,
        "loop_counter_update": "u8(counter - 1)" if matches else None,
        "exit_test": "signed 8-bit counter < 0 after decrement" if matches else None,
        "backward_bra_targets_descriptor_processing_head": bool(matches),
        "backward_branch_has_nop_delay_slot": bool(matches),
        "loop_bodies_containing_and_0x3f": sum(m["mask_present"] for m in matches),
        "example_pure_math_iterations": ({
            "initial_0": modeled_iterations(0),
            "initial_1": modeled_iterations(1),
            "initial_127": modeled_iterations(127),
            "initial_128": modeled_iterations(128),
            "initial_255": modeled_iterations(255),
        } if matches else None),
        "limitations": [
            "The counter model ignores other writes, interrupts and unusual control-flow entries.",
            "Actual R4 provenance, initial values and reachable conditions are unknown.",
            "A mask in the loop body need not execute along every control-flow path.",
            "This is narrow static pattern analysis rather than complete SH-2 emulation.",
            "No original binary positions, game code or resource bytes are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage24_descriptor_loop_counter",
        "target_file": "0TH2.BIN",
        "analysis": summarize_loop_provenance(iso_file_payload(image)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
