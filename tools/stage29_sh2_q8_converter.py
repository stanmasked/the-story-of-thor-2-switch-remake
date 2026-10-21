#!/usr/bin/env python3
"""Stage29: resolve the shared SH-2 fixed-point scaling helper.

Only a fixed five-instruction synthetic opcode signature and aggregate metadata
are public. Never export original game bytes, addresses or protected assets.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage25_r4_provenance_probe import find_input_preservation_paths
from stage28_helper_nonzero_fields import CALL_OFFSETS, verify_nonzero_fields

# Inferred loader base, validated during Stage15. Not an original binary offset.
CODE_LOAD_BASE = 0x06004000
SCALE_SIGNATURE = (
    0x254F,  # MULS.W R4,R5, 32-bit signed product -> MACL
    0x001A,  # STS MACL,R0
    0x4019,  # SHLR8 R0 (logical 8-bit shift)
    0x000B,  # RTS
    0x600F,  # EXTS.W R0,R0, executes in RTS delay slot
)


def signed16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def model_signed_q8_mul(arg: int, scale: int) -> int:
    """Exact register-width semantics of the validated SH-2 instruction path.

    MULS.W uses the low 16 bits of both registers signed. SHLR8 zero-fills
    the 32-bit product in R0; EXTS.W preserves only its low signed 16 bits.
    """
    product = signed16(arg) * signed16(scale)
    shifted = (product & 0xFFFFFFFF) >> 8
    return signed16(shifted)


def movl_pc_literal(data: bytes, position: int, dest_reg: int = 13) -> tuple[int, int] | None:
    """MOV.L @(disp,PC),Rn, PC+4 rounded down to a four-byte boundary."""
    if position < 0 or position & 1 or position + 2 > len(data):
        return None
    opcode = be16(data, position)
    if opcode & 0xFF00 != 0xD000 | dest_reg << 8:
        return None
    slot = ((position + 4) & ~3) + (opcode & 0xFF) * 4
    if slot + 4 > len(data):
        return None
    return slot, int.from_bytes(data[slot:slot + 4], "big")


def inspect_converter(data: bytes, helper_entry: int) -> dict | None:
    """Link all six verified JSR sites through R13 to a short SH-2 routine."""
    if verify_nonzero_fields(data, helper_entry) is None:
        return None
    literal = movl_pc_literal(data, helper_entry + 0x90, 13)
    if literal is None:
        return None
    _, runtime_address = literal
    converter = runtime_address - CODE_LOAD_BASE
    if converter < 0 or converter & 1 or converter + len(SCALE_SIGNATURE) * 2 > len(data):
        return None
    if any(be16(data, converter + i * 2) != opcode
           for i, opcode in enumerate(SCALE_SIGNATURE)):
        return None

    # Independently verify signed-word scale loading into R12, then R5, for
    # the two groups identified in Stage28.
    if any(be16(data, helper_entry + off) != code for off, code in (
        (0xAE, 0xE058), (0xB0, 0x0CED), (0xB6, 0x65C3),
        (0xD2, 0xE05A), (0xD6, 0x0CED), (0xDC, 0x65C3),
    )):
        return None

    if any(be16(data, helper_entry + off) != 0x4D0B for off in CALL_OFFSETS):
        return None
    return {
        "helper_entry": helper_entry,
        "converter_offset": converter,
        "call_sites": len(CALL_OFFSETS),
        "scale_sources": (88, 90),
        "returns_through_rts_delay_slot": True,
    }


def summarize_converter(data: bytes) -> dict:
    targets = {p["target"] for p in find_input_preservation_paths(data)}
    matches = [m for target in targets if (m := inspect_converter(data, target)) is not None]
    return {
        "stage28_helper_targets_examined": len(targets),
        "helpers_with_resolved_q8_converter": len(matches),
        "linked_indirect_conversion_call_sites": sum(m["call_sites"] for m in matches),
        "distinct_resolved_converter_targets": len({m["converter_offset"] for m in matches}),
        "operation": "signed_16x16_to_32_multiply_then_shift_right_8_and_signed16" if matches else None,
        "scale_input_field_offsets": list(matches[0]["scale_sources"]) if matches else [],
        "scale_identity_sentinel": 256 if matches else None,
        "identity_in_q8": model_signed_q8_mul(-321, 256) == -321 if matches else None,
        "return_sign_extension_in_RTS_delay_slot": bool(matches),
        "synthetic_examples": {
            "positive_times_one": model_signed_q8_mul(125, 256),
            "negative_times_one": model_signed_q8_mul(-125, 256),
            "positive_times_half": model_signed_q8_mul(125, 128),
            "negative_times_half": model_signed_q8_mul(-125, 128),
        } if matches else {},
        "interpretation": (
            "The shared R13 function multiplies the low signed 16 bits of R4 "
            "and R5, transfers MACL to R0, shifts right 8, then sign-extends "
            "the low 16 bits in the RTS delay slot. Signed Q8.8 fixed-point "
            "scaling explains why a scale of 256 permits skipping the call."
        ) if matches else "The complete shared converter signature was not verified.",
        "limitations": [
            "The game-level meanings of scaled fields and nested resource layouts remain unknown.",
            "The six JSR sites are static; their actual execution is conditional.",
            "This is not a renderer, texture decoder or Saturn emulator execution.",
            "Original executable offsets, bytes and game assets are never exported.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage29_sh2_q8_converter",
        "target_file": "0TH2.BIN",
        "analysis": summarize_converter(iso_file_payload(image)),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("image", type=Path)
    p.add_argument("-o", "--output", type=Path)
    args = p.parse_args()
    result = json.dumps(analyze(args.image), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result)


if __name__ == "__main__":
    main()
