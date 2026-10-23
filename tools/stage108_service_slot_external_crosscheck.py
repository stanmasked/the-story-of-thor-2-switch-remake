#!/usr/bin/env python3
"""Stage108: corroborate Saturn public BIOS service-slot classification.

Public-code only; takes a private ISO, private BIOS and private eight-hex-digit
slot-input file at runtime. Never prints source file names, offsets, BIOS bytes,
addresses or register contents. Crosschecking the documented service slot
is NOT evidence of a dynamic call, target identity or SH-2 R13 preservation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ORIGINAL_ISO_BYTES = 106954752
ORIGINAL_ISO_SHA256 = "25b0b2774d4621bd9f95a01fc5420ded37b481b61b3cdf515360d82b2cb7bb0d"
EU_BIOS_BYTES = 524288
EU_BIOS_SHA256 = "96e106f740ab448cf89f0dd49dfbac7fe5391cb6bd6e14ad5e3061c13330266f"
# This offset originates from publicly published SGL assembly, not the game's
# disassembly. It is a system ABI constant, not a private game address.
PUBLIC_SYS_CHGSCUIM_SLOT = 0x06000344
PUBLIC_ASSEMBLY_URL = "https://segaxtreme.net/threads/notes-on-interrupts-int_setmsk-int_setfunc.14464/"
PUBLIC_FUNCTION_SPEC_URL = "https://www.infochunk.com/saturn/segahtml_en/prgg/sysg/prog/hon/p02_11.htm"


class SafeInputError(ValueError):
    """An input failed privately; error text must never contain private data."""


def sha256_file(path: Path, size: int) -> bool:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest() == (ORIGINAL_ISO_SHA256 if size == ORIGINAL_ISO_BYTES else EU_BIOS_SHA256)


def safe_crosscheck(*, slot_text: str, iso_verified: bool, bios_verified: bool) -> dict:
    if type(slot_text) is not str or not re.fullmatch(r"[0-9a-fA-F]{8}", slot_text):
        raise SafeInputError("private_slot_input_invalid")
    if iso_verified is not True or bios_verified is not True:
        raise SafeInputError("source_identity_mismatch")
    if int(slot_text, 16) != PUBLIC_SYS_CHGSCUIM_SLOT:
        raise SafeInputError("documented_service_slot_mismatch")
    return {
        "schema_version": 1,
        "stage": "stage108_external_service_slot_crosscheck",
        "analysis": {
            "original_disc_sha256_verified": True,
            "european_bios_sha256_verified": True,
            "observed_private_slot_matches_independent_public_sgl_example": True,
            "documented_sys_chgscuim_andmask_ormask_signature_compatible": True,
            "system_slot_semantic_classification_independently_corroborated": True,
            "actual_runtime_callee_entry_observed": False,
            "actual_runtime_callee_return_observed": False,
            "actual_bios_callee_identity_independently_verified": False,
            "r13_before_after_runtime_pair_observed": False,
            "late_stage99_r13_writer_reached": False,
            "unconditional_r13_preservation_proven": False,
            "private_addresses_or_register_values_emitted": False,
            "raw_game_or_bios_data_emitted": False,
        },
        "public_references": [PUBLIC_ASSEMBLY_URL, PUBLIC_FUNCTION_SPEC_URL],
    }


def run_private(iso: Path, bios: Path, slot_file: Path) -> dict:
    try:
        # Reject symlinks, oversized or malformed text before opening.
        if slot_file.is_symlink() or not slot_file.is_file() or slot_file.stat().st_size not in (8, 9):
            raise SafeInputError("private_slot_input_invalid")
        slot_text = slot_file.read_text(encoding="ascii").rstrip("\n")
        return safe_crosscheck(
            slot_text=slot_text,
            iso_verified=sha256_file(iso, ORIGINAL_ISO_BYTES),
            bios_verified=sha256_file(bios, EU_BIOS_BYTES),
        )
    except (OSError, UnicodeError):
        raise SafeInputError("private_file_access_failed") from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso-private", type=Path, required=True)
    parser.add_argument("--bios-private", type=Path, required=True)
    parser.add_argument("--slot-private", type=Path, required=True)
    parser.add_argument("--aggregate-private", type=Path)
    args = parser.parse_args()
    try:
        result = run_private(args.iso_private, args.bios_private, args.slot_private)
    except SafeInputError as exc:
        print(json.dumps({"stage":"stage108_external_service_slot_crosscheck", "passed":False,"error_code":str(exc)}))
        raise SystemExit(2) from None
    output = json.dumps(result,indent=2,ensure_ascii=False) + "\n"
    if args.aggregate_private:
        args.aggregate_private.write_text(output,encoding="utf-8")
    else:
        print(output,end="")


if __name__ == "__main__":
    main()