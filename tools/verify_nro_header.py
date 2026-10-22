#!/usr/bin/env python3
"""Validate the fixed NRO header before publishing a Switch build artifact.

This intentionally checks only the public container header. It does not run
or certify the binary, and it never reads or embeds original game assets.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

NRO_HEADER_OFFSET = 0x10
NRO_HEADER_SIZE = 0x70
NRO_MIN_SIZE = NRO_HEADER_OFFSET + NRO_HEADER_SIZE
NRO_MAGIC = b"NRO0"


def validate_nro_bytes(data: bytes) -> dict[str, int | str]:
    if len(data) < NRO_MIN_SIZE:
        raise ValueError(
            f"file is too short for the NRO header: {len(data)} < {NRO_MIN_SIZE}"
        )
    magic = data[NRO_HEADER_OFFSET:NRO_HEADER_OFFSET + 4]
    if magic != NRO_MAGIC:
        raise ValueError(f"invalid NRO magic at 0x{NRO_HEADER_OFFSET:X}: {magic!r}")

    version, declared_size, flags = struct.unpack_from(
        "<III", data, NRO_HEADER_OFFSET + 4
    )
    if declared_size < NRO_MIN_SIZE:
        raise ValueError(
            f"declared NRO size is smaller than its header: {declared_size}"
        )
    if declared_size > len(data):
        raise ValueError(
            f"declared NRO size {declared_size} exceeds file length {len(data)}"
        )
    return {
        "magic": magic.decode("ascii"),
        "version": version,
        "declared_size": declared_size,
        "file_size": len(data),
        "flags": flags,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nro", type=Path, help="path to the built .nro file")
    args = parser.parse_args(argv)
    try:
        result = validate_nro_bytes(args.nro.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"NRO validation failed: {exc}", file=sys.stderr)
        return 1
    print(
        "NRO header PASS: "
        f"magic={result['magic']} version={result['version']} "
        f"declared_size={result['declared_size']} "
        f"file_size={result['file_size']} flags={result['flags']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
