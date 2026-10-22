#!/usr/bin/env python3
"""Stage72: verify the ID64 callback's signed-status producer ordering.

The original Saturn ISO stays local. The report contains aggregate booleans only,
not addresses, executable offsets, instruction bytes, or game assets. This is
static evidence, not a runtime trace.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from stage18_writer_guard_flow import iso_file_payload
from stage35_table_tail_link import branch_destination, movl_literal
from stage46_vdp1_submit_gate import find_submit_gates
from stage71_callback_dispatch_chain import (
    TARGET_CALLBACK_ID,
    _find_negative_writer_registrations,
    audit_dispatch_chain,
)

VDP1_VRAM_BASE = 0x25C00000


def audit_callback_body(
    data: bytes, callback_entry: int, status_address: int | None
) -> dict:
    if status_address is None or callback_entry < 0 or callback_entry + 0x36 > len(data):
        return {
            "callback_body_pattern_verified": False,
            "reads_gate_status_as_signed_byte": False,
            "negative_status_skips_producer_block": False,
            "nonnegative_status_calls_pre_status_helper": False,
            "helper_receives_vdp1_vram_base": False,
            "same_status_byte_written_after_helper": False,
            "callback_body_handshake_verified": False,
            "runtime_callback_invocation_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
        }

    status_read = movl_literal(data, callback_entry + 0x0C)
    source_pointer = movl_literal(data, callback_entry + 0x20)
    destination_base = movl_literal(data, callback_entry + 0x24)
    helper_pointer = movl_literal(data, callback_entry + 0x28)
    status_write = movl_literal(data, callback_entry + 0x30)
    branch = branch_destination(
        callback_entry + 0x12, int.from_bytes(
            data[callback_entry + 0x12:callback_entry + 0x14], "big"
        )
    )

    reads_status = (
        status_read is not None
        and status_read[1] == status_address
        and status_read[2] == 3
        and int.from_bytes(data[callback_entry + 0x0E:callback_entry + 0x10], "big") == 0x6230
        and int.from_bytes(data[callback_entry + 0x10:callback_entry + 0x12], "big") == 0x4215
    )
    negative_skips = (
        reads_status
        and branch == ("BF/S", callback_entry + 0x34)
        and int.from_bytes(data[callback_entry + 0x14:callback_entry + 0x16], "big") == 0xEE01
    )
    helper_before_store = (
        source_pointer is not None
        and source_pointer[2] == 5
        and destination_base is not None
        and destination_base[2] == 4
        and destination_base[1] == VDP1_VRAM_BASE
        and helper_pointer is not None
        and helper_pointer[2] == 3
        and int.from_bytes(data[callback_entry + 0x1C:callback_entry + 0x1E], "big") == 0x6621
        and int.from_bytes(data[callback_entry + 0x1E:callback_entry + 0x20], "big") == 0x4608
        and int.from_bytes(data[callback_entry + 0x22:callback_entry + 0x24], "big") == 0x4608
        and int.from_bytes(data[callback_entry + 0x26:callback_entry + 0x28], "big") == 0x4600
        and int.from_bytes(data[callback_entry + 0x2A:callback_entry + 0x2C], "big") == 0x430B
        and int.from_bytes(data[callback_entry + 0x2C:callback_entry + 0x2E], "big") == 0x7602
    )
    same_status_write = (
        status_write is not None
        and status_write[1] == status_address
        and status_write[2] == 3
        and int.from_bytes(data[callback_entry + 0x2E:callback_entry + 0x30], "big") == 0xE2FF
        and int.from_bytes(data[callback_entry + 0x32:callback_entry + 0x34], "big") == 0x2320
    )
    pattern = negative_skips and helper_before_store and same_status_write
    return {
        "callback_body_pattern_verified": pattern,
        "reads_gate_status_as_signed_byte": reads_status,
        "negative_status_skips_producer_block": negative_skips,
        "nonnegative_status_calls_pre_status_helper": helper_before_store,
        "helper_receives_vdp1_vram_base": bool(
            destination_base and destination_base[1] == VDP1_VRAM_BASE
        ),
        "same_status_byte_written_after_helper": same_status_write,
        "callback_body_handshake_verified": pattern,
        "runtime_callback_invocation_confirmed": False,
        "private_addresses_or_code_offsets_emitted": False,
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    gates = find_submit_gates(data)
    status_address = gates[0]["status_address"] if len(gates) == 1 else None
    dispatch = audit_dispatch_chain(data, status_address)
    registrations, negative_count = (
        _find_negative_writer_registrations(data, status_address)
        if status_address is not None else ([], 0)
    )
    id64 = [item for item in registrations if item["callback_id"] == TARGET_CALLBACK_ID]
    body = (
        audit_callback_body(data, id64[0]["callback_entry"], status_address)
        if len(id64) == 1 else audit_callback_body(data, -1, None)
    )
    chain_verified = (
        len(gates) == 1
        and dispatch["static_registration_to_indirect_call_chain_verified"]
        and len(id64) == 1
        and body["callback_body_handshake_verified"]
    )
    return {
        "schema_version": 1,
        "stage": "stage72_status_producer_order",
        "target_file": "0TH2.BIN",
        "analysis": {
            "unique_submit_gate_signature": len(gates) == 1,
            "negative_status_writer_candidates": negative_count,
            "callback_id_64_registration_sites": len(id64),
            **body,
            "callback_to_gate_status_handshake_statically_verified": chain_verified,
            "same_frame_submit_timing_confirmed": False,
            "runtime_callback_invocation_confirmed": False,
            "private_addresses_or_code_offsets_emitted": False,
        },
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
        print(rendered, end="")


if __name__ == "__main__":
    main()
