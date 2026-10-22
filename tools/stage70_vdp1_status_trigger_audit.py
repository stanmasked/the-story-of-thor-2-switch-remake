#!/usr/bin/env python3
"""Stage70: bounded SH-2 audit of the VDP1 status byte and trigger-register paths.

The original Saturn ISO stays private. Output contains aggregate counts only:
no executable offsets, global addresses, literal values other than named PTMR
mode classes, or original instruction bytes. This is static evidence, not a
runtime trace; branch-following and indirect-pointer coverage are incomplete.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage35_table_tail_link import movl_literal
from stage46_vdp1_submit_gate import find_submit_gates

CODE_LOAD_ADDRESS = 0x06004000
VDP1_REGISTER_BASE = 0x25D00000
VDP1_REGISTER_OFFSETS = {
    0x00: "TVMR",
    0x02: "FBCR",
    0x04: "PTMR",
    0x06: "EWDR",
    0x08: "EWLR",
    0x0A: "EWRR",
    0x0C: "ENDR",
    0x10: "EDSR",
    0x12: "LOPR",
    0x14: "COPR",
    0x16: "MODR",
}


def _signed8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _is_control_transfer(opcode: int) -> bool:
    return (
        opcode >> 12 in (0xA, 0xB)
        or opcode == 0x000B
        or opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00)
        or opcode & 0xF0FF in (0x400B, 0x402B)
    )


def _writes_register(opcode: int, register: int) -> bool:
    top = opcode >> 12
    n = (opcode >> 8) & 0xF
    m = (opcode >> 4) & 0xF
    low = opcode & 0xF

    if top in (0x7, 0x9, 0xD, 0xE) and n == register:
        return True
    if top == 0x6 and n == register:
        return True
    if top == 0x3 and n == register and low in (0x4, 0x8, 0xA, 0xB, 0xC):
        return True
    if top == 0x4 and n == register and low in (0x0, 0x1, 0x8, 0x9):
        return True
    if top == 0x0 and n == register and low in (0xC, 0xD, 0xE):
        return True
    if top == 0x8 and opcode & 0xFF00 in (0x8400, 0x8500) and register == 0:
        return True
    if top == 0xC and register == 0 and opcode & 0xFF00 in (
        0xC900, 0xCA00, 0xCB00
    ):
        return True
    # Predecrement stores update their address register.
    if top == 0x2 and n == register and low in (0x4, 0x5, 0x6):
        return True
    return False


def _byte_store_source(opcode: int, pointer_register: int) -> int | None:
    """Return source register for an exact byte store through a known pointer."""
    # MOV.B Rm,@Rn
    if (opcode >> 12) == 0x2 and opcode & 0xF == 0:
        if (opcode >> 8) & 0xF == pointer_register:
            return (opcode >> 4) & 0xF
    # MOV.B R0,@(0,Rn); nonzero displacement is not the exact global byte.
    if opcode & 0xFF00 == 0x8000:
        if (opcode >> 4) & 0xF == pointer_register and opcode & 0xF == 0:
            return 0
    return None


def _constant_before_store(
    data: bytes, position: int, register: int, max_back: int = 12
) -> int | None:
    """Recognize a nearby MOV #imm,Rn definition; otherwise stay conservative."""
    for step in range(1, max_back + 1):
        prior = position - 2 * step
        if prior < 0:
            break
        opcode = be16(data, prior)
        top = opcode >> 12
        n = (opcode >> 8) & 0xF
        m = (opcode >> 4) & 0xF
        low = opcode & 0xF
        if top == 0xE and n == register:
            return _signed8(opcode & 0xFF)
        if top == 0x6 and low == 0x3 and n == register:
            if m == register:
                return None
            return _constant_before_store(data, prior, m, max_back=step - 1)
        if _is_control_transfer(opcode):
            break
        if _writes_register(opcode, register):
            break
    return None


def scan_status_writes(
    data: bytes, status_address: int, max_lookahead: int = 20
) -> tuple[list[tuple[int, int]], list[dict]]:
    """Find bounded linear byte-store candidates through PC-literal status pointers.

    A branch/call delay-slot store is included. This deliberately does not claim
    full control-flow dominance or prove that a candidate wakes the submit gate.
    """
    pointer_loads = []
    for position in range(0, len(data) - 5, 2):
        literal = movl_literal(data, position)
        if literal is not None and literal[1] == status_address:
            pointer_loads.append((position, literal[2]))

    events_by_store = {}
    for load_position, pointer_register in pointer_loads:
        for step in range(1, max_lookahead + 1):
            position = load_position + 2 * step
            if position + 2 > len(data):
                break
            opcode = be16(data, position)
            source_register = _byte_store_source(opcode, pointer_register)
            if source_register is not None:
                value = _constant_before_store(data, position, source_register)
                kind = (
                    "negative" if value is not None and value < 0
                    else "zero" if value == 0
                    else "one" if value == 1
                    else "other"
                )
                events_by_store[position] = {
                    "store_position": position,
                    "pointer_load_position": load_position,
                    "source_register": source_register,
                    "constant_value": value,
                    "constant_class": kind,
                }
                break

            if _is_control_transfer(opcode):
                # SH-2 executes one delay-slot instruction before transfer.
                delay_position = position + 2
                if delay_position + 2 <= len(data):
                    delay_opcode = be16(data, delay_position)
                    delay_source = _byte_store_source(
                        delay_opcode, pointer_register
                    )
                    if delay_source is not None:
                        value = _constant_before_store(
                            data, delay_position, delay_source
                        )
                        kind = (
                            "negative" if value is not None and value < 0
                            else "zero" if value == 0
                            else "one" if value == 1
                            else "other"
                        )
                        events_by_store[delay_position] = {
                            "store_position": delay_position,
                            "pointer_load_position": load_position,
                            "source_register": delay_source,
                            "constant_value": value,
                            "constant_class": kind,
                        }
                break
            if _writes_register(opcode, pointer_register):
                break

    return pointer_loads, [
        events_by_store[position] for position in sorted(events_by_store)
    ]


def _matches_callback_table_dispatcher(data: bytes, entry: int) -> bool:
    """Match the narrow dispatcher pattern that stores R5 at table_base + id*4."""
    if entry < 0 or entry + 18 > len(data):
        return False
    first = be16(data, entry)
    second = be16(data, entry + 2)
    fourth = be16(data, entry + 4)
    sixth = be16(data, entry + 6)
    eighth = be16(data, entry + 8)
    tenth = be16(data, entry + 10)
    return (
        first & 0xF000 == 0xD000
        and (first >> 8) & 0xF == 0
        and second == 0x7FF8
        and fourth & 0xF000 == 0xD000
        and (fourth >> 8) & 0xF == 2
        and sixth == 0x6343
        and eighth & 0xF000 == 0xD000
        and (eighth >> 8) & 0xF == 1
        and tenth == 0x4308
        and be16(data, entry + 12) == 0x2F42
        and be16(data, entry + 14) == 0x1F31
        and be16(data, entry + 16) == 0x0356
    )


def find_negative_writer_callback_ids(
    data: bytes, status_address: int | None
) -> list[int]:
    """Find registration-like calls for functions with a nearby explicit -1 store.

    The recognized dispatcher writes its R5 callback argument into a table slot
    indexed by R4*4. A match establishes static registration, not callback
    invocation or a runtime causal link to the submit gate.
    """
    if status_address is None:
        return []
    _, status_writes = scan_status_writes(data, status_address)
    negative_writes = [
        event for event in status_writes
        if event["constant_class"] == "negative"
    ]
    registrations = []
    for position in range(0, len(data) - 8, 2):
        callback_literal = movl_literal(data, position)
        if callback_literal is None or callback_literal[2] != 5:
            continue
        callback_address = callback_literal[1]
        if not (
            CODE_LOAD_ADDRESS <= callback_address < CODE_LOAD_ADDRESS + len(data)
        ):
            continue
        callback_entry = callback_address - CODE_LOAD_ADDRESS
        if not any(
            callback_entry <= event["pointer_load_position"] < callback_entry + 0x100
            and callback_entry <= event["store_position"] < callback_entry + 0x100
            for event in negative_writes
        ):
            continue

        dispatcher_literal = movl_literal(data, position + 2)
        if dispatcher_literal is None or dispatcher_literal[2] != 2:
            continue
        if be16(data, position + 4) != 0x420B:
            continue
        delay_slot = be16(data, position + 6)
        if delay_slot & 0xFF00 != 0xE400:
            continue
        dispatcher_address = dispatcher_literal[1]
        if not (
            CODE_LOAD_ADDRESS <= dispatcher_address < CODE_LOAD_ADDRESS + len(data)
        ):
            continue
        dispatcher_entry = dispatcher_address - CODE_LOAD_ADDRESS
        if not _matches_callback_table_dispatcher(data, dispatcher_entry):
            continue
        registrations.append(_signed8(delay_slot & 0xFF))
    return sorted(set(registrations))


def _word_store(opcode: int, registers: dict[int, int | None]):
    """Decode common SH-2 word stores and return (effective address, value)."""
    top = opcode >> 12
    n = (opcode >> 8) & 0xF
    m = (opcode >> 4) & 0xF
    low = opcode & 0xF

    # MOV.W Rm,@Rn
    if top == 0x2 and low == 0x1:
        return registers.get(n), registers.get(m)
    # MOV.W R0,@(disp,Rn)
    if opcode & 0xFF00 == 0x8100:
        base = registers.get((opcode >> 4) & 0xF)
        displacement = (opcode & 0xF) * 2
        address = base + displacement if base is not None else None
        return address, registers.get(0)
    # MOV.W Rm,@(R0,Rn)
    if top == 0x0 and low == 0x5:
        base = registers.get(n)
        index = registers.get(0)
        address = base + index if base is not None and index is not None else None
        return address, registers.get(m)
    return None


def _update_known_registers(
    data: bytes, position: int, opcode: int, registers: dict[int, int | None]
) -> None:
    top = opcode >> 12
    n = (opcode >> 8) & 0xF
    m = (opcode >> 4) & 0xF
    low = opcode & 0xF

    if top == 0xE:
        registers[n] = _signed8(opcode & 0xFF)
        return
    if top == 0x7:
        current = registers.get(n)
        registers[n] = current + _signed8(opcode & 0xFF) if current is not None else None
        return
    if top == 0xD:
        literal = movl_literal(data, position)
        registers[n] = literal[1] if literal is not None else None
        return
    if top == 0x9:
        target = position + 4 + (opcode & 0xFF) * 2
        value = int.from_bytes(data[target:target + 2], "big") if target + 2 <= len(data) else None
        if value is not None and value & 0x8000:
            value -= 0x10000
        registers[n] = value
        return
    if top == 0x6:
        if low == 0x3:
            registers[n] = registers.get(m)
        elif low == 0xD:
            value = registers.get(m)
            registers[n] = value & 0xFFFF if value is not None else None
        elif low == 0xF:
            value = registers.get(m)
            registers[n] = (
                value - 0x10000 if value is not None and value & 0x8000
                else value & 0xFFFF if value is not None
                else None
            )
        elif low in (0x4, 0x5, 0x6):
            registers[n] = None
            current = registers.get(m)
            if current is not None:
                registers[m] = current + {0x4: 1, 0x5: 2, 0x6: 4}[low]
        elif low in (0x0, 0x1, 0x2, 0xC, 0xE):
            registers[n] = None
        else:
            registers[n] = None
        return
    if top == 0x3:
        if low == 0xC:
            left, right = registers.get(n), registers.get(m)
            registers[n] = left + right if left is not None and right is not None else None
        elif low in (0x4, 0x8, 0xA, 0xB):
            registers[n] = None
        return
    if top == 0x4:
        if low in (0x0, 0x1, 0x8, 0x9):
            value = registers.get(n)
            if value is None:
                registers[n] = None
            elif low == 0x0:
                registers[n] = value * 2
            elif low == 0x1:
                registers[n] = value // 2
            elif low == 0x8:
                registers[n] = value * 4
            else:
                registers[n] = value // 4
        elif low not in (0x2, 0x6, 0xA, 0xB):
            registers[n] = None
        return
    if top == 0x5:
        registers[n] = None
        return
    if top == 0x0:
        if low in (0xC, 0xD, 0xE, 0x1, 0x2):
            registers[n] = None
        return
    if top == 0x8:
        if opcode & 0xFF00 in (0x8400, 0x8500):
            registers[0] = None
        return
    if top == 0xC and opcode & 0xFF00 in (0xC900, 0xCA00, 0xCB00):
        value = registers.get(0)
        immediate = opcode & 0xFF
        if value is None:
            registers[0] = None
        elif opcode & 0xFF00 == 0xC900:
            registers[0] = value & immediate
        elif opcode & 0xFF00 == 0xCA00:
            registers[0] = value ^ immediate
        else:
            registers[0] = value | immediate
        return
    if top == 0x2 and low in (0x4, 0x5, 0x6):
        current = registers.get(n)
        if current is not None:
            registers[n] = current - {0x4: 1, 0x5: 2, 0x6: 4}[low]
        return
    if top == 0xF:
        registers[n] = None


def _trace_register_stores(
    data: bytes, load_position: int, pointer_register: int,
    pointer_address: int, max_steps: int = 40
) -> list[dict]:
    registers: dict[int, int | None] = {pointer_register: pointer_address}
    events = []
    position = load_position + 2
    for _ in range(max_steps):
        if position + 2 > len(data):
            break
        opcode = be16(data, position)
        store = _word_store(opcode, registers)
        if store is not None:
            address, value = store
            if address is not None and address - VDP1_REGISTER_BASE in VDP1_REGISTER_OFFSETS:
                events.append({
                    "store_position": position,
                    "register_offset": address - VDP1_REGISTER_BASE,
                    "value": value,
                })

        if _is_control_transfer(opcode):
            delay_position = position + 2
            if delay_position + 2 <= len(data):
                delay_store = _word_store(be16(data, delay_position), registers)
                if delay_store is not None:
                    address, value = delay_store
                    if address is not None and address - VDP1_REGISTER_BASE in VDP1_REGISTER_OFFSETS:
                        events.append({
                            "store_position": delay_position,
                            "register_offset": address - VDP1_REGISTER_BASE,
                            "value": value,
                        })
            break

        _update_known_registers(data, position, opcode, registers)
        if registers.get(pointer_register) is None:
            break
        position += 2
    return events


def scan_vdp1_register_writes(data: bytes) -> list[dict]:
    """Follow bounded straight-line paths from PC-literal VDP1 register pointers."""
    events_by_position = {}
    allowed = {
        VDP1_REGISTER_BASE + offset for offset in VDP1_REGISTER_OFFSETS
    }
    for position in range(0, len(data) - 5, 2):
        literal = movl_literal(data, position)
        if literal is None or literal[1] not in allowed:
            continue
        for event in _trace_register_stores(
            data, position, literal[2], literal[1]
        ):
            events_by_position[event["store_position"]] = event
    return [events_by_position[position] for position in sorted(events_by_position)]


def summarize(
    data: bytes, status_address: int | None, submit_gate_count: int
) -> dict:
    if status_address is None:
        status_loads, status_writes = [], []
    else:
        status_loads, status_writes = scan_status_writes(data, status_address)
    write_classes = Counter(event["constant_class"] for event in status_writes)
    callback_ids = find_negative_writer_callback_ids(data, status_address)
    hardware_writes = scan_vdp1_register_writes(data)
    register_counts = Counter(
        VDP1_REGISTER_OFFSETS[event["register_offset"]]
        for event in hardware_writes
    )
    ptmr_writes = [
        event for event in hardware_writes
        if event["register_offset"] == 0x04
    ]
    return {
        "submit_gate_signatures": submit_gate_count,
        "status_pointer_pc_literal_loads": len(status_loads),
        "status_byte_store_candidates": len(status_writes),
        "status_constant_minus_one_store_candidates": write_classes["negative"],
        "status_constant_zero_store_candidates": write_classes["zero"],
        "status_constant_one_store_candidates": write_classes["one"],
        "status_dynamic_or_unresolved_store_candidates": write_classes["other"],
        "negative_status_writer_callback_registration_candidates": len(callback_ids),
        "negative_status_writer_callback_registration_ids": callback_ids,
        "negative_status_writer_runtime_invocation_confirmed": False,
        "negative_status_writer_wakes_submit_gate_proven": False,
        "recognized_vdp1_register_store_candidates": len(hardware_writes),
        "recognized_vdp1_register_store_candidates_by_name": dict(sorted(register_counts.items())),
        "recognized_ptmr_store_candidates": len(ptmr_writes),
        "ptmr_automatic_frame_mode_value_2_candidates": sum(
            event["value"] == 2 for event in ptmr_writes
        ),
        "ptmr_manual_start_value_1_candidates": sum(
            event["value"] == 1 for event in ptmr_writes
        ),
        "ptmr_pointer_trace_is_exhaustive": False,
        "confirmed_runtime_hardware_execution": False,
        "private_addresses_or_code_offsets_emitted": False,
        "interpretation": (
            "One bounded PC-literal pointer path writes value 2 to PTMR, which "
            "selects automatic drawing at frame start. The scan finds a direct "
            "constant -1 store to the shared status byte and a registration-like "
            "call passing that writer to a dispatcher under callback ID 64. "
            "Static registration does not prove runtime invocation or prove that "
            "the callback wakes the submit gate. Other status writes and "
            "framebuffer-control paths remain only statically correlated."
        ),
    }


def analyze(image: Path) -> dict:
    data = iso_file_payload(image)
    gates = find_submit_gates(data)
    status_address = gates[0]["status_address"] if len(gates) == 1 else None
    return {
        "schema_version": 1,
        "stage": "stage70_vdp1_status_trigger_audit",
        "target_file": "0TH2.BIN",
        "analysis": summarize(data, status_address, len(gates)),
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
