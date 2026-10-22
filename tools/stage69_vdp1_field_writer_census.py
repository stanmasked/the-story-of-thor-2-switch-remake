#!/usr/bin/env python3
"""Stage69: bounded static census of writes to VDP1 producer object fields.

The input Saturn ISO is read locally. Output is aggregate-only: no instruction
offsets, raw machine bytes, source addresses, or original assets are emitted.
The recognizer is deliberately conservative and does not prove runtime writes.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from stage18_writer_guard_flow import be16, iso_file_payload
from stage20_vdp1_product_flow import matching_product_preludes

# Object-field hypotheses established by the preceding bounded SH-2 analysis.
# Expected store widths help reject an offset match with the wrong operation.
FIELDS = {
    0x007A: ("destination_slot", 2),
    0x0098: ("source_base", 4),
    0x00AC: ("metadata_pointer", 4),
}
FIELD_NAMES = tuple(name for name, _width in FIELDS.values())


def movw_target(pos: int, opcode: int, size: int) -> int | None:
    if pos < 0 or pos & 1 or pos + 2 > size or opcode & 0xF000 != 0x9000:
        return None
    target = pos + 4 + (opcode & 0xFF) * 2
    return target if 0 <= target and target + 2 <= size else None


def movl_target(pos: int, opcode: int, size: int) -> int | None:
    if pos < 0 or pos & 1 or pos + 2 > size or opcode & 0xF000 != 0xD000:
        return None
    target = ((pos + 4) & ~3) + (opcode & 0xFF) * 4
    return target if target >= 0 and target + 4 <= size else None


def is_control_flow(opcode: int) -> bool:
    if opcode & 0xF000 in (0xA000, 0xB000):
        return True
    if opcode & 0xFF00 in (0x8900, 0x8B00, 0x8D00, 0x8F00):
        return True
    if opcode in (0x000B, 0x002B):
        return True
    return opcode & 0xF0FF in (0x400B, 0x402B, 0x0003, 0x0023)


def writes_register(opcode: int, register: int) -> bool:
    """Conservative SH-2 register-write classifier for bounded back-scans."""
    top = opcode & 0xF000
    n = (opcode >> 8) & 0x0F
    low = opcode & 0x0F
    if top in (0x5000, 0x6000, 0x7000, 0x9000, 0xD000, 0xE000):
        return n == register
    if top == 0x3000:
        if low in (0, 2, 3, 6, 7):  # compare instructions do not write Rn
            return False
        return n == register
    if top == 0x2000:
        if low in (0, 1, 2, 4, 5, 6, 7, 12):
            return False
        return n == register and low in (8, 9, 10, 11, 13)
    if top == 0x0000:
        return n == register and low in (0xC, 0xD, 0xE)
    if top == 0x8000:
        return register == 0 and ((opcode >> 8) & 0x0F) in (4, 5)
    if top == 0xC000:
        sub = (opcode >> 8) & 0x0F
        return register == 0 and sub in (9, 10, 11)
    if top == 0x4000:
        # Conservatively treat most single-register operations as clobbers.
        low8 = opcode & 0xFF
        no_write = {0x0A, 0x0B, 0x0E, 0x11, 0x15, 0x1A, 0x1E, 0x2A, 0x2B}
        return n == register and low8 not in no_write
    return False


def _constant_definition_r0(data: bytes, pos: int, opcode: int) -> tuple[int | None, str | None]:
    """Resolve only a direct PC-relative literal or MOV #imm,R0 definition."""
    if opcode & 0xF000 == 0x9000 and ((opcode >> 8) & 0x0F) == 0:
        target = movw_target(pos, opcode, len(data))
        return (be16(data, target), "pc_word_literal") if target is not None else (None, None)
    if opcode & 0xF000 == 0xD000 and ((opcode >> 8) & 0x0F) == 0:
        target = movl_target(pos, opcode, len(data))
        if target is not None:
            return int.from_bytes(data[target:target + 4], "big"), "pc_long_literal"
        return None, None
    if opcode & 0xF000 == 0xE000 and ((opcode >> 8) & 0x0F) == 0:
        value = opcode & 0xFF
        if value & 0x80:
            value -= 0x100
        return value, "immediate"
    return None, None


def resolve_r0_field_offset(data: bytes, store_pos: int,
                            max_back_instructions: int = 40) -> tuple[int | None, str]:
    """Resolve a small field offset only when no R0 write/branch intervenes."""
    stop = max(-1, store_pos - max_back_instructions * 2 - 1)
    for pos in range(store_pos - 2, stop, -2):
        opcode = be16(data, pos)
        value, source = _constant_definition_r0(data, pos, opcode)
        if source is not None:
            return value, source
        if is_control_flow(opcode) or writes_register(opcode, 0):
            return None, "clobbered_or_control_flow"
    return None, "unknown"


def classify_source_definition(data: bytes, store_pos: int, source_reg: int,
                               max_back_instructions: int = 16) -> str:
    """Classify the closest recognized source-register definition, not its value."""
    stop = max(-1, store_pos - max_back_instructions * 2 - 1)
    for pos in range(store_pos - 2, stop, -2):
        opcode = be16(data, pos)
        if is_control_flow(opcode):
            return "unknown_across_control_flow"
        if not writes_register(opcode, source_reg):
            continue
        top = opcode & 0xF000
        n = (opcode >> 8) & 0x0F
        low = opcode & 0x0F
        if top == 0xE000 and n == source_reg:
            return "immediate"
        if top in (0x9000, 0xD000) and n == source_reg:
            return "pc_literal"
        if top == 0x6000 and low == 3:
            return "register_copy"
        if top in (0x5000, 0x6000, 0x0000, 0x8000):
            return "memory_or_indexed_load"
        if top in (0x7000, 0x3000, 0x2000, 0x4000):
            return "arithmetic_or_logic"
        return "other_write"
    return "unknown"


def field_write_candidates(data: bytes) -> list[dict]:
    """Return internal syntactic candidates; positions are never in the report."""
    stores = {0x0004: 1, 0x0005: 2, 0x0006: 4}
    candidates = []
    for pos in range(0, len(data) - 1, 2):
        opcode = be16(data, pos)
        form = opcode & 0xF00F
        if form not in stores:
            continue
        width = stores[form]
        field_offset, offset_source = resolve_r0_field_offset(data, pos)
        if field_offset not in FIELDS:
            continue
        field_name, expected_width = FIELDS[field_offset]
        if width != expected_width:
            continue
        candidates.append({
            "position": pos,
            "field": field_name,
            "base_register": (opcode >> 8) & 0x0F,
            "source_register": (opcode >> 4) & 0x0F,
            "offset_source": offset_source,
            "value_source_kind": classify_source_definition(
                data, pos, (opcode >> 4) & 0x0F),
        })
    return candidates


def _is_zero_count_test(opcode: int) -> bool:
    if opcode == 0x2228:  # TST R2,R2
        return True
    if opcode in (0x4211, 0x4215):  # CMP/PZ R2 or CMP/PL R2
        return True
    # R6 is initialized to zero in the recognized producer function. Treat
    # compares involving R2 and R6 as possible count tests, not as proof.
    if opcode & 0xF000 == 0x3000 and (opcode & 0x0F) in (0, 2, 3, 6, 7):
        n, m = (opcode >> 8) & 0x0F, (opcode >> 4) & 0x0F
        return 2 in (n, m) and 6 in (n, m)
    return False


def metadata_pointer_sentinel_guard_candidates(data: bytes) -> int:
    """Match a bounded 0xFFFF table-sentinel check leading to the +0xAC store.

    This is a syntactic candidate, not proof of a reachable runtime guard.
    """
    matches = 0
    for pos in range(0, len(data) - 18, 2):
        first = be16(data, pos)
        if first & 0xF000 != 0xD000 or ((first >> 8) & 0x0F) != 0:
            continue
        first_literal = movl_target(pos, first, len(data))
        if first_literal is None or int.from_bytes(
            data[first_literal:first_literal + 4], "big"
        ) != 0x20000002:
            continue
        if be16(data, pos + 2) != 0x4600:  # SHLL R6
            continue
        second = be16(data, pos + 4)
        if second & 0xF000 != 0xD000 or ((second >> 8) & 0x0F) != 2:
            continue
        second_literal = movl_target(pos + 4, second, len(data))
        if second_literal is None or int.from_bytes(
            data[second_literal:second_literal + 4], "big"
        ) != 0x0000FFFF:
            continue
        if [be16(data, pos + delta) for delta in (6, 8, 10, 12, 14)] != [
            0x6563, 0x354C, 0x055D, 0x635D, 0x3320
        ]:
            continue
        branch_pos = pos + 16
        branch = be16(data, branch_pos)
        if branch & 0xFF00 != 0x8B00:  # BF: non-sentinel path
            continue
        target = branch_pos + 4 + (branch & 0xFF if branch & 0x80 == 0
                                   else (branch & 0xFF) - 0x100) * 2
        if target < 0 or target + 2 > len(data):
            continue
        field_load = be16(data, target)
        if field_load & 0xF000 != 0x9000 or ((field_load >> 8) & 0x0F) != 0:
            continue
        field_literal = movw_target(target, field_load, len(data))
        if field_literal is not None and be16(data, field_literal) == 0x00AC:
            matches += 1
    return matches


def count_derivation_window(data: bytes, start: int,
                            lookahead_bytes: int = 96) -> dict | None:
    """Recognize MOV R4,R2 -> three SHAR R2 -> MOV.W R2,@R3.

    Only this bounded count-production window is inspected. A zero-test hit
    means a candidate test exists; absence does not prove all callers safe.
    """
    end = min(len(data), start + lookahead_bytes)
    copy_count = None
    store_count = None
    for pos in range(start, end - 1, 2):
        if be16(data, pos) == 0x6243:  # MOV R4,R2
            copy_count = pos
            break
    if copy_count is None:
        return None
    for pos in range(copy_count + 2, end - 1, 2):
        if be16(data, pos) == 0x2321:  # MOV.W R2,@R3
            store_count = pos
            break
    if store_count is None:
        return None
    window = [be16(data, pos) for pos in range(copy_count + 2, store_count, 2)]
    if window.count(0x4221) != 3:  # three arithmetic right shifts, divide by eight
        return None
    return {
        "recognized": True,
        "explicit_zero_test_candidate": any(_is_zero_count_test(op) for op in window),
    }


def summarize(data: bytes) -> dict:
    candidates = field_write_candidates(data)
    write_counts = Counter(item["field"] for item in candidates)
    base_counts: dict[str, Counter] = {name: Counter() for name in FIELD_NAMES}
    source_counts: dict[str, Counter] = {name: Counter() for name in FIELD_NAMES}
    offset_counts: dict[str, Counter] = {name: Counter() for name in FIELD_NAMES}
    for item in candidates:
        field = item["field"]
        base_counts[field][f'R{item["base_register"]}'] += 1
        source_counts[field][item["value_source_kind"]] += 1
        offset_counts[field][item["offset_source"]] += 1

    # Reuse the exact bounded producer signature from Stage20; do not guess
    # which arbitrary occurrence of MOV R4,R2 belongs to this count formula.
    producer_matches = matching_product_preludes(data)
    count_windows = [
        window for match in producer_matches
        if (window := count_derivation_window(data, match["block_start"])) is not None
    ]
    return {
        "candidate_write_total": len(candidates),
        "candidate_write_counts": {
            name: write_counts.get(name, 0) for name in FIELD_NAMES
        },
        "candidate_base_register_counts": {
            name: dict(sorted(base_counts[name].items())) for name in FIELD_NAMES
        },
        "candidate_value_source_kinds": {
            name: dict(sorted(source_counts[name].items())) for name in FIELD_NAMES
        },
        "candidate_offset_definition_kinds": {
            name: dict(sorted(offset_counts[name].items())) for name in FIELD_NAMES
        },
        "metadata_pointer_ffff_sentinel_guard_candidates":
            metadata_pointer_sentinel_guard_candidates(data),
        "recognized_producer_count_windows": len(count_windows),
        "recognized_count_windows_with_zero_test_candidate": sum(
            item["explicit_zero_test_candidate"] for item in count_windows
        ),
        "runtime_zero_count_invariant_proven": False,
        "object_field_initializers_proven": False,
        "interpretation": (
            "The bounded scan finds syntactic indexed-store candidates for the three "
            "producer fields. One recognized producer count path shifts the computed "
            "value right three times before storing it, with no explicit zero-test "
            "candidate in that bounded window. A separate field-writer census is not "
            "a function-boundary, pointer-alias, or runtime-execution proof."
        ),
        "limitations": [
            "The scanner does not establish full function boundaries or a control-flow graph.",
            "Base-register identity across calls and aliases is not proven.",
            "Code/data ambiguity can create false-positive syntactic candidates.",
            "Candidate writes do not prove object construction or runtime reachability.",
            "The 0xFFFF table-sentinel signature does not prove a nonzero metadata block count.",
            "Absence of a zero-test in the recognized window does not prove all callers lack a guard.",
            "No original code offsets, raw machine bytes, RAM captures, or game assets are emitted.",
        ],
    }


def analyze(image: Path) -> dict:
    return {
        "schema_version": 1,
        "stage": "stage69_vdp1_field_writer_census",
        "target_file": "0TH2.BIN",
        "analysis": summarize(iso_file_payload(image)),
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
