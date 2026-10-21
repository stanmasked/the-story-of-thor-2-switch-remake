#!/usr/bin/env python3
"""Stage03: validate counted big-endian 16-bit offset tables in Saturn containers.

Only publishes aggregate structural statistics; does not extract game payloads,
record contents, or sequences of individual offsets. No ROM is used in CI.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout

MAX_PROBE_BYTES = 5 * 1024 * 1024
MISSING = (0, 0xFFFF)


def inspect_counted_table(section: bytes) -> dict | None:
    """Recognize [be16 count][count+1 be16 offsets][payload].

    Missing offsets are encoded as zero or 0xffff. Valid offsets must be even,
    inside the section, and monotonic after ignoring missing entries.
    This validates only an index structure, not the meaning of records.
    """
    if len(section) < 6:
        return None
    count = int.from_bytes(section[:2], 'big')
    slots = count + 1
    table_end = 2 + slots * 2
    if not count or table_end >= len(section):
        return None
    start = int.from_bytes(section[2:4], 'big')
    if start != table_end:
        return None
    offsets = [int.from_bytes(section[2 + i * 2:4 + i * 2], 'big') for i in range(slots)]
    present = [offset for offset in offsets if offset not in MISSING]
    if not present or present[0] != table_end:
        return None
    if any(offset < table_end or offset >= len(section) or offset % 2 for offset in present):
        return None
    if any(a > b for a, b in zip(present, present[1:])):
        return None
    diffs = [b - a for a, b in zip(present, present[1:])]
    counts = Counter(diffs)
    predominant = counts.most_common(1)[0][0] if counts else None
    return {
        'table_end': table_end,
        'indexed_slots': slots,
        'present_slots': len(present),
        'missing_zero': offsets.count(0),
        'missing_ffff': offsets.count(0xFFFF),
        'duplicate_offsets': counts[0],
        'valid_offsets_even': True,
        'predominant_start_delta': predominant,
        'predominant_delta_occurrences': counts[predominant] if predominant is not None else 0,
        'gap_count': len(diffs),
        'six_byte_gaps': counts[6],
        'last_record_remaining_bytes': len(section) - present[-1],
        'six_byte_record_chain_candidate': bool(diffs) and len(section) - present[-1] == 6 and all(delta == 6 for delta in diffs),
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    out = []
    with image.open('rb') as stream:
        for info in disc['game_files']:
            size = info['size_bytes']
            if size > MAX_PROBE_BYTES:
                continue
            stream.seek(info['extent_sector'] * SECTOR)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError('Truncated ISO extent')
            layout = offsets_layout(data)
            if layout is None:
                continue
            base = layout['table_offset']
            bounds = [base + value for value in layout['relative_offsets']] + [size]
            sections = [data[a:b] for a, b in zip(bounds, bounds[1:])]
            indexed = [inspect_counted_table(part) for part in sections]
            out.append({'path': info['path'], 'section_size_bytes': layout['section_size_bytes'],
                        'counted_table_observations': indexed})
    matches = [(item['path'], i) for item in out for i, block in enumerate(item['counted_table_observations']) if block]
    sixbyte = [(item['path'], i) for item in out for i, block in enumerate(item['counted_table_observations']) if block and block['six_byte_record_chain_candidate']]
    return {
        'schema_version': 1,
        'stage': 'stage03_counted_be16_table_probe',
        'disc_sha256': disc['sha256'],
        'game_id': disc['saturn_header']['product'],
        'containers_checked': len(out),
        'validated_tables': len(matches),
        'six_byte_chain_candidates': len(sixbyte),
        'six_byte_chain_locations': [{'path': path, 'section': i} for path, i in sixbyte],
        'files': out,
        'limitations': [
            'The table format is a validated structural hypothesis, not an identified game data type.',
            'A six-byte index stride does not demonstrate animation/frame semantics.',
            'No original offsets, record bytes, game payloads or protected artwork are emitted.',
            'No native Switch game engine or usable gameplay has been implemented.',
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='Private ISO file path')
    parser.add_argument('-o', '--output', type=Path, help='Metadata-only JSON output path')
    args = parser.parse_args()
    result = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(result, encoding='utf-8')
        print('Wrote metadata-only report:', args.output)
    else:
        print(result)


if __name__ == '__main__':
    main()
