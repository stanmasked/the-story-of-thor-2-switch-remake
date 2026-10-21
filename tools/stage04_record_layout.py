#!/usr/bin/env python3
"""Stage04: validate counted 6-byte headers plus 8-byte items in Saturn files.

Only aggregate data is emitted. No graphics or game file content is exported.
The format describes storage, not identified game or animation semantics.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES, MISSING, inspect_counted_table


def indexed_records(section: bytes) -> list[bytes] | None:
    """Obtain bounded record spans from strictly increasing valid offsets."""
    header = inspect_counted_table(section)
    if header is None or header['duplicate_offsets']:
        return None
    slots = header['indexed_slots']
    starts = [int.from_bytes(section[2+i*2:4+i*2], 'big') for i in range(slots)]
    present = [x for x in starts if x not in MISSING]
    if not present or len(present) != len(set(present)):
        return None
    return [section[a:b] for a, b in zip(present, present[1:] + [len(section)])]


def inspect_record_layout(section: bytes) -> dict | None:
    """Validate 6+8*N and first BE16 word == N-1 for every indexed span."""
    records = indexed_records(section)
    if records is None:
        return None
    sizes = [len(rec) for rec in records]
    well_shaped = [len(rec) >= 14 and (len(rec)-6) % 8 == 0 for rec in records]
    matches = [ok and int.from_bytes(rec[:2], 'big') == (len(rec)-6)//8 - 1
               for ok, rec in zip(well_shaped, records)]
    item_counts = Counter((len(rec)-6)//8 for rec, ok in zip(records, matches) if ok)
    return {
        'record_count': len(records),
        'six_plus_eight_shape_count': sum(well_shaped),
        'header_counter_match_count': sum(matches),
        'fully_validated': all(matches),
        'min_record_bytes': min(sizes),
        'max_record_bytes': max(sizes),
        'min_item_count': min(item_counts) if item_counts else None,
        'max_item_count': max(item_counts) if item_counts else None,
        'item_count_histogram': {str(n): count for n, count in sorted(item_counts.items())},
        'unmatched_count': len(records) - sum(matches),
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    observations = []
    with image.open('rb') as stream:
        for entry in disc['game_files']:
            size = entry['size_bytes']
            if size > MAX_PROBE_BYTES:
                continue
            stream.seek(entry['extent_sector'] * SECTOR)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError('Short read from ISO extent')
            layout = offsets_layout(data)
            if layout is None:
                continue
            start = layout['table_offset'] + layout['relative_offsets'][0]
            end = layout['table_offset'] + layout['relative_offsets'][1]
            result = inspect_record_layout(data[start:end])
            observations.append({'path': entry['path'], 'section': 0, 'observation': result})
    accepted = [v for v in observations if v['observation'] and v['observation']['fully_validated']]
    rejected = [v for v in observations if v['observation'] and not v['observation']['fully_validated']]
    return {
        'schema_version': 1,
        'stage': 'stage04_counted_six_plus_eight_record_layout',
        'disc_sha256': disc['sha256'],
        'disc_product': disc['saturn_header']['product'],
        'three_section_containers': len(observations),
        'fully_validated_containers': len(accepted),
        'rejected_by_strict_record_rule': len(rejected),
        'total_records_strictly_validated': sum(v['observation']['record_count'] for v in accepted),
        'observations': observations,
        'limitations': [
            '6+8*N structure is byte-level evidence, not an identified graphics or animation format.',
            'Rejected candidates may contain different formats; this checker does not decode them.',
            'No original binary bytes, offsets, image content, music or video are exported.',
            'No native Switch NRO or gameplay has been produced.',
        ],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image', type=Path, help='Private ISO path')
    ap.add_argument('-o', '--output', type=Path, help='Metadata-only JSON report path')
    args = ap.parse_args()
    content = json.dumps(analyze(args.image), indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(content, encoding='utf-8')
        print('Stage 04 metadata-only report:', args.output)
    else:
        print(content)


if __name__ == '__main__':
    main()
