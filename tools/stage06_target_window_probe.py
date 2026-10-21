#!/usr/bin/env python3
"""Stage06: compare candidate byte-offset and 8-byte-unit interpretations.

Metadata-only diagnostic. It does not emit target bytes, exact offsets, sprites,
maps, audio, video, or individual record contents.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES
from stage04_record_layout import indexed_records
from stage05_field_profile import valid_eight_byte_items

WINDOW_SIZES = (8, 16, 32, 64, 128)
TARGET_FIELDS = {
    'element_a_raw_bytes': {'source': 'element', 'offset': 0, 'scale': 1},
    'element_a_units_of_8': {'source': 'element', 'offset': 0, 'scale': 8},
    'element_b_raw_bytes': {'source': 'element', 'offset': 2, 'scale': 1},
    'element_b_units_of_8': {'source': 'element', 'offset': 2, 'scale': 8},
    'record_header_a_raw_bytes': {'source': 'record_header', 'offset': 2, 'scale': 1},
    'record_header_a_units_of_8': {'source': 'record_header', 'offset': 2, 'scale': 8},
    'record_header_b_raw_bytes': {'source': 'record_header', 'offset': 4, 'scale': 1},
    'record_header_b_units_of_8': {'source': 'record_header', 'offset': 4, 'scale': 8},
}


def window_profile(windows: list[bytes], expected_count: int | None = None) -> dict:
    """Summarize windows without returning their contents or exact locations."""
    if expected_count is None:
        expected_count = len(windows)
    if not windows:
        return {
            'window_count': 0,
            'expected_window_count': expected_count,
            'out_of_bounds_count': expected_count,
            'coverage_fraction': 0.0 if expected_count else None,
            'unique_window_patterns': 0,
            'mean_zero_fraction': None,
            'mean_entropy_bits_per_byte': None,
            'all_zero_window_count': 0,
            'all_zero_window_fraction': None,
        }
    lengths = {len(window) for window in windows}
    if len(lengths) != 1 or not next(iter(lengths)):
        raise ValueError('All windows must have one common nonzero length')
    zero_fractions = []
    entropies = []
    all_zero = 0
    for window in windows:
        counts = Counter(window)
        n = len(window)
        zero_fractions.append(counts.get(0, 0) / n)
        entropies.append(-sum((c/n) * math.log2(c/n) for c in counts.values()))
        all_zero += not any(window)
    return {
        'window_count': len(windows),
        'expected_window_count': expected_count,
        'out_of_bounds_count': max(0, expected_count - len(windows)),
        'coverage_fraction': round(len(windows) / expected_count, 6) if expected_count else None,
        'unique_window_patterns': len(set(windows)),
        'mean_zero_fraction': round(sum(zero_fractions) / len(zero_fractions), 4),
        'mean_entropy_bits_per_byte': round(sum(entropies) / len(entropies), 4),
        'all_zero_window_count': all_zero,
        'all_zero_window_fraction': round(all_zero / len(windows), 4),
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    global_windows = {name: {size: [] for size in WINDOW_SIZES} for name in TARGET_FIELDS}
    global_expected = {name: 0 for name in TARGET_FIELDS}
    container_profiles = []
    strict_item_total = 0
    strict_record_total = 0
    strict_container_count = 0

    with image.open('rb') as stream:
        for entry in disc['game_files']:
            if entry['size_bytes'] > MAX_PROBE_BYTES:
                continue
            stream.seek(entry['extent_sector'] * SECTOR)
            data = stream.read(entry['size_bytes'])
            if len(data) != entry['size_bytes']:
                raise ValueError('Short read from ISO extent')
            layout = offsets_layout(data)
            if layout is None:
                continue
            base = layout['table_offset']
            boundaries = [base + value for value in layout['relative_offsets']] + [len(data)]
            sections = [data[a:b] for a, b in zip(boundaries, boundaries[1:])]
            items, _, strict = valid_eight_byte_items(sections[0])
            if not strict:
                continue
            records = indexed_records(sections[0])
            if records is None:
                continue
            strict_container_count += 1
            strict_item_total += len(items)
            strict_record_total += len(records)
            raw_targets = {
                'element': {
                    0: [int.from_bytes(item[0:2], 'big') for item in items],
                    2: [int.from_bytes(item[2:4], 'big') for item in items],
                },
                'record_header': {
                    2: [int.from_bytes(record[2:4], 'big') for record in records],
                    4: [int.from_bytes(record[4:6], 'big') for record in records],
                },
            }
            targets = {}
            for name, spec in TARGET_FIELDS.items():
                targets[name] = [v * spec['scale'] for v in raw_targets[spec['source']][spec['offset']]]
            per_container = {
                'path': entry['path'],
                'item_count': len(items),
                'record_count': len(records),
                'fields': {},
            }
            third = sections[2]
            for field_name, offsets in targets.items():
                global_expected[field_name] += len(offsets)
                per_container['fields'][field_name] = {}
                for size in WINDOW_SIZES:
                    windows = [third[offset:offset + size] for offset in offsets if offset + size <= len(third)]
                    global_windows[field_name][size].extend(windows)
                    per_container['fields'][field_name][str(size)] = window_profile(windows, len(offsets))
            container_profiles.append(per_container)

    profiles = {
        field_name: {
            str(size): window_profile(global_windows[field_name][size], global_expected[field_name])
            for size in WINDOW_SIZES
        }
        for field_name in TARGET_FIELDS
    }
    return {
        'schema_version': 1,
        'stage': 'stage06_candidate_target_window_profile',
        'disc_sha256': disc['sha256'],
        'disc_product': disc['saturn_header']['product'],
        'strict_container_count': strict_container_count,
        'strict_item_count': strict_item_total,
        'strict_record_count': strict_record_total,
        'window_sizes_bytes': list(WINDOW_SIZES),
        'candidate_fields': TARGET_FIELDS,
        'field_window_profiles': profiles,
        'container_profiles': container_profiles,
        'limitations': [
            'Scale-by-eight is a tested hypothesis, not confirmed encoding.',
            'Window statistics do not prove any field is a pointer or identify a pixel format.',
            'No exact offsets, window contents, graphics, maps, music or video are exported.',
            'No sprite decoder or playable Switch build exists yet.',
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='Private local Saturn ISO path')
    parser.add_argument('-o', '--output', type=Path, help='Metadata-only JSON output path')
    args = parser.parse_args()
    result = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(result, encoding='utf-8')
        print('Stage 06 target-window metadata saved:', args.output)
    else:
        print(result)


if __name__ == '__main__':
    main()
