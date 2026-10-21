#!/usr/bin/env python3
"""Stage06: compare byte-window statistics at two candidate reference fields.

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
from stage05_field_profile import valid_eight_byte_items

WINDOW_SIZES = (8, 16, 32, 64, 128)
FIELD_POSITIONS = (0, 2)


def window_profile(windows: list[bytes]) -> dict:
    """Summarize windows without returning their contents or exact locations."""
    if not windows:
        return {
            'window_count': 0,
            'unique_window_patterns': 0,
            'mean_zero_fraction': None,
            'mean_entropy_bits_per_byte': None,
            'all_zero_window_count': 0,
            'all_zero_window_fraction': None,
        }
    lengths = {len(window) for window in windows}
    if len(lengths) != 1 or not next(iter(lengths)):
        raise ValueError('All windows must have one common nonzero length')
    length = next(iter(lengths))
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
        'unique_window_patterns': len(set(windows)),
        'mean_zero_fraction': round(sum(zero_fractions) / len(zero_fractions), 4),
        'mean_entropy_bits_per_byte': round(sum(entropies) / len(entropies), 4),
        'all_zero_window_count': all_zero,
        'all_zero_window_fraction': round(all_zero / len(windows), 4),
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    global_windows = {pos: {size: [] for size in WINDOW_SIZES} for pos in FIELD_POSITIONS}
    container_profiles = []
    strict_item_total = 0
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
            strict_container_count += 1
            strict_item_total += len(items)
            per_container = {'path': entry['path'], 'item_count': len(items), 'fields': {}}
            third = sections[2]
            for pos in FIELD_POSITIONS:
                per_container['fields'][str(pos)] = {}
                for size in WINDOW_SIZES:
                    windows = []
                    for item in items:
                        offset = int.from_bytes(item[pos:pos + 2], 'big')
                        if offset + size <= len(third):
                            windows.append(third[offset:offset + size])
                    global_windows[pos][size].extend(windows)
                    per_container['fields'][str(pos)][str(size)] = window_profile(windows)
            container_profiles.append(per_container)

    profiles = {
        str(pos): {str(size): window_profile(global_windows[pos][size]) for size in WINDOW_SIZES}
        for pos in FIELD_POSITIONS
    }
    return {
        'schema_version': 1,
        'stage': 'stage06_candidate_target_window_profile',
        'disc_sha256': disc['sha256'],
        'disc_product': disc['saturn_header']['product'],
        'strict_container_count': strict_container_count,
        'strict_item_count': strict_item_total,
        'window_sizes_bytes': list(WINDOW_SIZES),
        'candidate_fields': {
            '0': 'first BE16 field in an eight-byte element; candidate target only',
            '2': 'second BE16 field in an eight-byte element; candidate target only',
        },
        'field_window_profiles': profiles,
        'container_profiles': container_profiles,
        'limitations': [
            'Window statistics do not prove either field is a pointer or identify a pixel format.',
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
