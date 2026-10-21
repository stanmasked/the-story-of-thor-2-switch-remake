#!/usr/bin/env python3
"""Stage09: profile nibble structure in candidate texture blocks.

Metadata-only analysis of locally referenced blocks. No original bytes, offsets,
images, palettes, audio, or video are written to the report.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES
from stage05_field_profile import valid_eight_byte_items

MIN_BLOCK_BYTES = 32
MAX_BLOCK_BYTES = 2048
MIN_TEXTURE_OFFSET = 512


def entropy(counts: Counter[int], total: int) -> float | None:
    if total <= 0:
        return None
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def profile_candidate_block(block: bytes) -> dict:
    """Report byte/nibble statistics without exposing individual values."""
    if not block:
        return {
            'block_bytes': 0,
            'unique_byte_values': 0,
            'unique_nibble_values': 0,
            'same_nibble_byte_fraction': None,
            'zero_byte_fraction': None,
            'byte_entropy_bits_per_byte': None,
            'nibble_entropy_bits_per_pixel': None,
        }
    byte_counts = Counter(block)
    nibbles = [nibble for value in block for nibble in (value >> 4, value & 0x0F)]
    nibble_counts = Counter(nibbles)
    same_nibble = sum((value >> 4) == (value & 0x0F) for value in block)
    return {
        'block_bytes': len(block),
        'unique_byte_values': len(byte_counts),
        'unique_nibble_values': len(nibble_counts),
        'same_nibble_byte_fraction': round(same_nibble / len(block), 6),
        'zero_byte_fraction': round(byte_counts.get(0, 0) / len(block), 6),
        'byte_entropy_bits_per_byte': round(entropy(byte_counts, len(block)), 4),
        'nibble_entropy_bits_per_pixel': round(entropy(nibble_counts, len(nibbles)), 4),
    }


def summarize_blocks(blocks: list[bytes]) -> dict:
    profiles = [profile_candidate_block(block) for block in blocks]
    if not profiles:
        return {
            'candidate_block_count': 0,
            'candidate_bytes_total': 0,
            'median_block_bytes': None,
            'mean_same_nibble_byte_fraction': None,
            'median_same_nibble_byte_fraction': None,
            'mean_zero_byte_fraction': None,
            'mean_unique_byte_values': None,
            'mean_unique_nibble_values': None,
            'mean_byte_entropy_bits_per_byte': None,
            'mean_nibble_entropy_bits_per_pixel': None,
        }
    def mean(key: str) -> float:
        return round(statistics.mean(profile[key] for profile in profiles), 4)
    same = [profile['same_nibble_byte_fraction'] for profile in profiles]
    return {
        'candidate_block_count': len(blocks),
        'candidate_bytes_total': sum(len(block) for block in blocks),
        'median_block_bytes': int(statistics.median(len(block) for block in blocks)),
        'mean_same_nibble_byte_fraction': mean('same_nibble_byte_fraction'),
        'median_same_nibble_byte_fraction': round(statistics.median(same), 4),
        'mean_zero_byte_fraction': mean('zero_byte_fraction'),
        'mean_unique_byte_values': mean('unique_byte_values'),
        'mean_unique_nibble_values': mean('unique_nibble_values'),
        'mean_byte_entropy_bits_per_byte': mean('byte_entropy_bits_per_byte'),
        'mean_nibble_entropy_bits_per_pixel': mean('nibble_entropy_bits_per_pixel'),
    }


def candidate_blocks(items: list[bytes], section: bytes) -> list[bytes]:
    """Use adjacent referenced offsets as exploratory block boundaries."""
    offsets = sorted(set(
        int.from_bytes(item[:2], 'big') * 8
        for item in items
        if int.from_bytes(item[:2], 'big') * 8 >= MIN_TEXTURE_OFFSET
    ))
    blocks = []
    for index, offset in enumerate(offsets):
        end = offsets[index + 1] if index + 1 < len(offsets) else len(section)
        size = end - offset
        if MIN_BLOCK_BYTES <= size <= MAX_BLOCK_BYTES and end <= len(section):
            blocks.append(section[offset:end])
    return blocks


def analyze(image: Path) -> dict:
    disc = inventory(image)
    container_results = []
    all_blocks: list[bytes] = []
    with image.open('rb') as stream:
        for entry in disc['game_files']:
            size = entry['size_bytes']
            if size > MAX_PROBE_BYTES:
                continue
            stream.seek(entry['extent_sector'] * SECTOR)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError(f'Short read from ISO extent: {entry["path"]}')
            layout = offsets_layout(data)
            if layout is None:
                continue
            base = layout['table_offset']
            bounds = [base + value for value in layout['relative_offsets']] + [len(data)]
            sections = [data[left:right] for left, right in zip(bounds, bounds[1:])]
            items, _, strict = valid_eight_byte_items(sections[0])
            if not strict:
                continue
            blocks = candidate_blocks(items, sections[2])
            summary = summarize_blocks(blocks)
            container_results.append({
                'path': entry['path'],
                'strict_item_count': len(items),
                **summary,
            })
            all_blocks.extend(blocks)
    overall = summarize_blocks(all_blocks)
    return {
        'schema_version': 1,
        'stage': 'stage09_candidate_texture_nibble_structure',
        'disc_sha256': disc['sha256'],
        'disc_product': disc['saturn_header']['product'],
        'container_count': len(container_results),
        'filters': {
            'minimum_candidate_offset_bytes': MIN_TEXTURE_OFFSET,
            'minimum_candidate_block_bytes': MIN_BLOCK_BYTES,
            'maximum_candidate_block_bytes': MAX_BLOCK_BYTES,
            'boundary_rule': 'from each non-null field-A offset multiplied by 8 to the next distinct referenced offset',
        },
        'overall_candidate_block_profile': overall,
        'containers': container_results,
        'interpretation': [
            'A high fraction of bytes with identical high/low nibbles is consistent with packed 4bpp pixels or another nibble-structured encoding.',
            'This statistic alone cannot distinguish raw 4bpp pixels from compression or metadata with similar patterns.',
            'Candidate block boundaries are inferred from neighboring references, not confirmed image extents.',
        ],
        'limitations': [
            'No original byte values, offsets, block contents, images, palettes, audio, or video are exported.',
            'No pixel format, texture dimensions, palette, compression scheme, or image extent is confirmed.',
            'The analysis does not produce a playable game or Switch NRO.',
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
        print('Stage 09 nibble-structure metadata saved:', args.output)
    else:
        print(result)


if __name__ == '__main__':
    main()
