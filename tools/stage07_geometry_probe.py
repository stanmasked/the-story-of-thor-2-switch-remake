#!/usr/bin/env python3
"""Stage07: validate texture-address and triangle-like geometry hypotheses.

Metadata-only analysis of private Sega Saturn resources. The tool reports only
aggregate counts and coordinate ranges; it does not export payload bytes,
exact target offsets, textures, images, audio, or video.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES
from stage05_field_profile import valid_eight_byte_items

TEXTURE_ALIGNMENT = 32
TEXTURE_MIN_BYTES = 32
GEOMETRY_TABLE_PREFIX_WORDS = 16
GEOMETRY_MIN_NONZERO_ENTRIES = 4
GEOMETRY_RECORD_BYTES = 14
GEOMETRY_TERMINATOR = 0x7FFF


def be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], 'big')


def signed16(value: int) -> int:
    return value if value < 0x8000 else value - 0x10000


def is_triangle_like_record(section: bytes, offset: int) -> bool:
    """Check a 14-byte record with six BE16 words and a 0x7fff tail marker."""
    return (
        offset >= 0
        and offset % 2 == 0
        and offset + GEOMETRY_RECORD_BYTES <= len(section)
        and be16(section, offset + 12) == GEOMETRY_TERMINATOR
    )


def texture_pointer_profile(items: list[bytes], section_size: int) -> dict:
    """Check field A as an 8-byte unit offset to a 32-byte-aligned texture."""
    raw_values = [be16(item, 0) for item in items]
    offsets = [value * 8 for value in raw_values if value]
    unique = sorted(set(offsets))
    gaps = [right - left for left, right in zip(unique, unique[1:])]
    return {
        'item_count': len(items),
        'null_pointer_count': raw_values.count(0),
        'non_null_pointer_occurrences': len(offsets),
        'unique_non_null_offsets': len(unique),
        'all_non_null_offsets_32_byte_aligned': all(v % TEXTURE_ALIGNMENT == 0 for v in offsets),
        'minimum_32_byte_window_in_bounds_count': sum(v + TEXTURE_MIN_BYTES <= section_size for v in offsets),
        'unique_offset_gap_count': len(gaps),
        'gaps_multiple_of_32_count': sum(g % TEXTURE_ALIGNMENT == 0 for g in gaps),
        'gaps_min_bytes': min(gaps) if gaps else None,
        'gaps_max_bytes': max(gaps) if gaps else None,
        'interpretation': 'strong texture-address candidate; pixel format and dimensions unconfirmed',
    }


def geometry_table_profile(items: list[bytes], section: bytes) -> dict:
    """Probe unique field-B table prefixes for offsets to 14-byte records."""
    candidate_tables: set[int] = set()
    candidate_entry_count = 0
    target_offsets: set[int] = set()

    for table_offset in sorted(set(be16(item, 2) for item in items)):
        if table_offset % 2 or table_offset + GEOMETRY_TABLE_PREFIX_WORDS * 2 > len(section):
            continue
        values = [be16(section, table_offset + 2 * i) for i in range(GEOMETRY_TABLE_PREFIX_WORDS)]
        nonzero = [value for value in values if value]
        if len(nonzero) < GEOMETRY_MIN_NONZERO_ENTRIES:
            continue
        valid = [value for value in nonzero if is_triangle_like_record(section, value)]
        # Keep the rule deliberately strict to reduce chance matches in opaque data.
        if len(valid) != len(nonzero):
            continue
        candidate_tables.add(table_offset)
        candidate_entry_count += len(valid)
        target_offsets.update(valid)

    # Offsets are local to this file, so comparisons stay within this section.
    sorted_targets = sorted(target_offsets)
    adjacent_stride_count = sum(
        offset + GEOMETRY_RECORD_BYTES in target_offsets for offset in sorted_targets
    )
    coords = []
    for offset in sorted_targets:
        coords.extend(signed16(be16(section, offset + pos)) for pos in (0, 2, 4, 6, 8, 10))

    return {
        'unique_field_b_offsets_examined': len(set(be16(item, 2) for item in items)),
        'candidate_table_prefix_count': len(candidate_tables),
        'prefix_words_checked': GEOMETRY_TABLE_PREFIX_WORDS,
        'minimum_nonzero_entries_for_candidate': GEOMETRY_MIN_NONZERO_ENTRIES,
        'valid_nonzero_entries_across_candidate_prefixes': candidate_entry_count,
        'unique_triangle_like_record_offsets': len(target_offsets),
        'unique_records_with_14_byte_successor': adjacent_stride_count,
        'successor_stride_14_fraction': round(adjacent_stride_count / len(target_offsets), 6) if target_offsets else None,
        'signed_coordinate_word_min': min(coords) if coords else None,
        'signed_coordinate_word_max': max(coords) if coords else None,
        'all_candidate_nonzero_entries_have_14_byte_0x7fff_tail': True if candidate_tables else False,
        'interpretation': 'triangle-like geometry-list candidate; semantics not proven',
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    results = []
    texture_occurrences = 0
    texture_unique_offsets = 0
    texture_aligned_occurrences = 0
    texture_windows_in_bounds = 0
    texture_gaps = 0
    texture_gaps_aligned = 0
    geometry_table_prefixes = 0
    geometry_entries = 0
    geometry_records = 0
    geometry_successors = 0
    geometry_files = 0
    strict_items_total = 0

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
            strict_items_total += len(items)
            texture = texture_pointer_profile(items, len(sections[2]))
            geometry = geometry_table_profile(items, sections[2])
            texture_occurrences += texture['non_null_pointer_occurrences']
            texture_unique_offsets += texture['unique_non_null_offsets']
            texture_aligned_occurrences += sum(
                be16(item, 0) != 0 and (be16(item, 0) * 8) % TEXTURE_ALIGNMENT == 0
                for item in items
            )
            texture_windows_in_bounds += texture['minimum_32_byte_window_in_bounds_count']
            texture_gaps += texture['unique_offset_gap_count']
            texture_gaps_aligned += texture['gaps_multiple_of_32_count']
            geometry_table_prefixes += geometry['candidate_table_prefix_count']
            geometry_entries += geometry['valid_nonzero_entries_across_candidate_prefixes']
            geometry_records += geometry['unique_triangle_like_record_offsets']
            geometry_successors += geometry['unique_records_with_14_byte_successor']
            if geometry['candidate_table_prefix_count']:
                geometry_files += 1
            results.append({
                'path': entry['path'],
                'section3_size_bytes': len(sections[2]),
                'strict_item_count': len(items),
                'texture_pointer_profile': texture,
                'geometry_table_profile': geometry,
            })

    return {
        'schema_version': 1,
        'stage': 'stage07_texture_and_geometry_pointer_probe',
        'disc_sha256': disc['sha256'],
        'disc_product': disc['saturn_header']['product'],
        'strict_container_count': len(results),
        'strict_item_count': strict_items_total,
        'texture_pointer_summary': {
            'non_null_pointer_occurrences': texture_occurrences,
            'unique_non_null_offsets_summed_per_container': texture_unique_offsets,
            'all_non_null_offsets_32_byte_aligned_count': texture_aligned_occurrences,
            'minimum_32_byte_window_in_bounds_count': texture_windows_in_bounds,
            'unique_offset_gaps_summed_per_container': texture_gaps,
            'gaps_multiple_of_32_count': texture_gaps_aligned,
            'interpretation': 'field A × 8 strongly matches the Saturn VDP1 32-byte character-pattern alignment, but format is not decoded',
        },
        'geometry_pointer_summary': {
            'containers_with_candidate_tables': geometry_files,
            'candidate_table_prefixes': geometry_table_prefixes,
            'valid_nonzero_entries_across_candidate_prefixes': geometry_entries,
            'unique_target_records_summed_per_container': geometry_records,
            'unique_records_with_14_byte_successor_summed_per_container': geometry_successors,
            'successor_stride_14_fraction': round(geometry_successors / geometry_records, 6) if geometry_records else None,
            'interpretation': 'field B may point to offset lists for 14-byte coordinate records ending in 0x7fff; semantics unproven',
        },
        'containers': results,
        'limitations': [
            'The texture pointer interpretation is strongly supported by alignment but not proven from executable code.',
            'The 14-byte marker pattern does not alone prove that records are triangles or that coordinates are vertices.',
            'Texture pixel format, dimensions, palette, compression, and draw order are not yet established.',
            'No original payload bytes, exact target offsets, images, audio, or video are exported.',
            'No playable engine or Switch NRO has been produced.',
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='Private local Saturn ISO path')
    parser.add_argument('-o', '--output', type=Path, help='Metadata-only JSON output path')
    args = parser.parse_args()
    output = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(output, encoding='utf-8')
        print('Stage 07 metadata-only report saved:', args.output)
    else:
        print(output)


if __name__ == '__main__':
    main()
