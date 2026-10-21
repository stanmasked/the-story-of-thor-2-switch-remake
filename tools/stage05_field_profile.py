#!/usr/bin/env python3
"""Stage05: profile candidate references and fixed-stride records, metadata only.

The report intentionally excludes individual byte values, offsets, record bytes,
images, audio and video. It identifies statistical patterns, not semantics.
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES, MISSING, inspect_counted_table
from stage04_record_layout import indexed_records

SAMPLE_LIMIT = 32768
ITEM_WIDTH = 8


def byte_profile(data: bytes) -> dict:
    """Return byte-distribution aggregates without disclosing actual values."""
    if not data:
        return {'sampled_bytes': 0, 'unique_values': 0, 'entropy_bits_per_byte': None,
                'zero_fraction': None, 'ff_fraction': None}
    counts = Counter(data)
    size = len(data)
    entropy = -sum((n / size) * math.log2(n / size) for n in counts.values())
    return {
        'sampled_bytes': size,
        'unique_values': len(counts),
        'entropy_bits_per_byte': round(entropy, 4),
        'zero_fraction': round(counts.get(0, 0) / size, 4),
        'ff_fraction': round(counts.get(255, 0) / size, 4),
    }


def word_profile(values: list[int]) -> dict:
    """Summarize unsigned 16-bit words, including signed interpretation."""
    if not values:
        return {'count': 0, 'unique_values': 0}
    signed = [v if v < 0x8000 else v - 0x10000 for v in values]
    aligned = sum(v % 8 == 0 for v in values)
    return {
        'count': len(values),
        'unique_values': len(set(values)),
        'min_unsigned': min(values),
        'max_unsigned': max(values),
        'min_signed': min(signed),
        'max_signed': max(signed),
        'zero_count': values.count(0),
        'aligned_to_8_count': aligned,
        'aligned_to_8_fraction': round(aligned / len(values), 6),
    }


def valid_eight_byte_items(section: bytes) -> tuple[list[bytes], int, bool]:
    """Return eight-byte items from records satisfying Stage04 grammar.

    The boolean indicates whether every indexed record in this section passes
    the strict grammar. Partial matches from exceptional containers are still
    profiled separately but are not included in strict-container totals.
    """
    records = indexed_records(section)
    if records is None:
        return [], 0, False
    all_strict = True
    items: list[bytes] = []
    accepted_records = 0
    for record in records:
        shape = len(record) >= 14 and (len(record) - 6) % ITEM_WIDTH == 0
        matches = shape and int.from_bytes(record[:2], 'big') == ((len(record) - 6) // ITEM_WIDTH - 1)
        if not matches:
            all_strict = False
            continue
        accepted_records += 1
        items.extend(record[i:i + ITEM_WIDTH] for i in range(6, len(record), ITEM_WIDTH))
    return items, accepted_records, all_strict


def six_byte_table_profile(section: bytes) -> dict:
    """Validate index table, then summarize a complete six-byte record chain."""
    table = inspect_counted_table(section)
    if table is None:
        return {'indexed_table_detected': False, 'six_byte_chain': False}
    starts = [int.from_bytes(section[2 + i * 2:4 + i * 2], 'big')
              for i in range(table['indexed_slots'])]
    present = [v for v in starts if v not in MISSING]
    unique = len(present) == len(set(present))
    differences = [b - a for a, b in zip(present, present[1:])]
    is_chain = bool(present) and unique and all(v == 6 for v in differences) and len(section) - present[-1] == 6
    result = {
        'indexed_table_detected': True,
        'indexed_slots': table['indexed_slots'],
        'present_slots': len(present),
        'missing_zero_slots': table['missing_zero'],
        'missing_ffff_slots': table['missing_ffff'],
        'six_byte_chain': is_chain,
    }
    if not is_chain:
        return result
    rows = [section[start:start + 6] for start in present]
    result['record_count'] = len(rows)
    result['record_width_bytes'] = 6
    result['word_fields'] = []
    for pos in (0, 2, 4):
        result['word_fields'].append({
            'byte_offset_zero_based': pos,
            **word_profile([int.from_bytes(row[pos:pos + 2], 'big') for row in rows]),
        })
    return result


def candidate_reference_profile(items: list[bytes], field_pos: int, third_size: int) -> dict:
    """Summarize whether one BE16 field is compatible with a third-block reference."""
    values = [int.from_bytes(item[field_pos:field_pos + 2], 'big') for item in items]
    in_bounds = sum(value + ITEM_WIDTH <= third_size for value in values)
    aligned = sum(value % 8 == 0 for value in values)
    return {
        'field_byte_offset_zero_based': field_pos,
        'unique_values': len(set(values)),
        'zero_value_count': values.count(0),
        'repeated_occurrences_beyond_first': len(values) - len(set(values)),
        'in_bounds_with_eight_byte_margin_count': in_bounds,
        'in_bounds_with_eight_byte_margin_fraction': round(in_bounds / len(values), 6),
        'aligned_to_eight_count': aligned,
        'aligned_to_eight_fraction': round(aligned / len(values), 6),
        'interpretation': 'candidate only; offset/identifier semantics not proven',
    }


def profile_items(items: list[bytes], third_size: int) -> dict:
    """Profile eight-byte elements and candidate third-section reference fields."""
    if not items:
        return {'item_count': 0}
    if any(len(item) != ITEM_WIDTH for item in items):
        raise ValueError('Items must be exactly eight bytes')
    byte_fields = []
    for pos in range(ITEM_WIDTH):
        byte_fields.append({'byte_offset_zero_based': pos, **byte_profile(bytes(item[pos] for item in items))})
    word_fields = []
    for pos in (0, 2, 4, 6):
        word_fields.append({
            'byte_offset_zero_based': pos,
            **word_profile([int.from_bytes(item[pos:pos + 2], 'big') for item in items]),
        })
    candidates = [candidate_reference_profile(items, pos, third_size) for pos in (0, 2)]
    return {
        'item_count': len(items),
        'byte_fields': byte_fields,
        'big_endian_word_fields': word_fields,
        'candidate_third_section_references': candidates,
        # Backwards-compatible alias: offset 2 is the more strongly aligned field.
        'candidate_third_section_reference': candidates[1],
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    containers = []
    strict_item_total = 0
    all_item_total = 0
    candidate_aggregate = {
        pos: {'count': 0, 'unique_values': set(), 'in_bounds': 0, 'aligned': 0, 'zero_count': 0}
        for pos in (0, 2)
    }
    six_chain_count = 0
    six_record_total = 0
    cross_matches = {
        candidate_pos: {
            row_pos: {'unique_value_matches_summed_per_container': 0, 'item_occurrences': 0}
            for row_pos in (0, 2, 4)
        }
        for candidate_pos in (0, 2)
    }
    entropy_values = []
    zero_fractions = []

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
            base = layout['table_offset']
            boundaries = [base + value for value in layout['relative_offsets']] + [size]
            sections = [data[a:b] for a, b in zip(boundaries, boundaries[1:])]
            items, accepted_records, strict_container = valid_eight_byte_items(sections[0])
            item_summary = profile_items(items, len(sections[2]))
            section2 = six_byte_table_profile(sections[1])
            sample = byte_profile(sections[2][:SAMPLE_LIMIT])
            if sample['entropy_bits_per_byte'] is not None:
                entropy_values.append(sample['entropy_bits_per_byte'])
                zero_fractions.append(sample['zero_fraction'])
            if section2.get('six_byte_chain'):
                six_chain_count += 1
                six_record_total += section2['record_count']
                starts = [int.from_bytes(sections[1][2 + i * 2:4 + i * 2], 'big')
                          for i in range(section2['indexed_slots'])]
                starts = [v for v in starts if v not in MISSING]
                rows = [sections[1][start:start + 6] for start in starts]
                row_values_by_pos = {
                    row_pos: [int.from_bytes(row[row_pos:row_pos + 2], 'big') for row in rows]
                    for row_pos in (0, 2, 4)
                }
                for candidate_pos in (0, 2):
                    values = [int.from_bytes(item[candidate_pos:candidate_pos + 2], 'big') for item in items]
                    for row_pos, row_values in row_values_by_pos.items():
                        row_value_set = set(row_values)
                        cross_matches[candidate_pos][row_pos]['unique_value_matches_summed_per_container'] += len(set(values) & row_value_set)
                        cross_matches[candidate_pos][row_pos]['item_occurrences'] += sum(v in row_value_set for v in values)
            if strict_container:
                strict_item_total += len(items)
                for pos in (0, 2):
                    values = [int.from_bytes(item[pos:pos + 2], 'big') for item in items]
                    aggregate = candidate_aggregate[pos]
                    aggregate['count'] += len(values)
                    aggregate['unique_values'].update(values)
                    aggregate['in_bounds'] += sum(value + ITEM_WIDTH <= len(sections[2]) for value in values)
                    aggregate['aligned'] += sum(value % 8 == 0 for value in values)
                    aggregate['zero_count'] += values.count(0)
            all_item_total += len(items)
            containers.append({
                'path': entry['path'],
                'section_sizes_bytes': layout['section_size_bytes'],
                'indexed_record_count': accepted_records,
                'all_records_match_stage04_grammar': strict_container,
                'item_profile': item_summary,
                'second_section_profile': section2,
                'third_section_sample': sample,
            })

    candidate_summary = {}
    for pos, aggregate in candidate_aggregate.items():
        count = aggregate['count']
        candidate_summary[str(pos)] = {
            'field_byte_offset_zero_based': pos,
            'item_count': count,
            'unique_values_across_strict_containers': len(aggregate['unique_values']),
            'zero_value_count': aggregate['zero_count'],
            'in_bounds_with_eight_byte_margin_count': aggregate['in_bounds'],
            'aligned_to_eight_count': aggregate['aligned'],
            'aligned_to_eight_fraction': round(aggregate['aligned'] / count, 6) if count else None,
            'interpretation': 'candidate only; offset/identifier semantics not proven',
        }

    return {
        'schema_version': 1,
        'stage': 'stage05_field_profile_and_section_cross_checks',
        'disc_sha256': disc['sha256'],
        'disc_product': disc['saturn_header']['product'],
        'container_count': len(containers),
        'strict_grammar_containers': sum(1 for item in containers if item['all_records_match_stage04_grammar']),
        'strict_grammar_items': strict_item_total,
        'all_individually_matching_items': all_item_total,
        'strict_candidate_reference_fields': candidate_summary,
        'six_byte_chains': six_chain_count,
        'six_byte_records': six_record_total,
        'cross_matches_between_candidate_fields_and_six_byte_words': {
            str(candidate_pos): {str(row_pos): result for row_pos, result in row_fields.items()}
            for candidate_pos, row_fields in cross_matches.items()
        },
        'third_section_sample_entropy_range': [min(entropy_values), max(entropy_values)] if entropy_values else None,
        'third_section_sample_zero_fraction_range': [min(zero_fractions), max(zero_fractions)] if zero_fractions else None,
        'containers': containers,
        'limitations': [
            'Candidate fields may be relative offsets, IDs or packed values; semantics are not proven.',
            'No exact offsets, raw byte values, records, sprites, maps, audio or video are exported.',
            'Low sample entropy does not prove an uncompressed image format.',
            'No asset decoder, native game engine or Switch NRO has been implemented.',
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
        print('Stage 05 metadata-only report saved:', args.output)
    else:
        print(result)


if __name__ == '__main__':
    main()
