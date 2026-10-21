#!/usr/bin/env python3
"""Stage10: test texture-dimension and palette hypotheses without exporting assets.

The analyzer emits only aggregate counts and statistics. It does not write
source bytes, individual offsets, decoded images, palettes, audio, or video.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES
from stage05_field_profile import valid_eight_byte_items

MIN_TEXTURE_OFFSET = 512
MIN_BLOCK_BYTES = 32
MAX_BLOCK_BYTES = 2048
MIN_WIDTH = 8
MAX_WIDTH = 256
MAX_HEIGHT = 256
WIDTH_STEP = 8
PALETTE_WINDOW_BYTES = 32


def be16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def candidate_blocks(items: list[bytes], section: bytes) -> list[tuple[int, bytes]]:
    """Return exploratory blocks between distinct field-A references.

    The returned offsets are internal only and must never be copied to reports.
    """
    offsets = sorted({
        be16(item, 0) * 8 for item in items
        if be16(item, 0) * 8 >= MIN_TEXTURE_OFFSET
    })
    blocks = []
    for index, offset in enumerate(offsets):
        end = offsets[index + 1] if index + 1 < len(offsets) else len(section)
        size = end - offset
        if MIN_BLOCK_BYTES <= size <= MAX_BLOCK_BYTES and end <= len(section):
            blocks.append((offset, section[offset:end]))
    return blocks


def dimension_candidates(block_bytes: int, bpp: int) -> list[tuple[int, int]]:
    """Return exact byte-length dimensions under a stated bpp assumption.

    Widths are multiples of eight from 8 to 256 pixels; heights are 1..256.
    A returned pair is arithmetic compatibility only, not a recovered dimension.
    """
    if bpp not in (4, 8, 16):
        raise ValueError("bpp must be 4, 8, or 16")
    if block_bytes <= 0:
        return []
    total_bits = block_bytes * 8
    result = []
    for width in range(MIN_WIDTH, MAX_WIDTH + 1, WIDTH_STEP):
        unit = width * bpp
        if total_bits % unit:
            continue
        height = total_bits // unit
        if 1 <= height <= MAX_HEIGHT:
            result.append((width, height))
    return result


def dimension_profile(block_sizes: list[int]) -> dict:
    """Summarize how many dimensions remain possible for each candidate block."""
    if not block_sizes:
        return {
            "candidate_block_count": 0,
            "distinct_block_sizes": 0,
            "blocks_with_dimensions_by_bpp": {"4": 0, "8": 0, "16": 0},
            "blocks_compatible_with_all_three_bpp_hypotheses": 0,
            "median_dimension_interpretations_per_block": None,
            "mean_dimension_interpretations_per_block": None,
            "maximum_dimension_interpretations_for_one_block": None,
        }
    interpretation_counts = []
    compatible = Counter()
    all_three = 0
    for size in block_sizes:
        candidates = {bpp: dimension_candidates(size, bpp) for bpp in (4, 8, 16)}
        for bpp, options in candidates.items():
            if options:
                compatible[bpp] += 1
        if all(candidates[bpp] for bpp in (4, 8, 16)):
            all_three += 1
        interpretation_counts.append(sum(len(options) for options in candidates.values()))
    return {
        "candidate_block_count": len(block_sizes),
        "distinct_block_sizes": len(set(block_sizes)),
        "blocks_with_dimensions_by_bpp": {str(bpp): compatible[bpp] for bpp in (4, 8, 16)},
        "blocks_compatible_with_all_three_bpp_hypotheses": all_three,
        "median_dimension_interpretations_per_block": statistics.median(interpretation_counts),
        "mean_dimension_interpretations_per_block": round(statistics.mean(interpretation_counts), 2),
        "maximum_dimension_interpretations_for_one_block": max(interpretation_counts),
    }


def direct_dimensions_match(width: int, height: int, block_bytes: int, bpp: int) -> bool:
    """Check whether two raw element words exactly explain a candidate block size."""
    if bpp not in (4, 8, 16):
        raise ValueError("bpp must be 4, 8, or 16")
    if not (MIN_WIDTH <= width <= MAX_WIDTH and width % WIDTH_STEP == 0):
        return False
    if not (1 <= height <= MAX_HEIGHT):
        return False
    return width * height * bpp == block_bytes * 8


def palette_window_profile(window: bytes) -> dict:
    """Profile one aligned 32-byte window as 16 tentative BE16 RGB555 words."""
    if len(window) != PALETTE_WINDOW_BYTES:
        raise ValueError("palette screen requires exactly 32 bytes")
    words = [be16(window, offset) for offset in range(0, PALETTE_WINDOW_BYTES, 2)]
    colors = [word & 0x7FFF for word in words]
    return {
        "unique_rgb555_values": len(set(colors)),
        "msb_set_word_count": sum(bool(word & 0x8000) for word in words),
        "nonzero_color_count": sum(color != 0 for color in colors),
    }


def is_loose_palette_like(profile: dict) -> bool:
    """A deliberately permissive screen, not a palette classifier."""
    return (
        4 <= profile["unique_rgb555_values"] <= 16
        and profile["msb_set_word_count"] <= 4
        and profile["nonzero_color_count"] >= 4
    )


def scan_palette_windows(sections: list[tuple[str, str, bytes]]) -> dict:
    """Count loose palette-like windows without retaining or emitting their bytes."""
    windows_scanned = 0
    region_counts: Counter[str] = Counter()
    strict_count = 0
    hashes_by_container: dict[str, set[str]] = defaultdict(set)
    unique_hashes: set[str] = set()

    for container, region, data in sections:
        for offset in range(0, len(data) - PALETTE_WINDOW_BYTES + 1, PALETTE_WINDOW_BYTES):
            window = data[offset:offset + PALETTE_WINDOW_BYTES]
            windows_scanned += 1
            profile = palette_window_profile(window)
            if not is_loose_palette_like(profile):
                continue
            region_counts[region] += 1
            digest = hashlib.sha256(window).hexdigest()
            unique_hashes.add(digest)
            hashes_by_container[digest].add(container)
            if (
                profile["unique_rgb555_values"] >= 14
                and profile["msb_set_word_count"] == 0
                and profile["nonzero_color_count"] >= 14
            ):
                strict_count += 1

    repeated_across_containers = sum(
        len(containers) >= 2 for containers in hashes_by_container.values()
    )
    return {
        "windows_scanned": windows_scanned,
        "loose_palette_like_windows_by_region": dict(sorted(region_counts.items())),
        "loose_palette_like_window_count": sum(region_counts.values()),
        "stricter_rgb555_like_window_count": strict_count,
        "distinct_loose_candidate_window_contents": len(unique_hashes),
        "candidate_contents_repeated_across_multiple_containers": repeated_across_containers,
        "interpretation": (
            "The screen is intentionally permissive. A large candidate count is "
            "evidence that RGB555-like word patterns alone cannot identify palettes."
        ),
    }


def analyze(image: Path) -> dict:
    disc = inventory(image)
    block_sizes: list[int] = []
    section_windows: list[tuple[str, str, bytes]] = []
    containers = []
    direct_matches = Counter()

    with image.open("rb") as stream:
        for entry in disc["game_files"]:
            size = entry["size_bytes"]
            if size > MAX_PROBE_BYTES:
                continue
            stream.seek(entry["extent_sector"] * SECTOR)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Short read from ISO extent: " + entry["path"])
            layout = offsets_layout(data)
            if layout is None:
                continue
            base = layout["table_offset"]
            bounds = [base + value for value in layout["relative_offsets"]] + [len(data)]
            sections = [data[left:right] for left, right in zip(bounds, bounds[1:])]
            items, _, strict = valid_eight_byte_items(sections[0])
            if not strict:
                continue

            blocks = candidate_blocks(items, sections[2])
            sizes_by_offset = {offset: len(block) for offset, block in blocks}
            block_sizes.extend(sizes_by_offset.values())
            section_windows.extend([
                (entry["path"], "section2", sections[1]),
                (entry["path"], "section3", sections[2]),
            ])

            for item in items:
                offset = be16(item, 0) * 8
                block_size = sizes_by_offset.get(offset)
                if block_size is None:
                    continue
                width = be16(item, 4)
                height = be16(item, 6)
                for bpp in (4, 8, 16):
                    if direct_dimensions_match(width, height, block_size, bpp):
                        direct_matches[bpp] += 1

            containers.append({
                "path": entry["path"],
                "strict_item_count": len(items),
                "candidate_block_count": len(blocks),
                "candidate_block_bytes_total": sum(len(block) for _, block in blocks),
            })

    size_counts = Counter(block_sizes)
    dimension_summary = dimension_profile(block_sizes)
    return {
        "schema_version": 1,
        "stage": "stage10_texture_dimension_palette_ambiguity_audit",
        "disc_sha256": disc["sha256"],
        "disc_product": disc["saturn_header"]["product"],
        "strict_container_count": len(containers),
        "candidate_blocks": {
            **dimension_summary,
            "candidate_bytes_total": sum(block_sizes),
            "median_block_bytes": statistics.median(block_sizes) if block_sizes else None,
            "most_common_block_sizes": [
                {"size_bytes": block_size, "count": count}
                for block_size, count in size_counts.most_common(10)
            ],
            "boundary_rule": (
                "from each non-null field-A reference multiplied by 8 to the next "
                "distinct referenced address; candidate lengths are not confirmed image extents"
            ),
        },
        "raw_field_c_d_dimension_check": {
            "matches_by_bpp": {str(bpp): direct_matches[bpp] for bpp in (4, 8, 16)},
            "field_interpretation": "raw BE16 words at byte offsets 4 and 6, tested as width and height",
            "note": "No match count proves field semantics; sparse matches may be coincidental.",
        },
        "palette_window_screen": scan_palette_windows(section_windows),
        "containers": containers,
        "interpretation": [
            "Almost every candidate block admits multiple exact width/height combinations under more than one bpp assumption.",
            "Raw words at element byte offsets 4 and 6 do not provide a consistent width/height explanation for the candidate blocks.",
            "The permissive RGB555-like scan returns many windows and does not isolate a palette table.",
            "Stage 10 therefore rejects selecting a pixel format or palette from these statistics alone.",
        ],
        "limitations": [
            "Only the ten strict three-section containers are scanned for candidate blocks and palette-like windows.",
            "Texture boundaries inferred from neighboring references are not confirmed image extents.",
            "No pixel format, dimensions, palette, transparency rule, compression scheme, or sprite extent is confirmed.",
            "Reports contain aggregate metadata only; no original bytes, exact offsets, images, palettes, audio, or video are exported.",
            "No native game engine, playable build, or Switch NRO is produced.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Private local Sega Saturn ISO")
    parser.add_argument("-o", "--output", type=Path, help="Metadata-only JSON output path")
    args = parser.parse_args()
    result = json.dumps(analyze(args.image), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
        print("Stage 10 metadata-only report saved:", args.output)
    else:
        print(result)


if __name__ == "__main__":
    main()
