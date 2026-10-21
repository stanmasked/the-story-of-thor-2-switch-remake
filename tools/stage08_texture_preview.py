#!/usr/bin/env python3
"""Stage08: render private candidate textures under explicit format assumptions.

This is an exploratory previewer, not a confirmed game asset decoder. It reads
one local ISO resource and writes a candidate PNG. Do not commit preview PNGs or
publish the original ISO/assets.
"""
from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

from inspect_saturn_iso import SECTOR, inventory
from stage02_probe import offsets_layout
from stage03_index_tables import MAX_PROBE_BYTES
from stage05_field_profile import valid_eight_byte_items

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'


def decode_rgba(payload: bytes, width: int, height: int, bpp: int, nibble_order: str = 'high-first') -> bytes:
    """Decode raw 4/8/16bpp candidates to RGBA; palette is only a debug grayscale."""
    if width <= 0 or height <= 0:
        raise ValueError('Width and height must be positive')
    if bpp not in (4, 8, 16):
        raise ValueError('bpp must be 4, 8, or 16')
    if nibble_order not in ('high-first', 'low-first'):
        raise ValueError('nibble_order must be high-first or low-first')
    pixel_count = width * height
    required = (pixel_count * bpp + 7) // 8
    if len(payload) < required:
        raise ValueError(f'Need {required} bytes for {width}x{height} at {bpp}bpp, got {len(payload)}')
    rgba = bytearray()
    if bpp == 4:
        values = []
        for byte in payload[:required]:
            high, low = byte >> 4, byte & 0x0F
            values.extend((high, low) if nibble_order == 'high-first' else (low, high))
        for value in values[:pixel_count]:
            shade = value * 17
            rgba.extend((shade, shade, shade, 0 if value == 0 else 255))
    elif bpp == 8:
        for value in payload[:pixel_count]:
            rgba.extend((value, value, value, 0 if value == 0 else 255))
    else:
        for offset in range(0, pixel_count * 2, 2):
            value = int.from_bytes(payload[offset:offset + 2], 'big')
            red = ((value >> 10) & 0x1F) * 255 // 31
            green = ((value >> 5) & 0x1F) * 255 // 31
            blue = (value & 0x1F) * 255 // 31
            rgba.extend((red, green, blue, 0 if value == 0 else 255))
    return bytes(rgba)


def _chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack('>I', len(data)) + body + struct.pack('>I', zlib.crc32(body) & 0xFFFFFFFF)


def encode_png(width: int, height: int, rgba: bytes) -> bytes:
    """Write an RGBA PNG using only the Python standard library."""
    if width <= 0 or height <= 0 or len(rgba) != width * height * 4:
        raise ValueError('RGBA byte count must equal width * height * 4')
    stride = width * 4
    scanlines = b''.join(b'\x00' + rgba[row * stride:(row + 1) * stride] for row in range(height))
    ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    return PNG_SIGNATURE + _chunk(b'IHDR', ihdr) + _chunk(b'IDAT', zlib.compress(scanlines, 9)) + _chunk(b'IEND', b'')


def nearest_neighbor_scale(rgba: bytes, width: int, height: int, scale: int) -> tuple[int, int, bytes]:
    if scale < 1:
        raise ValueError('scale must be at least 1')
    if scale == 1:
        return width, height, rgba
    out_width, out_height = width * scale, height * scale
    out = bytearray(out_width * out_height * 4)
    for y in range(out_height):
        source_y = y // scale
        for x in range(out_width):
            source_x = x // scale
            src = (source_y * width + source_x) * 4
            dst = (y * out_width + x) * 4
            out[dst:dst + 4] = rgba[src:src + 4]
    return out_width, out_height, bytes(out)


def texture_candidate(image: Path, container_path: str, element_index: int) -> tuple[bytes, dict]:
    """Return bytes until the next referenced texture offset and metadata only."""
    disc = inventory(image)
    target = '/' + container_path.lstrip('/').upper()
    entry = next((item for item in disc['game_files'] if item['path'].upper() == target), None)
    if entry is None:
        raise ValueError(f'Container not found in ISO: {container_path}')
    if entry['size_bytes'] > MAX_PROBE_BYTES:
        raise ValueError('Container exceeds the safe probe size')
    with image.open('rb') as stream:
        stream.seek(entry['extent_sector'] * SECTOR)
        data = stream.read(entry['size_bytes'])
    if len(data) != entry['size_bytes']:
        raise ValueError('Short read from ISO extent')
    layout = offsets_layout(data)
    if layout is None:
        raise ValueError('Container does not match the known three-section layout')
    base = layout['table_offset']
    bounds = [base + value for value in layout['relative_offsets']] + [len(data)]
    sections = [data[left:right] for left, right in zip(bounds, bounds[1:])]
    items, _, strict = valid_eight_byte_items(sections[0])
    if not strict:
        raise ValueError('Container does not pass the strict Stage04 record grammar')
    if element_index < 0 or element_index >= len(items):
        raise ValueError(f'element index must be in 0..{len(items)-1}')
    raw_pointer = int.from_bytes(items[element_index][:2], 'big')
    if raw_pointer == 0:
        raise ValueError('Selected element has a null texture-address candidate')
    section = sections[2]
    offset = raw_pointer * 8
    pointers = sorted(set(int.from_bytes(item[:2], 'big') * 8 for item in items if int.from_bytes(item[:2], 'big')))
    next_offsets = [value for value in pointers if value > offset]
    end = next_offsets[0] if next_offsets else len(section)
    if offset >= len(section) or end <= offset:
        raise ValueError('Texture-address candidate is outside the third section')
    payload = section[offset:end]
    return payload, {
        'container': entry['path'],
        'element_index': element_index,
        'candidate_offset_bytes': offset,
        'candidate_available_bytes': len(payload),
        'next_referenced_offset_bytes': end if next_offsets else None,
        'section3_size_bytes': len(section),
        'format_confirmed': False,
        'note': 'candidate block only; next referenced address is not proof of image extent',
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path, help='Private local Saturn ISO')
    parser.add_argument('--container', default='P0.BIN', help='Resource container, e.g. P0.BIN')
    parser.add_argument('--element', type=int, default=0, help='Eight-byte element index')
    parser.add_argument('--bpp', type=int, choices=(4, 8, 16), required=True, help='Candidate pixel depth')
    parser.add_argument('--width', type=int, required=True, help='Candidate width in pixels; Saturn VDP1 widths are normally multiples of 8')
    parser.add_argument('--height', type=int, help='Candidate height; if omitted, infer from the candidate block length')
    parser.add_argument('--nibble-order', choices=('high-first', 'low-first'), default='high-first')
    parser.add_argument('--scale', type=int, default=4, help='Nearest-neighbor display scale')
    parser.add_argument('-o', '--output', type=Path, required=True, help='Local PNG output path; do not commit the image')
    args = parser.parse_args()
    if args.width % 8:
        raise SystemExit('Candidate VDP1 width must be a multiple of 8 pixels')
    payload, metadata = texture_candidate(args.image, args.container, args.element)
    if args.height is None:
        bits = len(payload) * 8
        pixels = bits // args.bpp
        if bits % args.bpp or pixels % args.width:
            raise SystemExit('Candidate block length does not yield an exact height; specify --height to preview a prefix')
        height = pixels // args.width
    else:
        height = args.height
    rgba = decode_rgba(payload, args.width, height, args.bpp, args.nibble_order)
    out_width, out_height, scaled = nearest_neighbor_scale(rgba, args.width, height, args.scale)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encode_png(out_width, out_height, scaled))
    print('Candidate preview saved locally:', args.output)
    print(f'Assumption: {args.bpp}bpp, {args.width}x{height}, nibble order {args.nibble_order}, scale {args.scale}x')
    print(f"Candidate block: {metadata['candidate_available_bytes']} bytes at local section offset {metadata['candidate_offset_bytes']}; format unconfirmed")


if __name__ == '__main__':
    main()
