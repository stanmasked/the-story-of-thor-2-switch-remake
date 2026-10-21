"""Stage08 pixel decoder and PNG writer tests use synthetic bytes only."""
import struct
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from stage08_texture_preview import decode_rgba, encode_png, nearest_neighbor_scale


class Stage08TexturePreviewTests(unittest.TestCase):
    def test_4bpp_high_nibble_first(self):
        rgba = decode_rgba(bytes((0x12, 0x30, 0x45, 0x67)), 8, 1, 4, 'high-first')
        self.assertEqual(len(rgba), 8 * 4)
        self.assertEqual(rgba[0:4], bytes((17, 17, 17, 255)))
        self.assertEqual(rgba[4:8], bytes((34, 34, 34, 255)))
        self.assertEqual(rgba[12:16], bytes((0, 0, 0, 0)))

    def test_4bpp_low_nibble_first(self):
        rgba = decode_rgba(bytes((0x12, 0x30, 0x45, 0x67)), 8, 1, 4, 'low-first')
        self.assertEqual(rgba[0:4], bytes((34, 34, 34, 255)))
        self.assertEqual(rgba[4:8], bytes((17, 17, 17, 255)))

    def test_8bpp_debug_grayscale(self):
        rgba = decode_rgba(bytes((0, 128, 255)), 3, 1, 8)
        self.assertEqual(rgba[0:4], bytes((0, 0, 0, 0)))
        self.assertEqual(rgba[4:8], bytes((128, 128, 128, 255)))
        self.assertEqual(rgba[8:12], bytes((255, 255, 255, 255)))

    def test_16bpp_rgb555(self):
        payload = b'\x7f\xff' + bytes(14)
        rgba = decode_rgba(payload, 8, 1, 16)
        self.assertEqual(rgba[0:4], bytes((255, 255, 255, 255)))
        self.assertEqual(rgba[4:8], bytes((0, 0, 0, 0)))

    def test_rejects_invalid_bpp(self):
        with self.assertRaises(ValueError):
            decode_rgba(bytes(8), 8, 1, 2)

    def test_rejects_short_payload(self):
        with self.assertRaises(ValueError):
            decode_rgba(bytes(2), 8, 1, 4)

    def test_rejects_invalid_nibble_order(self):
        with self.assertRaises(ValueError):
            decode_rgba(bytes(4), 8, 1, 4, 'middle-first')

    def test_nearest_neighbor_scale(self):
        source = bytes((1, 2, 3, 4, 5, 6, 7, 8))
        width, height, scaled = nearest_neighbor_scale(source, 2, 1, 2)
        self.assertEqual((width, height), (4, 2))
        row = bytes((1,2,3,4,1,2,3,4,5,6,7,8,5,6,7,8))
        self.assertEqual(scaled, row + row)

    def test_png_signature_and_dimensions(self):
        png = encode_png(1, 1, bytes((10, 20, 30, 255)))
        self.assertTrue(png.startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertEqual(png[12:16], b'IHDR')
        self.assertEqual(struct.unpack('>II', png[16:24]), (1, 1))

    def test_png_idat_roundtrip(self):
        rgba = bytes((10, 20, 30, 255, 40, 50, 60, 128))
        png = encode_png(2, 1, rgba)
        pos = 8
        idat = bytearray()
        while pos < len(png):
            length = struct.unpack('>I', png[pos:pos + 4])[0]
            kind = png[pos + 4:pos + 8]
            data = png[pos + 8:pos + 8 + length]
            if kind == b'IDAT':
                idat.extend(data)
            pos += 12 + length
        self.assertEqual(zlib.decompress(bytes(idat)), b'\x00' + rgba)


if __name__ == '__main__':
    unittest.main()
