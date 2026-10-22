"""Synthetic tests for the public NRO container-header validator."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from verify_nro_header import NRO_HEADER_OFFSET, NRO_MIN_SIZE, validate_nro_bytes


def make_nro(file_size=0x100, declared_size=None, magic=b"NRO0"):
    data = bytearray(file_size)
    data[NRO_HEADER_OFFSET:NRO_HEADER_OFFSET + 4] = magic
    size = file_size if declared_size is None else declared_size
    struct.pack_into("<III", data, NRO_HEADER_OFFSET + 4, 0, size, 0)
    return bytes(data)


class NroHeaderValidationTests(unittest.TestCase):
    def test_valid_header(self):
        result = validate_nro_bytes(make_nro())
        self.assertEqual(result["magic"], "NRO0")
        self.assertEqual(result["declared_size"], 0x100)
        self.assertEqual(result["file_size"], 0x100)

    def test_rejects_truncated_header(self):
        with self.assertRaisesRegex(ValueError, "too short"):
            validate_nro_bytes(bytes(NRO_MIN_SIZE - 1))

    def test_rejects_wrong_magic(self):
        with self.assertRaisesRegex(ValueError, "invalid NRO magic"):
            validate_nro_bytes(make_nro(magic=b"ELF!"))

    def test_rejects_size_smaller_than_header(self):
        with self.assertRaisesRegex(ValueError, "smaller than its header"):
            validate_nro_bytes(make_nro(declared_size=NRO_MIN_SIZE - 1))

    def test_rejects_size_beyond_file(self):
        with self.assertRaisesRegex(ValueError, "exceeds file length"):
            validate_nro_bytes(make_nro(file_size=0x100, declared_size=0x200))


if __name__ == "__main__":
    unittest.main()
