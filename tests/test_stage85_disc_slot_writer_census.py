import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage85_disc_slot_writer_census import (
    MAX_FILE_SIZE,
    SECTOR,
    SERVICE_SLOT_A,
    SERVICE_SLOT_B,
    read_small_root_files,
    summarize_payload,
)


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | delta // 4)
    put32(data, literal_pos, value)


def record(name, extent, size, flags=0):
    name = name if isinstance(name, bytes) else name.encode()
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    out = bytearray(length)
    out[0] = length
    out[2:6] = extent.to_bytes(4, "little")
    out[6:10] = extent.to_bytes(4, "big")
    out[10:14] = size.to_bytes(4, "little")
    out[14:18] = size.to_bytes(4, "big")
    out[25] = flags
    out[28:30] = (1).to_bytes(2, "little")
    out[30:32] = (1).to_bytes(2, "big")
    out[32] = len(name)
    out[33:33 + len(name)] = name
    return bytes(out)


def synthetic_iso(file_size=8):
    image = bytearray(24 * SECTOR)
    pvd = 16 * SECTOR
    image[pvd:pvd + 7] = b"\x01CD001\x01"
    root_rec = record(b"\x00", 20, SECTOR, 2)
    image[pvd + 156:pvd + 156 + len(root_rec)] = root_rec
    directory = bytearray(SECTOR)
    dot = record(b"\x00", 20, SECTOR, 2)
    dotdot = record(b"\x01", 20, SECTOR, 2)
    file_rec = record(b"TEST.BIN;1", 21, file_size, 0)
    offset = 0
    for item in (dot, dotdot, file_rec):
        directory[offset:offset + len(item)] = item
        offset += len(item)
    image[20 * SECTOR:21 * SECTOR] = directory
    if file_size <= SECTOR:
        image[21 * SECTOR:21 * SECTOR + file_size] = b"X" * file_size
    return bytes(image)


class Stage85DiscSlotWriterTests(unittest.TestCase):
    def test_slot_a_literal_and_direct_store_candidate(self):
        data = bytearray(0x240)
        literal_load(data, 0x20, 2, 0x180, SERVICE_SLOT_A)
        put16(data, 0x22, 0x2231)  # MOV.W R3,@R2
        result = summarize_payload(data)
        self.assertEqual(result["slot_a_pc_literal_load_sites"], 1)
        self.assertEqual(result["slot_a_bounded_store_candidates"], 1)
        self.assertEqual(result["slot_b_pc_literal_load_sites"], 0)

    def test_slot_b_literal_is_counted_separately(self):
        data = bytearray(0x240)
        literal_load(data, 0x20, 3, 0x180, SERVICE_SLOT_B)
        put16(data, 0x22, 0x2331)  # MOV.W R3,@R3
        result = summarize_payload(data)
        self.assertEqual(result["slot_b_pc_literal_load_sites"], 1)
        self.assertEqual(result["slot_a_pc_literal_load_sites"], 0)

    def test_raw_odd_slot_match_is_not_aligned_pointer(self):
        data = bytearray(0x240)
        data[0x21:0x25] = SERVICE_SLOT_A.to_bytes(4, "big")
        result = summarize_payload(data)
        self.assertEqual(result["slot_a_raw_occurrences"]["raw_big_endian_occurrences"], 1)
        self.assertEqual(result["slot_a_raw_occurrences"]["occurrences_aligned_to_halfword"], 0)
        self.assertEqual(result["slot_a_raw_occurrences"]["occurrences_aligned_to_longword"], 0)

    def test_aligned_raw_match_is_not_registration_proof(self):
        data = bytearray(0x240)
        put32(data, 0x180, SERVICE_SLOT_A)
        result = summarize_payload(data)
        self.assertEqual(result["slot_a_raw_occurrences"]["occurrences_aligned_to_longword"], 1)
        self.assertFalse(result["all_slot_writers_resolved"])

    def test_no_references_returns_zero_counts(self):
        result = summarize_payload(bytearray(0x240))
        self.assertEqual(result["slot_a_pc_literal_load_sites"], 0)
        self.assertEqual(result["slot_b_pc_literal_load_sites"], 0)
        self.assertEqual(result["slot_a_bounded_store_candidates"], 0)
        self.assertEqual(result["slot_b_bounded_store_candidates"], 0)

    def test_root_directory_reader_loads_small_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.iso"
            path.write_bytes(synthetic_iso(8))
            result = read_small_root_files(path)
        self.assertEqual(result["root_file_count_scanned"], 1)
        self.assertEqual(result["files"]["TEST.BIN"], b"X" * 8)
        self.assertEqual(result["root_files_skipped_oversize"], 0)

    def test_root_directory_reader_skips_oversize_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.iso"
            path.write_bytes(synthetic_iso(MAX_FILE_SIZE + 1))
            result = read_small_root_files(path)
        self.assertEqual(result["root_file_count_scanned"], 0)
        self.assertEqual(result["root_files_skipped_oversize"], 1)

    def test_invalid_iso_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.iso"
            path.write_bytes(b"not an ISO" + bytes(40 * SECTOR))
            with self.assertRaises(ValueError):
                read_small_root_files(path)

    def test_output_redacts_address_values(self):
        result = summarize_payload(bytearray(0x240))
        rendered = json.dumps(result)
        self.assertNotIn(hex(SERVICE_SLOT_A), rendered)
        self.assertNotIn(hex(SERVICE_SLOT_B), rendered)

    def test_raw_literal_pool_word_is_distinguished(self):
        data = bytearray(0x240)
        literal_load(data, 0x20, 2, 0x180, SERVICE_SLOT_A)
        result = summarize_payload(data)
        self.assertEqual(
            result["slot_a_raw_occurrences"]["occurrences_used_as_pc_literal_pool_words"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
