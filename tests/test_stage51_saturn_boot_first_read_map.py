"""Stage51 synthetic Saturn IP/ISO9660 mapping tests; no original game data."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage46_vdp1_submit_gate import fixture as code_fixture
from stage51_saturn_boot_first_read_map import (
    SECTOR, RAM_BASE, SH2_LOAD_BASE, _entry_at,
    _root_entries, verify_boot_layout, analyze_private,
)

SYNTHETIC_PROGRAM = code_fixture()


def entry(name: bytes, extent: int, length: int, flags: int = 0) -> bytes:
    padding = (1 if len(name) % 2 == 0 else 0)
    rec = bytearray(33 + len(name) + padding)
    rec[0] = len(rec)
    rec[2:6] = extent.to_bytes(4, "little")
    rec[6:10] = extent.to_bytes(4, "big")
    rec[10:14] = length.to_bytes(4, "little")
    rec[14:18] = length.to_bytes(4, "big")
    rec[25] = flags
    rec[28:30] = (1).to_bytes(2, "little")
    rec[30:32] = (1).to_bytes(2, "big")
    rec[32] = len(name)
    rec[33:33+len(name)] = name
    return bytes(rec)


def image(first_name=b"0TH2.BIN;1", first_addr=SH2_LOAD_BASE,
          ip_size=0x1000, program=SYNTHETIC_PROGRAM, extra=False):
    sectors = 24 + (len(program) + SECTOR - 1)//SECTOR + 2
    raw = bytearray(sectors * SECTOR)
    raw[:16] = b"SEGA SEGASATURN "
    raw[0xE0:0xE4] = ip_size.to_bytes(4, "big")
    raw[0xF0:0xF4] = first_addr.to_bytes(4, "big")
    pvd = bytearray(SECTOR)
    pvd[:7] = b"\x01CD001\x01"
    pvd[156:190] = entry(b"\x00", 23, SECTOR, 2)
    raw[16*SECTOR:17*SECTOR] = pvd
    contents = entry(b"\x00", 23, SECTOR, 2)+entry(b"\x01", 23, SECTOR, 2)
    contents += entry(first_name, 24, len(program))
    if extra:
        contents += entry(b"OTHER.BIN;1", 25+(len(program)+SECTOR-1)//SECTOR, 0)
    raw[23*SECTOR:23*SECTOR+len(contents)] = contents
    raw[24*SECTOR:24*SECTOR+len(program)] = program
    return bytes(raw)


class Stage51BootTests(unittest.TestCase):
    def test_valid_declared_first_read(self):
        r = verify_boot_layout(image())
        self.assertTrue(r["independent_boot_metadata_supports_static_load_base"])
        self.assertTrue(r["iso9660_first_program_is_0th2_bin"])

    def test_twelve_stage45_46_private_roles(self):
        self.assertEqual(verify_boot_layout(image())["stage45_46_private_static_role_count"], 12)

    def test_abstract_output_has_no_game_code_or_offsets(self):
        out = json.dumps(verify_boot_layout(image()))
        for word in ('"pc"', '"offset"', '"extent"', '"source_bytes"', '"raw_code"'):
            self.assertNotIn(word, out)

    def test_declared_transfer_is_not_execution(self):
        r = verify_boot_layout(image())
        self.assertFalse(r["actual_bootrom_file_transfer_observed"])
        self.assertFalse(r["actual_sh2_execution_observed"])
        self.assertFalse(r["emulator_origin_authenticated"])

    def test_declared_ip_size(self):
        self.assertEqual(verify_boot_layout(image())["ip_program_size_bytes"], 0x1000)

    def test_declared_1st_read_size_ignored_for_cd(self):
        r = bytearray(image())
        r[0xF4:0xF8] = (256).to_bytes(4, "big")
        self.assertTrue(verify_boot_layout(bytes(r))["first_read_transfer_size_field_ignored_for_cd"])

    def test_bad_ip_signature(self):
        data = bytearray(image())
        data[0] ^= 1
        with self.assertRaises(ValueError):
            verify_boot_layout(bytes(data))

    def test_bad_pvd(self):
        data = bytearray(image())
        data[16*SECTOR+1] = 0
        with self.assertRaises(ValueError):
            verify_boot_layout(bytes(data))

    def test_bad_first_file_name(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(first_name=b"WRONG.BIN;1"))

    def test_unexpected_declared_first_read_address(self):
        r = verify_boot_layout(image(first_addr=SH2_LOAD_BASE+0x1000))
        self.assertFalse(r["first_read_address_equals_stage49_assumption"])
        self.assertFalse(r["independent_boot_metadata_supports_static_load_base"])

    def test_zero_first_read_rejected(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(first_addr=0))

    def test_unaligned_first_read_rejected(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(first_addr=SH2_LOAD_BASE+1))

    def test_outside_high_ram_rejected(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(first_addr=0x07000000))

    def test_boot_program_overlaps_ip(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(ip_size=0x4000))

    def test_ip_size_too_small(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(ip_size=0x0FFC))

    def test_ip_size_too_big(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(ip_size=0x9000))

    def test_ip_size_not_aligned(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(ip_size=0x1001))

    def test_transfer_over_system_reserved_tail_rejected(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(first_addr=RAM_BASE+0xFEE00))

    def test_first_program_not_sh2_static_pair_rejected(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image(program=bytes(len(SYNTHETIC_PROGRAM))))

    def test_root_records_little_and_big_endian_disagreement(self):
        r = bytearray(image())
        directory = 23*SECTOR
        first = len(entry(b"\x00", 23, SECTOR, 2))+len(entry(b"\x01", 23, SECTOR, 2))
        r[directory+first+6] ^= 1
        with self.assertRaises(ValueError):
            verify_boot_layout(bytes(r))

    def test_truncated_image(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(image()[:24*SECTOR])

    def test_root_entries_present_in_expected_order(self):
        raw = image(extra=True)
        entries = _root_entries(raw, raw[16*SECTOR:17*SECTOR])
        self.assertEqual(entries[2]["id"], b"0TH2.BIN")
        self.assertEqual(entries[3]["id"], b"OTHER.BIN")

    def test_same_name_but_file_identifier_not_first(self):
        raw = bytearray(image())
        d = 23*SECTOR
        first_offset = len(entry(b"\x00", 23, SECTOR, 2))+len(entry(b"\x01", 23, SECTOR, 2))
        raw[d+first_offset+33] = ord("Z")
        with self.assertRaises(ValueError):
            verify_boot_layout(bytes(raw))

    def test_bad_iso_record_name_truncated(self):
        with self.assertRaises(ValueError):
            _entry_at(b"\x22" + bytes(32) + b"NO")

    def test_not_byte_input(self):
        with self.assertRaises(ValueError):
            verify_boot_layout(bytearray(image()))

    def test_hash_pinning_blocks_any_synthetic_disc(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/"stage51_fake.iso"
            p.write_bytes(image())
            with self.assertRaises(ValueError):
                analyze_private(p)

    def test_fid_special_records_missing(self):
        raw = bytearray(image())
        raw[23*SECTOR+33] = ord("X")
        with self.assertRaises(ValueError):
            verify_boot_layout(bytes(raw))

    def test_first_read_fits_high_work_ram(self):
        r = verify_boot_layout(image())
        self.assertTrue(r["first_read_mapping_fits_high_work_ram"])
        self.assertFalse(r["first_read_mapping_crosses_reserved_system_tail"])


if __name__ == "__main__":
    unittest.main()
