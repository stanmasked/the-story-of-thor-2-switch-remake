"""Stage54 tests: synthetic Saturn ISO and no private original/BIOS assets."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage51_saturn_boot_first_read_map import image as synthetic_image
from stage54_saturn_iso_cue_bios_preflight import (
    SECTOR, CUE_SUFFIX, BIOS_BYTES, KNOWN_BIOS,
    disc_preflight, make_cue, check_bios, check_emulator,
    write_private_cue, run_private,
)


def fixture(region="E"):
    data = bytearray(synthetic_image())
    data[0x40:0x50] = region.encode("ascii").ljust(16, b" ")
    return bytes(data)


class Stage54CueAndFirmwareTests(unittest.TestCase):
    def test_synthetic_european_disc(self):
        r = disc_preflight(fixture("E"))
        self.assertEqual(r["region"], "E")
        self.assertTrue(r["stage51_first_read_mapping_verified"])

    def test_synthetic_japanese_disc(self):
        self.assertEqual(disc_preflight(fixture("J"))["region"], "J")

    def test_2048_sector_count(self):
        r = disc_preflight(fixture())
        self.assertEqual(r["sectors"] * SECTOR, len(fixture()))

    def test_raw_subchannels_not_reconstructed(self):
        r = disc_preflight(fixture())
        self.assertFalse(r["raw_cd_subchannels_available"])
        self.assertFalse(r["original_audio_track_layout_verified"])

    def test_mode1_2048_cue(self):
        self.assertEqual(make_cue("The Story of Thor 2.iso"),
                         'FILE "The Story of Thor 2.iso" BINARY\n'
                         '  TRACK 01 MODE1/2048\n'
                         '    INDEX 01 00:00:00\n')

    def test_track_is_not_lied_about_as_2352(self):
        self.assertNotIn("MODE1/2352", make_cue("test.iso"))

    def test_cue_file_uses_relative_basename(self):
        self.assertEqual(make_cue("local.iso").splitlines()[0],
                         'FILE "local.iso" BINARY')

    def test_reject_absolute_path(self):
        for v in ("/tmp/test.iso", "C:\\test.iso", "../test.iso"):
            with self.subTest(value=v), self.assertRaises(ValueError):
                make_cue(v)

    def test_reject_quote_injection(self):
        with self.assertRaises(ValueError):
            make_cue('evil.iso"\n  TRACK 02 AUDIO')

    def test_reject_untrusted_newline(self):
        with self.assertRaises(ValueError):
            make_cue("evil\n.bin.iso")

    def test_reject_missing_extension(self):
        with self.assertRaises(ValueError):
            make_cue("saturn.bin")

    def test_reject_nonascii_filename(self):
        with self.assertRaises(ValueError):
            make_cue("игра.iso")

    def test_reject_bytearray_disc(self):
        with self.assertRaises(ValueError):
            disc_preflight(bytearray(fixture()))

    def test_reject_incorrect_sector_boundary(self):
        with self.assertRaises(ValueError):
            disc_preflight(fixture() + b"\x00")

    def test_reject_unknown_disc_region(self):
        for region in ("X", "", "EJ"):
            with self.subTest(region=region), self.assertRaises(ValueError):
                disc_preflight(fixture(region))

    def test_reject_invalid_saturn_header(self):
        raw = bytearray(fixture())
        raw[0] = ord("Z")
        with self.assertRaises(ValueError):
            disc_preflight(bytes(raw))

    def test_european_bios_filename(self):
        r = check_bios("E", None)
        self.assertEqual(r["known_region_firmware_expected"], "mpr-17933.bin")
        self.assertFalse(r["private_bios_matches_official_mednafen_reference"])

    def test_japanese_bios_filename(self):
        r = check_bios("J", None)
        self.assertEqual(r["known_region_firmware_expected"], "sega_101.bin")

    def test_declared_official_firmware_hashes(self):
        self.assertEqual(KNOWN_BIOS["E"][1],
                         "96e106f740ab448cf89f0dd49dfbac7fe5391cb6bd6e14ad5e3061c13330266f")
        self.assertEqual(KNOWN_BIOS["J"][1],
                         "dcfef4b99605f872b6c3b6d05c045385cdea3d1b702906a0ed930df7bcb7deac")

    def test_fake_bios_hash_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "mpr-17933.bin"
            path.write_bytes(bytes(BIOS_BYTES))
            with self.assertRaises(ValueError):
                check_bios("E", path)

    def test_wrong_bios_size_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "sega_101.bin"
            path.write_bytes(b"0")
            with self.assertRaises(ValueError):
                check_bios("J", path)

    def test_no_emulator_is_explicit(self):
        self.assertFalse(check_emulator(None)["emulator_binary_executable"])

    def test_unexecutable_emulator_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "mednafen"
            path.write_bytes(b"!" * 8192)
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                check_emulator(path)

    def test_oversmall_executable_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "mednafen"
            path.write_bytes(b"tiny")
            path.chmod(0o700)
            with self.assertRaises(ValueError):
                check_emulator(path)

    def test_private_cue_permissions_and_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            iso = root / "fake.iso"
            iso.write_bytes(fixture())
            cue = root / "fake.private-mode1.cue"
            write_private_cue(cue, iso, make_cue(iso.name))
            self.assertEqual(stat.S_IMODE(cue.stat().st_mode), 0o600)
            self.assertEqual(cue.read_text(), make_cue(iso.name))

    def test_private_cue_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            iso = root / "test.iso"
            iso.write_bytes(fixture())
            cue = root / "test.private-mode1.cue"
            cue.write_text("do not change", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_private_cue(cue, iso, make_cue(iso.name))
            self.assertEqual(cue.read_text(), "do not change")

    def test_private_cue_rejects_different_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            iso = root / "test.iso"
            iso.write_bytes(fixture())
            out = root / "separate"
            out.mkdir()
            with self.assertRaises(ValueError):
                write_private_cue(out / "test.cue", iso, make_cue(iso.name))

    def test_private_cue_refuses_symlink(self):
        if os.name == "nt":
            self.skipTest("POSIX symlink permissions")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            iso = root / "test.iso"
            iso.write_bytes(fixture())
            target = root / "target"
            target.write_text("keep", encoding="ascii")
            cue = root / "test.cue"
            cue.symlink_to(target)
            with self.assertRaises(OSError):
                write_private_cue(cue, iso, make_cue(iso.name))
            self.assertEqual(target.read_text(), "keep")

    def test_private_wrong_disc_sha_rejected_without_writing_cue(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            iso = root / "not-original.iso"
            iso.write_bytes(fixture())
            cue = root / "not-original.private-mode1.cue"
            with self.assertRaises(ValueError):
                run_private(iso, cue)
            self.assertFalse(cue.exists())


if __name__ == "__main__":
    unittest.main()
