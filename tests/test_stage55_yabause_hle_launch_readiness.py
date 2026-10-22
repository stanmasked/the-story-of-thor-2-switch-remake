"""Stage55 synthetic-only checks for the Yabause HLE BIOS-free launch path."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage54_saturn_iso_cue_bios_preflight import fixture as synthetic_iso
from stage50_sh2_load_mapping_evidence import REFERENCE_ISO_SHA256
from stage55_yabause_hle_launch_readiness import (
    SOURCE_LIBRETRO, SOURCE_CLI, ELF, validate_binary, safe_local_path,
    readiness, create_private_file, run_private,
)

MOD = "stage55_yabause_hle_launch_readiness"


def elf_file(path, executable=True, valid=True):
    path.write_bytes(
        (ELF + bytes([2, 1]) + bytes(58) if valid else b"NOPE" + bytes(60))
        + bytes(4096))
    path.chmod(0o700 if executable else 0o600)
    return path


class Stage55HLETests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.iso = self.root / "The Story of Thor 2.iso"
        self.iso.write_bytes(synthetic_iso("E"))
        self.ra = elf_file(self.root / "retroarch")
        self.core = elf_file(self.root / "yabause_libretro.so")

    def analyze(self, ra=True, core=True, display=False):
        with patch(MOD + "._iso_sha256", return_value=REFERENCE_ISO_SHA256):
            return readiness(self.iso, self.ra if ra else None,
                             self.core if core else None,
                             display_available=display)

    def test_original_synthetic_disc_boot_layout_preserved(self):
        pub, _ = self.analyze()
        self.assertEqual(pub["original_iso_region"], "E")
        self.assertTrue(pub["disc_iso9660_and_boot_layout_valid"])

    def test_iso_direct_core_avoids_provisional_cue(self):
        pub, private = self.analyze()
        self.assertFalse(pub["single_track_cue_required_for_yabause_libretro_iso"])
        self.assertEqual(private["launch_argv_if_host_binaries_pass"][-1], str(self.iso))

    def test_hle_bios_path_requires_no_external_firmware(self):
        pub, private = self.analyze()
        self.assertFalse(pub["external_original_saturn_bios_required_for_this_path"])
        self.assertFalse(private["requires_original_bios"])
        self.assertIn("enabled", private["yabause_core_setting"])

    def test_private_command_is_argv_not_shell(self):
        _, private = self.analyze()
        self.assertEqual(private["launch_argv_if_host_binaries_pass"],
                         [str(self.ra), "-L", str(self.core), str(self.iso)])

    def test_frontend_not_supplied(self):
        pub, private = self.analyze(ra=False)
        self.assertFalse(pub["retroarch_binary_supplied"])
        self.assertFalse(pub["host_executable_prerequisites_present"])
        self.assertIsNone(private["launch_argv_if_host_binaries_pass"])

    def test_core_not_supplied(self):
        pub, private = self.analyze(core=False)
        self.assertFalse(pub["yabause_libretro_core_supplied"])
        self.assertFalse(pub["host_executable_prerequisites_present"])
        self.assertIsNone(private["launch_argv_if_host_binaries_pass"])

    def test_neither_binary_present(self):
        pub, private = self.analyze(ra=False, core=False)
        self.assertFalse(pub["host_executable_prerequisites_present"])
        self.assertIsNone(private["launch_argv_if_host_binaries_pass"])

    def test_binary_checks_do_not_attest_running_emulator(self):
        pub, _ = self.analyze()
        self.assertTrue(pub["host_executable_prerequisites_present"])
        self.assertFalse(pub["actual_emulator_process_started"])
        self.assertFalse(pub["saturn_game_booted"])

    def test_display_no_does_not_falsify_host_binaries(self):
        pub, _ = self.analyze(display=False)
        self.assertFalse(pub["host_display_declared_available"])
        self.assertTrue(pub["host_executable_prerequisites_present"])

    def test_display_yes_does_not_prove_boot(self):
        pub, _ = self.analyze(display=True)
        self.assertTrue(pub["host_display_declared_available"])
        self.assertFalse(pub["saturn_game_booted"])

    def test_external_original_iso_sha_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            readiness(self.iso, self.ra, self.core)

    def test_original_file_symlink_rejected(self):
        link = self.root / "link.iso"
        link.symlink_to(self.iso)
        with self.assertRaises(ValueError):
            readiness(link, self.ra, self.core)

    def test_invalid_original_iso_structure_rejected(self):
        self.iso.write_bytes(b"bad")
        with patch(MOD + "._iso_sha256", return_value=REFERENCE_ISO_SHA256):
            with self.assertRaises(ValueError):
                readiness(self.iso, self.ra, self.core)

    def test_bad_frontend_elf_rejected(self):
        elf_file(self.ra, valid=False)
        pub, private = self.analyze()
        self.assertFalse(pub["retroarch_elf_header_and_exec_permission_pass"])
        self.assertIsNone(private["launch_argv_if_host_binaries_pass"])

    def test_bad_core_elf_rejected(self):
        elf_file(self.core, valid=False)
        pub, private = self.analyze()
        self.assertFalse(pub["yabause_core_elf_header_pass"])
        self.assertIsNone(private["launch_argv_if_host_binaries_pass"])

    def test_frontend_permission_rejected(self):
        self.ra.chmod(0o600)
        pub, _ = self.analyze()
        self.assertFalse(pub["retroarch_elf_header_and_exec_permission_pass"])

    def test_core_permission_not_required_for_shared_object(self):
        self.core.chmod(0o600)
        pub, _ = self.analyze()
        self.assertTrue(pub["yabause_core_elf_header_pass"])

    def test_binary_below_minimum_size_rejected(self):
        small = self.root / "small"
        small.write_bytes(ELF + bytes(200))
        with self.assertRaises(ValueError):
            validate_binary(small, executable=True)

    def test_symlinked_binary_rejected(self):
        link = self.root / "retroarch_symlink"
        link.symlink_to(self.ra)
        with self.assertRaises(ValueError):
            validate_binary(link, executable=True)

    def test_missing_binary_rejected(self):
        with self.assertRaises(ValueError):
            validate_binary(self.root / "missing", executable=True)

    def test_bad_type_binary_rejected(self):
        with self.assertRaises(ValueError):
            validate_binary("retroarch", executable=True)

    def test_path_quotes_rejected(self):
        with self.assertRaises(ValueError):
            safe_local_path(Path("bad\"file"))

    def test_path_newline_rejected(self):
        with self.assertRaises(ValueError):
            safe_local_path(Path("bad\nfile"))

    def test_path_backslash_rejected(self):
        with self.assertRaises(ValueError):
            safe_local_path(Path("bad\\path"))

    def test_safe_path_with_spaces(self):
        self.assertIn("Story of Thor", safe_local_path(self.iso))

    def test_nonboolean_display_rejected(self):
        with patch(MOD + "._iso_sha256", return_value=REFERENCE_ISO_SHA256):
            with self.assertRaises(ValueError):
                readiness(self.iso, self.ra, self.core, display_available="yes")

    def test_safe_stdout_no_private_paths(self):
        pub, private = self.analyze()
        encoded = json.dumps(pub)
        for raw in (str(self.iso), str(self.ra), str(self.core), str(self.root)):
            self.assertNotIn(raw, encoded)
        self.assertIn(str(self.iso), json.dumps(private))

    def test_safe_stdout_no_original_bios_or_ram(self):
        pub, _ = self.analyze()
        self.assertFalse(pub["original_ram_vram_trace_captured"])
        self.assertFalse(pub["saturn_game_booted"])

    def test_private_write_0600(self):
        _, plan = self.analyze()
        path = self.root / "stage55.private-yabause-launch.json"
        create_private_file(path, plan)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text())["schema_version"], 1)

    def test_private_no_overwrite(self):
        path = self.root / "existing.json"
        path.write_text("original")
        with self.assertRaises(FileExistsError):
            create_private_file(path, {})
        self.assertEqual(path.read_text(), "original")

    @unittest.skipIf(os.name == "nt", "symlink semantics on POSIX only")
    def test_private_no_symlink(self):
        target = self.root / "target.json"
        target.write_text("unchanged")
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            create_private_file(link, {})
        self.assertEqual(target.read_text(), "unchanged")

    def test_run_private_without_binaries_writes_no_command(self):
        path = self.root / "private.json"
        with patch(MOD + "._iso_sha256", return_value=REFERENCE_ISO_SHA256):
            pub = run_private(self.iso, path, None, None, False)
        self.assertTrue(pub["private_launch_command_written_by_helper"])
        self.assertFalse(pub["host_executable_prerequisites_present"])
        self.assertIsNone(json.loads(path.read_text())["launch_argv_if_host_binaries_pass"])

    def test_run_private_with_binaries_writes_arg_list(self):
        path = self.root / "private.json"
        with patch(MOD + "._iso_sha256", return_value=REFERENCE_ISO_SHA256):
            pub = run_private(self.iso, path, self.ra, self.core, True)
        self.assertTrue(pub["host_executable_prerequisites_present"])
        self.assertEqual(len(json.loads(path.read_text())["launch_argv_if_host_binaries_pass"]), 4)

    def test_official_reference_links(self):
        _, private = self.analyze()
        self.assertIn(SOURCE_LIBRETRO, private["sources"])
        self.assertIn(SOURCE_CLI, private["sources"])


if __name__ == "__main__":
    unittest.main()
