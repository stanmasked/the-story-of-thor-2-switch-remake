"""Stage53 ROM-free debugger watchlist tests; all SH-2 fixtures are synthetic."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from test_stage46_vdp1_submit_gate import fixture as synthetic_program
from stage46_vdp1_submit_gate import find_submit_gates
from stage49_sh2_vdp1_trace_contract import find_private_roles
from stage53_mednafen_private_capture_plan import (
    ROLE_LABELS, RAM_DUMP_BYTES, VDP1_DUMP_BYTES, REFERENCE_DOC,
    _hex, capture_plan, public_summary, write_plan_private, run_private,
)

PROGRAM = synthetic_program()


class Stage53MednafenPlanTests(unittest.TestCase):
    def plan(self):
        return capture_plan(PROGRAM)

    def test_unique_twelve_static_roles(self):
        self.assertEqual(len(self.plan()["sh2_pc_breakpoints_in_role_order"]), 12)

    def test_expected_role_names(self):
        self.assertEqual(tuple(x["role"] for x in self.plan()["sh2_pc_breakpoints_in_role_order"]),
                         ROLE_LABELS)

    def test_real_addresses_from_synthetic_code_not_hardcoded_watchlist(self):
        private = find_private_roles(PROGRAM)
        actual = [int(x["pc_hex"], 16)
                  for x in self.plan()["sh2_pc_breakpoints_in_role_order"]]
        expected = [private["gate"], private["jsr"], *private["stores"],
                    private["copy_rts"], private["submit_rts"]]
        self.assertEqual(actual, expected)

    def test_pc_values_are_unique(self):
        values = [x["pc_hex"] for x in self.plan()["sh2_pc_breakpoints_in_role_order"]]
        self.assertEqual(len(set(values)), len(values))

    def test_pc_hex_width(self):
        self.assertTrue(all(len(x["pc_hex"]) == 8
                            for x in self.plan()["sh2_pc_breakpoints_in_role_order"]))

    def test_private_status_global_resolved(self):
        gate = find_submit_gates(PROGRAM)[0]
        self.assertEqual(self.plan()["stage46_private_global_watch_addresses"][
            "signed_status_byte_hex"], f'{gate["status_address"]:08X}')

    def test_private_pending_count_resolved(self):
        gate = find_submit_gates(PROGRAM)[0]
        self.assertEqual(self.plan()["stage46_private_global_watch_addresses"][
            "pending_descriptor_count_u16_hex"], f'{gate["count_address"]:08X}')

    def test_private_buffer_pointer_resolved(self):
        gate = find_submit_gates(PROGRAM)[0]
        self.assertEqual(self.plan()["stage46_private_global_watch_addresses"][
            "descriptor_buffer_pointer_hex"], f'{gate["source_address"]:08X}')

    def test_private_committed_pointer_resolved(self):
        gate = find_submit_gates(PROGRAM)[0]
        self.assertEqual(self.plan()["stage46_private_global_watch_addresses"][
            "last_submitted_pointer_hex"], f'{gate["last_submitted_pointer_address"]:08X}')

    def test_ram_dump_exact_one_megabyte(self):
        r = self.plan()["dump_ranges"][0]
        self.assertEqual(int(r["byte_count_hex"], 16), RAM_DUMP_BYTES)
        self.assertEqual(int(r["start_hex"], 16), 0x06000000)

    def test_vram_dump_exact_512k(self):
        for r in self.plan()["dump_ranges"][1:]:
            self.assertEqual(int(r["byte_count_hex"], 16), VDP1_DUMP_BYTES)
            self.assertEqual(int(r["start_hex"], 16), 0x25C00000)

    def test_dump_recipe_hex_count(self):
        self.assertIn("+100000", self.plan()["dump_ranges"][0]["mednafen_memory_editor_D_example"])
        self.assertIn("+80000", self.plan()["dump_ranges"][1]["mednafen_memory_editor_D_example"])

    def test_documented_hotkey_for_memory_dump(self):
        p = self.plan()
        self.assertIn("D in memory editor", p["documented_mednafen_shortcuts"]["memory_dump"])

    def test_documented_cpu_breakpoint(self):
        p = self.plan()
        self.assertIn("SPACE", p["documented_mednafen_shortcuts"]["pc_breakpoint_toggle"])

    def test_uses_mednafen_official_debugger_documentation(self):
        self.assertEqual(self.plan()["debugger_manual"], REFERENCE_DOC)
        self.assertTrue(REFERENCE_DOC.startswith("https://mednafen.github.io/"))

    def test_private_plan_does_not_claim_emulator_execution(self):
        p = self.plan()
        for key in ("actual_emulator_run_performed", "high_ram_snapshot_captured",
                    "vdp1_snapshot_captured", "sh2_events_captured"):
            self.assertFalse(p[key])

    def test_private_plan_warns_about_memory_domain(self):
        self.assertTrue(any("memory domain" in x.lower()
                            for x in self.plan()["operator_checklist"]))

    def test_private_plan_explains_r2_r5(self):
        self.assertTrue(any("R2" in x and "R5" in x
                            for x in self.plan()["operator_checklist"]))

    def test_public_report_contains_counts_only(self):
        pub = public_summary(self.plan(), original_verified=True)
        self.assertEqual(pub["pc_breakpoint_roles_prepared"], 12)
        self.assertEqual(pub["private_global_watch_addresses_prepared"], 4)
        self.assertEqual(pub["dump_ranges_prepared"], 3)
        self.assertTrue(pub["original_disc_verified"])

    def test_public_report_no_private_pc_values(self):
        p = self.plan()
        pub = json.dumps(public_summary(p))
        for value in (x["pc_hex"] for x in p["sh2_pc_breakpoints_in_role_order"]):
            self.assertNotIn(value, pub)
        for value in p["stage46_private_global_watch_addresses"].values():
            self.assertNotIn(value, pub)

    def test_public_report_never_claims_runtime(self):
        pub = public_summary(self.plan(), original_verified=True)
        self.assertFalse(pub["actual_emulator_run_performed"])
        self.assertFalse(pub["verified_ram_or_vram_snapshot_available"])
        self.assertFalse(pub["sh2_execution_proven"])

    def test_bad_program_rejected(self):
        with self.assertRaises(ValueError):
            capture_plan(bytes(len(PROGRAM)))

    def test_private_plan_written_and_parsed(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "private_watchlist.json"
            write_plan_private(file, self.plan())
            parsed = json.loads(file.read_text(encoding="utf-8"))
            self.assertEqual(len(parsed["sh2_pc_breakpoints_in_role_order"]), 12)

    @unittest.skipIf(os.name == "nt", "POSIX permissions apply to private captures")
    def test_owner_only_file_mode(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "watchlist.json"
            write_plan_private(file, self.plan())
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)

    def test_refuses_existing_file(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "exists.json"
            file.write_text("untouched", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_plan_private(file, self.plan())
            self.assertEqual(file.read_text(encoding="utf-8"), "untouched")

    @unittest.skipIf(os.name == "nt", "symlink test requires POSIX")
    def test_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.json"
            target.write_text("do not replace", encoding="utf-8")
            link = Path(td) / "link.json"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                write_plan_private(link, self.plan())
            self.assertEqual(target.read_text(encoding="utf-8"), "do not replace")

    def test_private_iso_must_match_pinned_hash(self):
        with tempfile.TemporaryDirectory() as td:
            image = Path(td) / "wrong.iso"
            image.write_bytes(b"synthetic only")
            with self.assertRaises(ValueError):
                run_private(image, Path(td) / "would_be_private.json")
            self.assertFalse((Path(td) / "would_be_private.json").exists())

    def test_hex_32bit_zero_padding(self):
        self.assertEqual(_hex(0x601), "00000601")
        self.assertEqual(_hex(0x06004000), "06004000")


if __name__ == "__main__":
    unittest.main()
