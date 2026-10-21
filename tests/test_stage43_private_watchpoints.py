"""Stage43 synthetic-only tests. No Saturn ROM, debugger or real trace."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage43_private_watchpoints import (
    slot_number, inspect_snapshots, _write_private_json, derive_private_manifest,
)


def manifest():
    return {
        "pool_base":0x06080000, "pool_stride":276, "pool_count":43,
        "slot_return_pc":0x06020000,
        "copy_entry_pc":0x06020100,
        "index_store_pc":0x06020200,
        "function_39_runtime_address":0x06020300,
        "dispatchers":{
            "table_start":{"entry_pc":0x06020400,"jump_pc":0x06020430,
                           "jump_target_register":"r3"},
            "selected_cell":{"entry_pc":0x06020500,"jump_pc":0x06020530,
                             "jump_target_register":"r2"},
        },
    }


def snapshots(route="table_start", rewrite=False):
    m=manifest()
    address=m["pool_base"]+3*276
    events=[
        {"cycle":1,"event":"slot-return","pc":m["slot_return_pc"],"r0":address},
        {"cycle":2,"event":"copy-entry","pc":m["copy_entry_pc"],
         "r4":0x06090000,"r5":address},
        {"cycle":3,"event":"index-store-pre","pc":m["index_store_pc"],
         "r14":address,"r3":38},
    ]
    value=38
    if rewrite:
        value=0
        events.append({
            "cycle":4,"event":"index-word-change","pc":0x06020600,
            "address":address+126,"width_bytes":2,"old_value":38,"new_value":0
        })
    time=5 if rewrite else 4
    events.extend([
        {"cycle":time,"event":"dispatch-entry",
         "pc":m["dispatchers"][route]["entry_pc"],"anchor":route,
         "r4":address,"index_word":value},
        {"cycle":time+1,"event":"dispatch-jmp-pre",
         "pc":m["dispatchers"][route]["jump_pc"],
         "r14":address,"index_word":value,
         m["dispatchers"][route]["jump_target_register"]:
             m["function_39_runtime_address"]},
    ])
    return events


class Stage43SyntheticTests(unittest.TestCase):
    def check(self, ev):
        return inspect_snapshots(manifest(),ev)

    def test_slot_first(self):
        self.assertEqual(slot_number(manifest()["pool_base"],manifest()),0)

    def test_slot_last(self):
        m=manifest()
        self.assertEqual(slot_number(m["pool_base"]+42*276,m),42)

    def test_slot_outside(self):
        m=manifest()
        self.assertIsNone(slot_number(m["pool_base"]+43*276,m))

    def test_slot_misaligned(self):
        m=manifest()
        self.assertIsNone(slot_number(m["pool_base"]+12,m))

    def test_slot_bool_rejected(self):
        self.assertIsNone(slot_number(True,manifest()))

    def test_base_route(self):
        self.assertTrue(self.check(snapshots())["supplied_snapshots_consistent"])

    def test_selected_route_requires_rewrite(self):
        self.assertFalse(self.check(snapshots("selected_cell"))[
            "supplied_snapshots_consistent"])

    def test_selected_route_with_explicit_rewrite(self):
        self.assertTrue(self.check(snapshots("selected_cell",True))[
            "supplied_snapshots_consistent"])

    def test_base_route_must_not_have_rewrite_to_zero(self):
        self.assertFalse(self.check(snapshots("table_start",True))[
            "supplied_snapshots_consistent"])

    def test_rewrite_wrong_location(self):
        s=snapshots("selected_cell",True);s[3]["address"]+=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_rewrite_wrong_width(self):
        s=snapshots("selected_cell",True);s[3]["width_bytes"]=1
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_rewrite_wrong_previous_value(self):
        s=snapshots("selected_cell",True);s[3]["old_value"]=37
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_rewrite_wrong_new_value(self):
        s=snapshots("selected_cell",True);s[3]["new_value"]=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_invalid_kind(self):
        s=snapshots();s[0]["event"]="bad"
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_invalid_cycle(self):
        s=snapshots();s[0]["cycle"]=-1
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_duplicate_cycle(self):
        s=snapshots();s[1]["cycle"]=1
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_reverse_cycles(self):
        s=snapshots();s[0]["cycle"]=99
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_malformed_events(self):
        self.assertFalse(self.check({})["supplied_snapshots_consistent"])

    def test_missing_events(self):
        self.assertFalse(self.check(snapshots()[:2])["supplied_snapshots_consistent"])

    def test_extra_events(self):
        s=snapshots();s.append(s[-1])
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_event_non_dict(self):
        s=snapshots();s[0]="bad"
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_allocator_pc(self):
        s=snapshots();s[0]["pc"]+=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_allocator_slot(self):
        s=snapshots();s[0]["r0"]+=1
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_copy_source_null(self):
        s=snapshots();s[1]["r4"]=0
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_copy_destination_mismatch(self):
        s=snapshots();s[1]["r5"]+=276
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_copy_pc(self):
        s=snapshots();s[1]["pc"]+=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_writer_register(self):
        s=snapshots();s[2]["r3"]=37
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_writer_destination(self):
        s=snapshots();s[2]["r14"]+=276
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_writer_pc(self):
        s=snapshots();s[2]["pc"]+=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_dispatch_pointer(self):
        s=snapshots();s[3]["r4"]+=276
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_dispatch_field(self):
        s=snapshots();s[3]["index_word"]=37
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_dispatch_entry_pc(self):
        s=snapshots();s[3]["pc"]+=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_jump_target(self):
        s=snapshots();s[4]["r3"]+=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_jump_register_after_copy(self):
        s=snapshots();s[4]["r14"]=0x06090000
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_jump_pc(self):
        s=snapshots();s[4]["pc"]+=2
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_jump_index(self):
        s=snapshots();s[4]["index_word"]=0
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_unknown_anchor(self):
        s=snapshots();s[3]["anchor"]="other"
        self.assertFalse(self.check(s)["supplied_snapshots_consistent"])

    def test_no_runtime_attestation_even_if_consistent(self):
        result=self.check(snapshots())
        self.assertFalse(result["real_emulator_execution_attested"])
        self.assertFalse(result["real_vdp1_output_attested"])

    def test_output_has_no_private_pointer(self):
        result=self.check(snapshots())
        self.assertNotIn("pool_base",result)
        self.assertNotIn("r14",result)
        self.assertNotIn("pc",result)

    def test_private_manifest_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"manifest.json"
            _write_private_json(path,manifest())
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_private_manifest_overwrite_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"manifest.json"
            path.write_text("old")
            os.chmod(path,0o644)
            _write_private_json(path,manifest())
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_derive_private_manifest_reject_bad_iso(self):
        with patch("stage43_private_watchpoints.pool_base",return_value=None), \
             patch("stage43_private_watchpoints._pointer_table",return_value=None), \
             patch("stage43_private_watchpoints.find_writer_entries",return_value=[]):
            with self.assertRaises(ValueError):
                derive_private_manifest(b"","0"*64)


if __name__=="__main__":
    unittest.main()
