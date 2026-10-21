"""Stage44 synthetic VDP1 command chains and VRAM delta tests.

All test records are manufactured; NO original Saturn VRAM is committed.
"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage44_vdp1_vram_audit import (
    VDP1_VRAM_BYTES,hardware_literal_counts,parse_command_chain,
    compare_vram_dumps,
)


def vram(*commands):
    data=bytearray(VDP1_VRAM_BYTES)
    for off,ctrl,link,size in commands:
        data[off:off+2]=ctrl.to_bytes(2,"big")
        data[off+2:off+4]=link.to_bytes(2,"big")
        data[off+0x0A:off+0x0C]=size.to_bytes(2,"big")
    return bytes(data)


class Stage44Tests(unittest.TestCase):
    def check(self,*cmds):
        return parse_command_chain(vram(*cmds))[0]

    def test_empty_reference_scan(self):
        r=hardware_literal_counts(b"")
        self.assertEqual((r["pc_relative_loads_vdp1_vram_base"],
                          r["pc_relative_loads_vdp1_register_base"]),(0,0))

    def test_static_hardware_loads(self):
        b=bytearray(24)
        b[0:2]=(0xD001).to_bytes(2,"big")
        b[8:12]=(0x25C00000).to_bytes(4,"big")
        b[2:4]=(0xD102).to_bytes(2,"big")
        b[12:16]=(0x25D00000).to_bytes(4,"big")
        r=hardware_literal_counts(bytes(b))
        self.assertEqual((r["pc_relative_loads_vdp1_vram_base"],
                          r["pc_relative_loads_vdp1_register_base"]),(1,1))

    def test_static_load_not_write_proof(self):
        self.assertFalse(hardware_literal_counts(b"")[
            "vdp1_memory_writes_from_game_confirmed"])

    def test_only_end(self):
        r=self.check((0,0x8000,0,0))
        self.assertEqual(r["terminated_by"],"end_bit")
        self.assertEqual(r["executed_non_end_entries"],0)

    def test_next_then_end(self):
        r=self.check((0,0,0,0x0102),(32,0x8000,0,0))
        self.assertEqual(r["visited_distinct_command_entries"],2)
        self.assertEqual(r["types_executed"],{"normal_sprite":1})

    def test_nonempty_dimensions(self):
        self.assertEqual(self.check((0,0,0,0x0102),(32,0x8000,0,0))[
            "sprite_size_zero_candidates"],0)

    def test_zero_dimensions_flagged(self):
        self.assertEqual(self.check((0,0,0,0),(32,0x8000,0,0))[
            "sprite_size_zero_candidates"],1)

    def test_assign_link_is_times_eight(self):
        r=self.check((0,0x1004,8,0),(64,0x8000,0,0))
        self.assertEqual(r["types_executed"],{"polygon":1})
        self.assertTrue(r["end_bit_reached"])

    def test_call_and_return(self):
        r=self.check((0,0x2000,8,0x0101),(32,0x8000,0,0),
                     (64,0x3008,0,0))
        self.assertEqual(r["visited_distinct_command_entries"],3)
        self.assertTrue(r["end_bit_reached"])

    def test_skip_next(self):
        r=self.check((0,0x4000,0,0),(32,0x8000,0,0))
        self.assertEqual(r["skipped_entries"],1)
        self.assertEqual(r["executed_non_end_entries"],0)

    def test_skip_assign(self):
        r=self.check((0,0x5004,8,0),(64,0x8000,0,0))
        self.assertTrue(r["end_bit_reached"])
        self.assertEqual(r["skipped_entries"],1)

    def test_skip_call(self):
        r=self.check((0,0x6000,8,0),(32,0x8000,0,0),
                     (64,0x7006,0,0))
        self.assertTrue(r["end_bit_reached"])
        self.assertEqual(r["skipped_entries"],2)

    def test_unmatched_return(self):
        self.assertEqual(self.check((0,0x3000,0,0))[
            "terminated_by"],"return_without_call")

    def test_nested_call_rejected(self):
        self.assertEqual(self.check((0,0x2000,8,0),
                                    (64,0x2000,12,0))[
            "terminated_by"],"nested_call_unsupported")

    def test_loop_detected(self):
        self.assertEqual(self.check((0,0x1000,0,0))["terminated_by"],"cycle")

    def test_outside_vram(self):
        self.assertEqual(self.check((0,0x1000,0xFFFF,0))[
            "terminated_by"],"command_out_of_bounds")

    def test_command_budget(self):
        self.assertEqual(parse_command_chain(vram((0,0,0,0)),1)[0][
            "terminated_by"],"limit")

    def test_vram_size_is_exact(self):
        with self.assertRaises(ValueError):
            parse_command_chain(b"\0"*1024)

    def test_invalid_budget(self):
        with self.assertRaises(ValueError):
            parse_command_chain(vram(),0)

    def test_unknown_command_type_counted(self):
        self.assertEqual(self.check((0,0x000F,0,0),(32,0x8000,0,0))[
            "unsupported_command_types"],1)

    def test_skipped_unknown_not_executed(self):
        self.assertEqual(self.check((0,0x400F,0,0),(32,0x8000,0,0))[
            "unsupported_command_types"],0)

    def test_polygon(self):
        self.assertEqual(self.check((0,0x0004,0,0),(32,0x8000,0,0))[
            "types_executed"],{"polygon":1})

    def test_local_coordinate_command(self):
        self.assertEqual(self.check((0,0x000A,0,0),(32,0x8000,0,0))[
            "types_executed"],{"local_coordinates":1})

    def test_same_dump(self):
        a=vram((0,0x8000,0,0))
        r=compare_vram_dumps(a,a)
        self.assertTrue(r["dumps_are_identical"])
        self.assertEqual(r["changed_reachable_command_slots"],0)

    def test_changed_end_command(self):
        a=vram((0,0x8000,0,0))
        b=vram((0,0x8001,0,0))
        r=compare_vram_dumps(a,b)
        self.assertEqual(r["changed_vram_bytes"],1)
        self.assertEqual(r["changed_reachable_command_slots"],1)

    def test_texture_change_not_command_change(self):
        a=vram((0,0x8000,0,0))
        b=bytearray(a);b[0x10000]=0xAA
        r=compare_vram_dumps(a,bytes(b))
        self.assertEqual(r["changed_vram_bytes"],1)
        self.assertEqual(r["changed_reachable_command_slots"],0)

    def test_changed_later_command(self):
        a=vram((0,0,0,0),(32,0x8000,0,0))
        b=vram((0,0,0,0),(32,0x8002,0,0))
        self.assertEqual(compare_vram_dumps(a,b)[
            "changed_reachable_command_slots"],1)

    def test_no_runtime_attestation(self):
        a=vram((0,0x8000,0,0))
        r=compare_vram_dumps(a,vram((0,0x8001,0,0)))
        self.assertFalse(r["emulator_origin_authenticated"])
        self.assertFalse(r["changes_attributed_to_handler_39"])

    def test_no_pixel_decoder_claim(self):
        r=self.check((0,0x8000,0,0))
        self.assertFalse(r["rendered_pixels_produced"])
        self.assertFalse(r["confirmed_hardware_execution"])

    def test_no_raw_addresses_in_summary(self):
        r=self.check((0,0x8000,0,0))
        for key in ("position","pc","address","raw_command","texels"):
            self.assertNotIn(key,r)

    def test_unaligned_link(self):
        self.assertEqual(self.check((0,0x1000,5,0))[
            "terminated_by"],"unaligned_command_address")

    def test_end_bit_before_jump(self):
        self.assertEqual(self.check((0,0xF002,100,0))[
            "terminated_by"],"end_bit")

    def test_three_command_types(self):
        r=self.check((0,0x0008,0,0),(32,0x0009,0,0),
                     (64,0x000A,0,0),(96,0x8000,0,0))
        self.assertEqual(r["executed_non_end_entries"],3)
        self.assertTrue(r["end_bit_reached"])


if __name__=="__main__":
    unittest.main()
