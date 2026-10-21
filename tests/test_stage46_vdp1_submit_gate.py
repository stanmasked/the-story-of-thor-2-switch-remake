"""Stage46 synthetic-only gate and descriptor tests; no original Saturn code."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from test_stage45_vdp1_command_copy import fixture as stage45_fixture,put,ENTRY
from stage46_vdp1_submit_gate import (
    GATE_TEMPLATE,LOADING_REGS,bt_target,match_submit_gate,
    find_submit_gates,ptr_load_count,summarize,
)

GATE=0x400
STATUS=0x060A0010
COUNT=0x060A0012
BUFFER=0x060A1000
COMMITTED=0x060A0014
LITERALS={
    0x02:(0x490,STATUS),0x0E:(0x490,STATUS),
    0x12:(0x494,COUNT),0x1C:(0x498,BUFFER),
    0x1E:(0x49C,0x06004000+ENTRY),0x2A:(0x4A0,COMMITTED),
    0x2E:(0x494,COUNT),
}


def fixture(mutation=None,with_gate=True,with_writer=True,with_caller=False):
    data=bytearray(stage45_fixture(with_writer=with_writer,
                                    with_caller=with_caller))
    data.extend(bytes(max(0,0x600-len(data))))
    if with_gate:
        for offset,opcode in GATE_TEMPLATE.items():
            put(data,GATE+offset,opcode)
        for offset,(litpos,address) in LITERALS.items():
            p=GATE+offset
            disp=(litpos-((p+4)&~3))//4
            put(data,p,0xD000 | LOADING_REGS[offset]<<8 | disp)
            data[litpos:litpos+4]=address.to_bytes(4,"big")
    if mutation:
        put(data,*mutation)
    return bytes(data)


class Stage46Tests(unittest.TestCase):
    def report(self,**kwargs):
        return summarize(fixture(**kwargs))

    def test_full_submit_gate(self):
        self.assertEqual(self.report()["verified_submit_gate_signatures"],1)

    def test_exact_gate_start(self):
        self.assertEqual(find_submit_gates(fixture())[0]["start"],GATE)

    def test_signed_negative_status(self):
        self.assertEqual(self.report()["gates_with_negative_signed_byte_flag"],1)

    def test_nonzero_record_count(self):
        self.assertEqual(self.report()["gates_with_unsigned_nonzero_record_count"],1)

    def test_status_reset_before_count(self):
        self.assertTrue(self.report()["status_cleared_before_count_test"])

    def test_buffer_in_r4(self):
        self.assertTrue(self.report()["command_source_r4_from_pc_literal"])

    def test_record_count_in_r5(self):
        self.assertTrue(self.report()["command_count_r5_from_global_word"])

    def test_commit_after_call(self):
        self.assertTrue(self.report()["committed_pointer_saved_after_copy"])

    def test_pending_reset_after_call(self):
        self.assertTrue(self.report()["pending_count_cleared_after_copy"])

    def test_eight_byte_record(self):
        self.assertEqual(self.report()["input_record_width_bytes"],8)

    def test_field_grammar(self):
        self.assertEqual(self.report()["input_record_field_layout"],
                         "u32 source_pointer, u16 vram_index, i16 command_count")

    def test_copy_command_width(self):
        self.assertEqual(self.report()["vdp1_command_copy_size_bytes"],32)

    def test_destination_offset_scale(self):
        self.assertEqual(self.report()["destination_offset_unit_bytes"],8)

    def test_source_pointer_census(self):
        self.assertEqual(self.report()["source_base_pc_literal_loads"],1)

    def test_status_pointer_census(self):
        self.assertGreaterEqual(self.report()["status_byte_pointer_pc_literal_loads"],2)

    def test_count_pointer_census(self):
        self.assertEqual(self.report()["pending_count_pointer_pc_literal_loads"],2)

    def test_count_range_not_claimed(self):
        self.assertFalse(self.report()["record_count_capacity_or_upper_bound_proven"])

    def test_no_live_gpu_claim(self):
        self.assertFalse(self.report()["live_vdp1_command_output_proven"])

    def test_no_handler_identity_claim(self):
        self.assertFalse(self.report()["handler_39_producer_identity_proven"])

    def test_direct_branch_math(self):
        self.assertEqual(bt_target(GATE+0x0A,0x8912),GATE+0x32)
        self.assertIsNone(bt_target(GATE+0x0A,0x8B12))

    def test_missing_writer(self):
        self.assertEqual(self.report(with_writer=False)["verified_submit_gate_signatures"],0)

    def test_missing_gate(self):
        self.assertEqual(self.report(with_gate=False)["verified_submit_gate_signatures"],0)

    def test_corrupt_gate_flag_test(self):
        self.assertEqual(self.report(mutation=(GATE+8,0x4310))["verified_submit_gate_signatures"],0)

    def test_corrupt_sign_gate(self):
        self.assertEqual(self.report(mutation=(GATE+0x0A,0x8B12))["verified_submit_gate_signatures"],0)

    def test_corrupt_status_clear(self):
        self.assertEqual(self.report(mutation=(GATE+0x10,0x2311))["verified_submit_gate_signatures"],0)

    def test_corrupt_count_extension(self):
        self.assertEqual(self.report(mutation=(GATE+0x16,0x625E))["verified_submit_gate_signatures"],0)

    def test_corrupt_zero_count_branch(self):
        self.assertEqual(self.report(mutation=(GATE+0x1A,0x8909))["verified_submit_gate_signatures"],0)

    def test_corrupt_buffer_ptr_register(self):
        self.assertEqual(self.report(mutation=(GATE+0x1C,0xD51E))["verified_submit_gate_signatures"],0)

    def test_corrupt_buffer_address_literal(self):
        self.assertEqual(self.report(mutation=(0x498,0x0000))["verified_submit_gate_signatures"],0)

    def test_corrupt_writer_target_literal(self):
        self.assertEqual(self.report(mutation=(0x49C,0xFFFF))["verified_submit_gate_signatures"],0)

    def test_corrupt_status_pointer_alias(self):
        self.assertEqual(self.report(mutation=(GATE+0x0E,0xD31F))["verified_submit_gate_signatures"],0)

    def test_corrupt_count_pointer_alias(self):
        self.assertEqual(self.report(mutation=(GATE+0x2E,0xD31A))["verified_submit_gate_signatures"],0)

    def test_corrupt_save_r4(self):
        self.assertEqual(self.report(mutation=(GATE+0x20,0x2F32))["verified_submit_gate_signatures"],0)

    def test_corrupt_jsr_register(self):
        self.assertEqual(self.report(mutation=(GATE+0x22,0x430B))["verified_submit_gate_signatures"],0)

    def test_corrupt_commit_store(self):
        self.assertEqual(self.report(mutation=(GATE+0x2C,0x2231))["verified_submit_gate_signatures"],0)

    def test_corrupt_pending_counter_reset(self):
        self.assertEqual(self.report(mutation=(GATE+0x30,0x2310))["verified_submit_gate_signatures"],0)

    def test_corrupt_rts(self):
        self.assertEqual(self.report(mutation=(GATE+0x36,0x0009))["verified_submit_gate_signatures"],0)

    def test_empty(self):
        self.assertEqual(summarize(b"")["verified_submit_gate_signatures"],0)

    def test_private_positions_not_exported(self):
        for key in ("start","status_address","count_address","source_address",
                    "writer_entry","last_submitted_pointer_address",
                    "raw_bytes","pc"):
            self.assertNotIn(key,self.report())


if __name__=="__main__":
    unittest.main()
