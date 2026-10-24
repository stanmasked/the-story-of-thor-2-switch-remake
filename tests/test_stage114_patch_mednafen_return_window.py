import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage114_patch_mednafen_return_window import patch, SIGNATURE, CODE, PRE, POST, RUNLOOP

FIXTURE = '''#include <cstdio>
struct Stage112Monitor { bool enabled=false; uint32 trigger=1,target=0x06000000; unsigned long max_steps=350000; unsigned ByteAtTarget(){return 0;} void Configure(){} void Record(SH7095&,bool){} };
static Stage112Monitor stage112_monitor;
struct Stage113OpcodeWitness { bool enabled=false; uint32 trigger=1; void Configure(){} void Before(SH7095&){} void After(SH7095&){} };
static Stage113OpcodeWitness stage113_opcode;
void step() {
 '''+PRE+'''
 CPU[0].Step<0, EmulateICache, DebugMode>();
 '''+POST+'''
}
void Emulate() {
 int32 end_ts;
 '''+RUNLOOP+'''
}
'''

class Stage114PatchTests(unittest.TestCase):
    def test_patch_adds_default_disabled_window(self):
        out=patch(FIXTURE)
        self.assertEqual(out.count(SIGNATURE),1)
        self.assertIn("stage114_return_window.Before(CPU[0]);",out)
        self.assertIn("stage114_return_window.After(CPU[0]);",out)
        self.assertIn("stage114_return_window.Configure();",out)
        self.assertIn("RunLoop_Debug<true>(espec)",out)
        self.assertIn("RunLoop_Debug<false>(espec)",out)
    def test_patch_rejects_second_application(self):
        with self.assertRaisesRegex(ValueError,"already_patched_stage114"):
            patch(patch(FIXTURE))
    def test_missing_stage113_object_rejected(self):
        with self.assertRaisesRegex(ValueError,"stage113_object_anchor_mismatch"):
            patch(FIXTURE.replace("static Stage113OpcodeWitness stage113_opcode;",""))
    def test_missing_pre_hook_rejected(self):
        with self.assertRaisesRegex(ValueError,"stage113_step_hook_anchor_mismatch"):
            patch(FIXTURE.replace(PRE,""))
    def test_missing_post_hook_rejected(self):
        with self.assertRaisesRegex(ValueError,"stage113_step_hook_anchor_mismatch"):
            patch(FIXTURE.replace(POST,""))
    def test_missing_runloop_rejected(self):
        with self.assertRaisesRegex(ValueError,"runloop_selection_anchor_mismatch"):
            patch(FIXTURE.replace(RUNLOOP,""))
    def test_reads_public_getters_not_private_members(self):
        for token in ["GSREG_PC_ID","GSREG_PC_IF","GSREG_PID","GSREG_PIF","GSREG_RPC","GSREG_PR","GSREG_R13","GSREG_R15","GSREG_R3","GSREG_SR"]:
            with self.subTest(token=token): self.assertIn(token,CODE)
        for token in ["cpu.PC_ID","cpu.PC_IF","cpu.Pipe_ID","cpu.Pipe_IF","cpu.R[","cpu.PR","cpu.SR"]:
            with self.subTest(token=token): self.assertNotIn(token,CODE)
    def test_dispatch_selector_is_preserved(self):
        self.assertIn("((pid >> 24) & 0xffU) == 0x6aU",CODE)
        self.assertIn("((pid >> 24) & 0xffU) == 0x6eU",CODE)
    def test_no_private_game_values_embedded(self):
        for token in ["Stage111_Private_PC_Trigger","The Story of Thor 2.iso","Sega Saturn BIOS","0x23d0"]:
            with self.subTest(token=token): self.assertNotIn(token,CODE)
    def test_read_only_observer(self):
        for token in ["SetRegister(","MemWrite","BusWrite","MemWrite8("]:
            with self.subTest(token=token): self.assertNotIn(token,CODE)
    def test_bounded_capture(self):
        self.assertIn("max_rows=512",CODE)
        self.assertIn("follow_remaining=4",CODE)
        self.assertIn('Finish("step_limit")',CODE)
        self.assertIn('Finish("event_cap")',CODE)
    def test_marker_has_no_payload(self):
        self.assertIn("for(unsigned i=0;i<25;i++) std::fputc(',',out);",CODE)

if __name__=="__main__": unittest.main()
