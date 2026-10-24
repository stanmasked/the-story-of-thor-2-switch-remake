import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage113_patch_mednafen_opcode_trace import patch,SIGNATURE

FIXTURE="""template<unsigned which, bool EmulateICache, int DebugMode>
INLINE void SH7095::Step(void)
{
 const uint32 instr = (uint16)Pipe_ID;
 const unsigned instr_nyb1 = (instr >> 4) & 0xF;
 const unsigned instr_nyb2 = (instr >> 8) & 0xF;
 switch(Pipe_ID >> 24)
 {
 }
 PC += 2;
}

void SH7095::StateAction(StateMem* sm, const unsigned load)
{
}
"""

class PatchTests(unittest.TestCase):
    def test_adds_opt_in_dispatch_trace(self):
        out=patch(FIXTURE)
        self.assertEqual(out.count(SIGNATURE),1)
        self.assertIn("stage113_opcode_trace.Configure();",out)
        self.assertIn("stage113_opcode_trace.Begin(which",out)
        self.assertIn("stage113_opcode_trace.Complete(which",out)
        self.assertIn("STAGE113_OPCODE_TRACE_ENABLE",out)
    def test_hooks_are_inside_step_body(self):
        out=patch(FIXTURE)
        begin=out.index("stage113_opcode_trace.Begin(which")
        switch=out.index("switch(Pipe_ID >> 24)")
        complete=out.index("stage113_opcode_trace.Complete(which")
        advance=out.index(" PC += 2;")
        self.assertLess(begin,switch)
        self.assertLess(advance,complete)
    def test_no_game_specific_address_is_embedded(self):
        out=patch(FIXTURE)
        self.assertNotIn("0x06000000",out)
        self.assertNotIn("0x07000000",out)
    def test_refuses_second_application(self):
        with self.assertRaisesRegex(ValueError,"already_patched"):
            patch(patch(FIXTURE))
    def test_missing_step_rejected(self):
        with self.assertRaisesRegex(ValueError,"step_anchor"):
            patch("void Other() {}")
    def test_missing_pc_advance_rejected(self):
        with self.assertRaisesRegex(ValueError,"step_body"):
            patch(FIXTURE.replace(" PC += 2;",""))
    def test_duplicate_pc_advance_rejected(self):
        with self.assertRaisesRegex(ValueError,"step_body"):
            patch(FIXTURE.replace(" PC += 2;"," PC += 2;\n PC += 2;"))
    def test_missing_state_boundary_rejected(self):
        with self.assertRaisesRegex(ValueError,"step_end"):
            patch(FIXTURE.replace("\n\nvoid SH7095::StateAction",""))
    def test_duplicate_step_anchor_rejected(self):
        with self.assertRaisesRegex(ValueError,"step_anchor"):
            patch(FIXTURE.replace("void SH7095::StateAction","INLINE void SH7095::Step(void)\n{}\n\nvoid SH7095::StateAction"))
if __name__=="__main__":unittest.main()
