import unittest
from stage115_patch_mednafen_control_flow_witness import patch

FIXTURE = """static Stage114ReturnWindow stage114_return_window;
if(stage114_return_window.enabled) stage114_return_window.Before(CPU[0]);
if(stage114_return_window.enabled) stage114_return_window.After(CPU[0]);
void runloop() {
 stage112_monitor.Configure();
 stage113_opcode.Configure();
 stage114_return_window.Configure();
 if(stage114_return_window.force_debug_mode)
  end_ts = NeedEmuICache ? RunLoop_Debug<true>(espec) : RunLoop_Debug<false>(espec);
 else
  end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);
}
"""

class Stage115PatcherTests(unittest.TestCase):
    def test_adds_default_disabled_read_only_monitor(self):
        out=patch(FIXTURE)
        self.assertIn("STAGE115_SH2_CONTROL_FLOW_WITNESS_V1",out)
        self.assertIn('STAGE115_CONTROL_FLOW_ENABLE',out)
        self.assertIn('stage115_control_flow.Configure();',out)
        self.assertIn('stage114_return_window.force_debug_mode || stage115_control_flow.force_debug_mode',out)
        self.assertIn('stage115_control_flow.Before(CPU[0]);',out)
        self.assertIn('stage115_control_flow.After(CPU[0]);',out)
        self.assertIn('max_rows=16384',out)
        self.assertNotIn('WorkRAMH',out)
        self.assertNotIn('ne16_rbo_be',out)
        self.assertNotIn('060042a4',out.lower())

    def test_rejects_double_patch(self):
        with self.assertRaisesRegex(ValueError,'already_patched_stage115'):
            patch(patch(FIXTURE))

    def test_rejects_missing_hook(self):
        with self.assertRaisesRegex(ValueError,'stage114_step_hook_anchor_mismatch'):
            patch(FIXTURE.replace('if(stage114_return_window.enabled) stage114_return_window.After(CPU[0]);','',1))

    def test_rejects_duplicate_runloop(self):
        extra = """\nstage112_monitor.Configure();
stage113_opcode.Configure();
stage114_return_window.Configure();
if(stage114_return_window.force_debug_mode)
 end_ts = NeedEmuICache ? RunLoop_Debug<true>(espec) : RunLoop_Debug<false>(espec);
else
 end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);"""
        with self.assertRaisesRegex(ValueError,'runloop_selection_anchor_mismatch'):
            patch(FIXTURE + extra)

if __name__=='__main__': unittest.main()
