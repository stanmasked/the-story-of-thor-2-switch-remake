import unittest
from tools.stage113_patch_mednafen_opcode_witness import patch, SIGNATURE

PRE = 'if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],true);'
POST = 'if(stage112_monitor.enabled) stage112_monitor.Record(CPU[0],false);'
RUNLOOP = 'end_ts = rltab[NeedEmuICache][DBG_NeedCPUHooks()](espec);'
FIXTURE = '''#include <cstdio>
struct Stage112Monitor { bool enabled=false; uint32 trigger=1,target=0x06000000; unsigned long max_steps=2000000; unsigned ByteAtTarget(){return 0;} void Configure(){} void Record(SH7095&,bool){} };
static Stage112Monitor stage112_monitor;
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

class Stage113PatchTests(unittest.TestCase):
    def test_patch_adds_opt_in_window_and_hooks(self):
        out = patch(FIXTURE)
        self.assertIn(SIGNATURE, out)
        self.assertEqual(out.count(SIGNATURE), 1)
        self.assertIn('stage113_opcode_window.Before(CPU[0]);', out)
        self.assertIn('stage113_opcode_window.After(CPU[0]);', out)
        self.assertIn('stage113_opcode_window.Configure();', out)
        self.assertIn('if(stage113_opcode_window.force_debug_mode)', out)
        self.assertIn('RunLoop_Debug<true>(espec)', out)
        self.assertIn('RunLoop_Debug<false>(espec)', out)

    def test_patch_is_not_idempotently_reapplied(self):
        with self.assertRaisesRegex(ValueError, 'already_patched_stage113'):
            patch(FIXTURE + SIGNATURE)

    def test_missing_stage112_object_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'stage112_object_anchor_mismatch'):
            patch(FIXTURE.replace('static Stage112Monitor stage112_monitor;', ''))

    def test_missing_pre_hook_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'stage112_step_hook_anchor_mismatch'):
            patch(FIXTURE.replace(PRE, ''))

    def test_missing_post_hook_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'stage112_step_hook_anchor_mismatch'):
            patch(FIXTURE.replace(POST, ''))

    def test_missing_runloop_anchor_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'runloop_selection_anchor_mismatch'):
            patch(FIXTURE.replace(RUNLOOP, ''))

    def test_no_game_specific_locator_embedded(self):
        self.assertNotIn('Stage111_Private_PC_Trigger', SIGNATURE + '\n' + FIXTURE)
        self.assertNotIn('0x23d0', SIGNATURE + '\n' + FIXTURE)

if __name__ == '__main__':
    unittest.main()