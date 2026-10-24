"""Stage109 public-source synthetic patch tests: no original game / firmware."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage109_patch_mednafen_observer import patch, SIGNATURE

BASE = '''#include <mednafen/mednafen.h>\n#include "sh7095.h"\nSH7095 CPU[2]{ {"a",0,nullptr}, {"b",1,nullptr} };\nvoid loop(){\n CPU[0].Step<0, EmulateICache, DebugMode>();\n}\n'''

class Stage109PatchTests(unittest.TestCase):
    def test_inserts_once(self):
        v=patch(BASE)
        self.assertEqual(v.count(SIGNATURE),1)
        self.assertIn('Record(CPU[0],"pre")',v)
        self.assertIn('Record(CPU[0],"post")',v)
    def test_standard_headers_remain_outside_emulator_namespace(self):
        original = '#include <mednafen/mednafen.h>\n#include <vector>\nnamespace MDFN_IEN_SS {\n' + BASE.replace('#include <mednafen/mednafen.h>\n','') + '\n}'
        result = patch(original)
        self.assertLess(result.index('#include <mednafen/mednafen.h>'), result.index('#include <cstdio>'))
        self.assertLess(result.index('#include <cstring>'), result.index('namespace MDFN_IEN_SS'))
        self.assertEqual(result.count('#include <cstdio>'), 1)

    def test_header_order_respects_mednafen_types_guard(self):
        result=patch(BASE)
        self.assertLess(result.index('#include <mednafen/mednafen.h>'),result.index('#include <cstdint>'))
    def test_missing_core_include_rejected(self):
        with self.assertRaisesRegex(ValueError,'mednafen_core_include'):
            patch(BASE.replace('#include <mednafen/mednafen.h>\n',''))
    def test_duplicate_core_include_rejected(self):
        with self.assertRaisesRegex(ValueError,'mednafen_core_include'):
            patch('#include <mednafen/mednafen.h>\n'+BASE)
    def test_absent_anchor_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'cpu_step_anchor'): patch(BASE.replace('Step<0,','Step<1,'))
    def test_two_anchors_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'cpu_step_anchor'): patch(BASE+BASE)
    def test_missing_cpu_global_fail_closed(self):
        with self.assertRaisesRegex(ValueError,'cpu_global'): patch(BASE.replace('SH7095 CPU[2]','SH7095 CAR[2]'))
    def test_repatch_refused(self):
        with self.assertRaisesRegex(ValueError,'already_patched'): patch(patch(BASE))
    def test_no_private_hardcoded_address(self):
        s=patch(BASE)
        self.assertNotIn('0600220e',s.lower())
        self.assertNotIn('06000344',s.lower())
        self.assertNotIn('The Story of Thor',s)
        self.assertIn('STAGE109_SH2_OBSERVER_PC',s)
    def test_observer_opt_in(self):
        s=patch(BASE)
        self.assertIn('std::strcmp(yes, "1")',s)
        self.assertIn('if(!yes',s)
    def test_immediate_first_step_opt_in_only(self):
        s=patch(BASE)
        self.assertIn('STAGE109_SH2_OBSERVER_START_IMMEDIATELY',s)
        self.assertIn('if(enabled && immediate && !std::strcmp(immediate,"1")) tracing=true;',s)
        self.assertLess(s.index('enabled = (out != nullptr);'),s.index('if(enabled && immediate'))
        self.assertIn('if(!yes || std::strcmp(yes, "1") || !pc || !dst || !*dst) return;',s)
    def test_first_step_has_complete_pre_post_in_main_loop(self):
        s=patch(BASE)
        self.assertLess(s.index('Record(CPU[0],"pre")'),s.index('CPU[0].Step<0, EmulateICache, DebugMode>();'))
        self.assertLess(s.index('CPU[0].Step<0, EmulateICache, DebugMode>();'),s.index('Record(CPU[0],"post")'))
    def test_trace_bounded(self):
        s=patch(BASE)
        self.assertIn('m<=4096',s)
        self.assertIn('step>=limit',s)
    def test_no_game_path_in_observer(self):
        s=patch(BASE)
        self.assertNotIn('/mnt/data',s)
        self.assertNotIn('.iso',s)
        self.assertNotIn('.bin',s)

if __name__=='__main__': unittest.main()