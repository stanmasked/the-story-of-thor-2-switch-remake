import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage112_patch_mednafen_event_monitor import patch,SIGNATURE,PRE,POST

SS = '''#include <mednafen/mednafen.h>
namespace MDFN_IEN_SS {
SH7095 CPU[2];
static uint16 WorkRAMH[1024 * 1024 / sizeof(uint16)];
/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */
/* STAGE111_PRIVATE_RAM_WITNESS_V1 */
void test() {
    if(stage109_observer.enabled) stage109_observer.Record(CPU[0],"pre");
    if(stage111_witness.enabled) stage111_witness.Record(CPU[0],"pre");
    CPU[0].Step<0, EmulateICache, DebugMode>();
    if(stage109_observer.enabled) stage109_observer.Record(CPU[0],"post");
    if(stage111_witness.enabled) stage111_witness.Record(CPU[0],"post");
}
}
'''
class MonitorTests(unittest.TestCase):
    @staticmethod
    def prepared():return SS
    def test_generated(self):self.assertIn(SIGNATURE,patch(self.prepared()))
    def test_once(self):self.assertEqual(patch(self.prepared()).count(SIGNATURE),1)
    def test_guards_pre(self):
        self.assertRaisesRegex(ValueError,'stage109_missing',patch,SS.replace('/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */',''))
    def test_guards_second(self):
        self.assertRaisesRegex(ValueError,'stage111_missing',patch,SS.replace('/* STAGE111_PRIVATE_RAM_WITNESS_V1 */',''))
    def test_no_twice(self):
        self.assertRaisesRegex(ValueError,'already_patched',patch,patch(self.prepared()))
    def test_no_pre(self):
        self.assertRaisesRegex(ValueError,'step_anchors',patch,self.prepared().replace(PRE,'not_here'))
    def test_no_post(self):
        self.assertRaisesRegex(ValueError,'step_anchors',patch,self.prepared().replace(POST,'not_here'))
    def test_no_ram(self):
        self.assertRaisesRegex(ValueError,'ram_layout',patch,self.prepared().replace('static uint16 WorkRAMH','static uint32 WorkRAMH'))
    def test_exact_step(self):
        o=patch(self.prepared());self.assertEqual(o.count('stage112_monitor.Record(CPU[0],true);'),1)
        self.assertEqual(o.count('stage112_monitor.Record(CPU[0],false);'),1)
    def test_disable_by_default(self):
        o=patch(self.prepared());self.assertIn('STAGE112_SH2_EVENTS_ENABLE',o)
        self.assertIn('if(!yes || std::strcmp(yes,"1")',o)
    def test_memory_no_bus(self):
        o=patch(self.prepared());self.assertIn('ne16_rbo_be<uint8>(WorkRAMH,target & 0xFFFFFU)',o)
        self.assertNotIn('BSC_BusRead',o)
    def test_no_private_constants(self):
        o=patch(self.prepared());self.assertNotIn('deadbeef',o);self.assertNotIn('cafe0123',o)
    def test_cap(self):
        o=patch(self.prepared());self.assertIn('max_steps = 200000',o);self.assertIn('2000000,max_steps',o)
        self.assertIn('events>=max_events',o)
    def test_conservative_candidate(self):
        o=patch(self.prepared());self.assertIn('rpc_equals_pr_candidate',o)
        self.assertNotIn('return_verified',o)
    def test_no_standard_headers(self):
        o=patch(self.prepared());sig=o.index(SIGNATURE);self.assertNotIn('#include <cstdio>',o[sig:])
    def test_cross_source(self):
        o=patch(self.prepared());self.assertIn('stage109_observer.Record(CPU[0],"pre");',o)
        self.assertIn('stage111_witness.Record(CPU[0],"pre");',o)
    def test_fixed_target(self):
        o=patch(self.prepared());self.assertIn('STAGE112_SH2_EVENTS_RAM_POINTER',o)
        self.assertIn('target<0x06000000U || target>=0x08000000U',o)

if __name__=='__main__':unittest.main()