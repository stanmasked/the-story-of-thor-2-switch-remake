import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage116_patch_mednafen_code_window import patch,SIGNATURE,OBJECT,PRE,POST,CONFIG

FIXTURE='''
static uint16 WorkRAMH[1024 * 1024 / sizeof(uint16)];
static Stage115ControlFlowWitness stage115_control_flow;
void run() {
 stage115_control_flow.Configure();
 if(stage115_control_flow.enabled) stage115_control_flow.Before(CPU[0]);
 CPU[0].Step<0, EmulateICache, DebugMode>();
 if(stage115_control_flow.enabled) stage115_control_flow.After(CPU[0]);
}
'''
class PatchTests(unittest.TestCase):
 def test_adds_signature(self): self.assertIn(SIGNATURE,patch(FIXTURE))
 def test_only_once(self): self.assertEqual(patch(FIXTURE).count(SIGNATURE),1)
 def test_pre_hook(self): self.assertEqual(patch(FIXTURE).count('stage116_code_window.Before(CPU[0]);'),1)
 def test_post_hook(self): self.assertEqual(patch(FIXTURE).count('stage116_code_window.After(CPU[0]);'),1)
 def test_config_hook(self): self.assertEqual(patch(FIXTURE).count('stage116_code_window.Configure();'),1)
 def test_rejects_duplicate(self): self.assertRaisesRegex(ValueError,'already_patched',patch,patch(FIXTURE))
 def test_rejects_missing_object(self): self.assertRaisesRegex(ValueError,'object_anchor',patch,FIXTURE.replace(OBJECT,''))
 def test_rejects_missing_pre(self): self.assertRaisesRegex(ValueError,'hook_anchor',patch,FIXTURE.replace(PRE,'not_pre'))
 def test_rejects_missing_post(self): self.assertRaisesRegex(ValueError,'hook_anchor',patch,FIXTURE.replace(POST,'not_post'))
 def test_rejects_missing_config(self): self.assertRaisesRegex(ValueError,'config_anchor',patch,FIXTURE.replace(CONFIG,'not_config'))
 def test_no_private_constants(self):
  out=patch(FIXTURE)
  self.assertNotIn('deadbeef',out.lower()); self.assertNotIn('cafe0123',out.lower())
 def test_no_mmio_reads(self):
  out=patch(FIXTURE)
  self.assertIn('ne16_rbo_be<uint8>(WorkRAMH,address & 0xFFFFFU)',out)
  self.assertNotIn('BSC_BusRead',out)
 def test_bounds(self):
  out=patch(FIXTURE)
  self.assertIn('n>hard_max_rows',out)
  self.assertIn('base+48U<=0x06100000U',out)
if __name__=='__main__': unittest.main()
