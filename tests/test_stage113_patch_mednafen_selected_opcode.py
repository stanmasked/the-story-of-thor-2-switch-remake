import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage113_patch_mednafen_selected_opcode import patch,SIG,CODE,PRE,POST

MOCK='''#include <mednafen/mednafen.h>\nSH7095 CPU[2];\nstatic uint16 WorkRAMH[1024 * 1024 / sizeof(uint16)];\n/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */\n/* STAGE111_PRIVATE_RAM_WITNESS_V1 */\n/* STAGE112_PUBLIC_SH2_LIVENESS_MONITOR_V1 */\nvoid Test(){\n%s\nCPU[0].Step<0, EmulateICache, DebugMode>();\n%s\n}\n'''%(PRE,POST)

class Tests(unittest.TestCase):
 def test_patch(self):
  s=patch(MOCK);self.assertEqual(s.count(SIG),1);self.assertIn('stage113_opcode.Before(CPU[0]);',s);self.assertIn('stage113_opcode.After(CPU[0]);',s)
 def test_idempotence_fail_closed(self):
  with self.assertRaisesRegex(ValueError,'already_patched'):patch(patch(MOCK))
 def test_missing_prev(self):
  for sig in ['/* STAGE109_SH2_OPT_IN_OBSERVER_V1 */', '/* STAGE111_PRIVATE_RAM_WITNESS_V1 */','/* STAGE112_PUBLIC_SH2_LIVENESS_MONITOR_V1 */']:
   with self.subTest(sig=sig),self.assertRaisesRegex(ValueError,'requires_previous'):patch(MOCK.replace(sig,''))
 def test_missing_anchors(self):
  for sig in [PRE,POST]:
   with self.subTest(sig=sig),self.assertRaisesRegex(ValueError,'bad_step_anchor'):patch(MOCK.replace(sig,''))
 def test_duplicate_anchors(self):
  with self.assertRaisesRegex(ValueError,'bad_step_anchor'):patch(MOCK.replace(PRE,PRE+PRE))
 def test_bad_ram(self):
  with self.assertRaisesRegex(ValueError,'bad_ram_backing'):patch(MOCK.replace('static uint16 WorkRAMH[1024 * 1024 / sizeof(uint16)];',''))
 def test_opt_in(self):
  self.assertIn('STAGE113_OPCODE_WITNESS_ENABLE',CODE);self.assertIn('std::strcmp(yes,"1")',CODE)
 def test_raw_opcode(self):
  self.assertIn('SH7095::GSREG_PID',CODE);self.assertIn('pid&0xffffU',CODE);self.assertIn('pending_pid=pid',CODE)
 def test_opcode_labels(self):
  for s in ['0xb000U','0x400bU','0x000bU']:
   with self.subTest(s=s):self.assertIn(s,CODE)
 def test_read_only(self):
  self.assertNotIn('SetRegister(',CODE);self.assertNotIn('MemWrite',CODE);self.assertNotIn('BusRead',CODE)
 def test_bounded(self):
  self.assertIn('2000000',CODE);self.assertIn('16384',CODE);self.assertIn('event_cap',CODE)
 def test_retain_flags(self):
  self.assertIn('pending_pid=pid',CODE);self.assertIn('pending_pid);',CODE)
 def test_no_original_addresses(self):
  self.assertNotIn('ORIGINAL_GAME_PC',CODE)
  self.assertNotIn('ORIGINAL_GAME_ISO',CODE)
 def test_no_implicit_return(self):
  self.assertNotIn('return_proven',CODE);self.assertNotIn('r13_all_paths_proven',CODE)

if __name__=='__main__':unittest.main()