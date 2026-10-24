"""Stage110 synthetic-only private provenance gates; no game data in tests."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage110_private_stage99_machine_gate import audit, EvidenceError, read_trace, check_config

TARGET='20000100'

def trace(steps=2,missing=False,r13=1,corrupt=None):
    rows=['stage109_sh2_steps_v1']
    for step in range(steps):
        for phase in ('pre','post'):
            # Every next pre equals the preceding post, except step index.
            # PC is identical in all rows by design, which is allowed for a stalled CPU.
            pc=TARGET if (not missing and step==0 and phase=='pre') else '00000000'
            values=[pc,'00000000','00000000',f'{r13:08x}']+['00000000']*6
            rows.append(f"{step},{phase},"+','.join(values))
    if corrupt == 'step': rows[2]=rows[2].replace('0,post,','9,post,')
    elif corrupt == 'phase': rows[2]=rows[2].replace(',post,',',pre,')
    elif corrupt == 'value': rows[2]=rows[2].replace('00000000','zzzzzzzz',1)
    elif corrupt == 'continuity': rows[3]=rows[3].replace('00000000','20000102',1)
    elif corrupt == 'truncated': rows.pop()
    elif corrupt == 'header': rows[0]='not_trace'
    return '\n'.join(rows)+'\n'

class Stage110MachineGateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  r=Path(self.tmp.name);self.files={k:r/k for k in ('iso','bios','A','B','pc','cfg_A','cfg_B')}
  self.files['iso'].write_bytes(b'fake-iso');self.files['bios'].write_bytes(b'fake-bios')
  self.pins={k:(self.files[k].stat().st_size,hashlib.sha256(self.files[k].read_bytes()).hexdigest()) for k in ('iso','bios')}
  self.files['A'].write_text(trace());self.files['B'].write_text(trace())
  self.files['pc'].write_text(TARGET+'\n')
  for k in ('cfg_A','cfg_B'):self.files[k].write_text('debugger.autostepmode 0\n')
 def check(self):
  f=self.files
  return audit(f['iso'],f['bios'],f['A'],f['B'],f['pc'],f['cfg_A'],f['cfg_B'],self.pins)
 def test_valid_synthetic_pair_safe_aggregate(self):
  r=self.check();self.assertEqual((r['session_a_valid_pairs'],r['session_b_valid_pairs']),(2,2))
  self.assertTrue(r['r13_one_at_trigger_in_both']);self.assertTrue(r['raw_trace_bytes_identical'])
  self.assertFalse(r['stage104_unconditional_r13_preservation_proven'])
  self.assertFalse(r['callee_entry_return_verified'])
  self.assertNotIn(TARGET,str(r));self.assertNotIn('fake-iso',str(r));self.assertFalse(r['private_addresses_registers_or_game_bytes_emitted'])
 def test_one_malformed_iso(self):
  self.files['iso'].write_bytes(b'bad-test');self.assertRaisesRegex(EvidenceError,'source_identity_mismatch',self.check)
 def test_changed_firmware_with_same_length(self):
  self.files['bios'].write_bytes(b'fake-Xios');self.assertRaisesRegex(EvidenceError,'source_identity_mismatch',self.check)
 def test_autostep_1_rejected(self):
  self.files['cfg_A'].write_text('debugger.autostepmode 1\n');self.assertRaisesRegex(EvidenceError,'debugger_autostep_must_be_disabled',self.check)
 def test_missing_autostep_rejected(self):
  self.files['cfg_A'].write_text('foo 0\n');self.assertRaises(EvidenceError,self.check)
 def test_duplicate_autostep_rejected(self):
  self.files['cfg_A'].write_text('debugger.autostepmode 0\ndebugger.autostepmode 0\n');self.assertRaises(EvidenceError,self.check)
 def test_same_trace_rejected(self):
  self.files['B']=self.files['A'];self.assertRaisesRegex(EvidenceError,'sessions_not_distinct',self.check)
 def test_same_config_rejected(self):
  self.files['cfg_B']=self.files['cfg_A'];self.assertRaisesRegex(EvidenceError,'sessions_not_distinct',self.check)
 def test_missing_pc_trigger_rejected(self):
  self.files['pc'].write_text('0600???\n');self.assertRaisesRegex(EvidenceError,'invalid_private_pc',self.check)
 def test_pc_not_in_trace_rejected(self):
  self.files['B'].write_text(trace(missing=True));self.assertRaisesRegex(EvidenceError,'target_not_uniquely_observed',self.check)
 def test_r13_non_one_rejected(self):
  self.files['A'].write_text(trace(r13=0));self.assertRaisesRegex(EvidenceError,'r13_not_one',self.check)
 def test_invalid_step_number_rejected(self):
  self.files['A'].write_text(trace(corrupt='step'));self.assertRaisesRegex(EvidenceError,'invalid_trace',self.check)
 def test_invalid_phase_rejected(self):
  self.files['A'].write_text(trace(corrupt='phase'));self.assertRaisesRegex(EvidenceError,'invalid_trace',self.check)
 def test_invalid_hex_rejected(self):
  self.files['A'].write_text(trace(corrupt='value'));self.assertRaisesRegex(EvidenceError,'invalid_trace',self.check)
 def test_truncated_pair_rejected(self):
  self.files['A'].write_text(trace(corrupt='truncated'));self.assertRaisesRegex(EvidenceError,'invalid_trace',self.check)
 def test_bad_header_rejected(self):
  self.files['A'].write_text(trace(corrupt='header'));self.assertRaisesRegex(EvidenceError,'invalid_trace',self.check)
 def test_state_continuity_rejected(self):
  self.files['A'].write_text(trace(corrupt='continuity'));self.assertRaisesRegex(EvidenceError,'state_continuity_mismatch',self.check)
 def test_r13_changes_later_does_not_prove_return(self):
  source=trace().splitlines()
  fields=source[-1].split(',');fields[5]='00000000';source[-1]=','.join(fields)
  self.files['B'].write_text('\n'.join(source)+'\n')
  self.assertFalse(self.check()['r13_one_throughout_session_b'])
  self.assertFalse(self.check()['callee_entry_return_verified'])

if __name__=='__main__':unittest.main()