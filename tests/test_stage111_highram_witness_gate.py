"""Synthetic-only Stage111 paired-witness tests, never original Saturn data."""
import tempfile,unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage111_highram_witness_gate import audit,session,EvidenceError

REG_HEAD='stage109_sh2_steps_v1\n'
RAM_HEAD='stage111_sh2_highram_witness_v1\n'
# Synthetic invented register state, no relation to game PC or RAM value.
PC='06010000';PTR='06050000'
def make(n=4,change=True):
    rr=[REG_HEAD];mm=[RAM_HEAD]
    for i in range(n):
      for phase in ['pre','post']:
        rr.append(f'{i},{phase},00000000,00000000,{PC},00000001,06040000,00000000,{PTR},00000000,00000000,00000000\n')
        v='01' if phase=='post' and change and i==1 else '00'
        mm.append(f'{i},{phase},00000000,00000000,{PC},{PTR},{v},1\n')
    return ''.join(rr),''.join(mm)

class Stage111GateTests(unittest.TestCase):
    def setUp(self):
       self.tmp=tempfile.TemporaryDirectory()
       self.addCleanup(self.tmp.cleanup)
       self.paths=[Path(self.tmp.name)/x for x in ('regA.csv','memA.csv','regB.csv','memB.csv')]
       r,m=make()
       for p,s in zip(self.paths,(r,m,r,m)):p.write_text(s)
    def chk(self):return audit(*self.paths)
    def test_valid_pair(self):
      x=self.chk();self.assertTrue(x['pass']);self.assertEqual(x['session_a_full_step_pairs'],4)
    def test_detect_change(self):self.assertTrue(self.chk()['session_a_ram_transition_seen'])
    def test_never_proves_opcode(self):self.assertFalse(self.chk()['opcode_origin_independently_proven'])
    def test_never_proves_full_return(self):self.assertFalse(self.chk()['call_return_verified'])
    def test_never_unconditional(self):self.assertFalse(self.chk()['stage104_unconditional_r13_preservation_proven'])
    def test_zero_changes_valid(self):
      self.paths[1].write_text(make(change=False)[1]);self.paths[3].write_text(make(change=False)[1]);self.assertFalse(self.chk()['session_a_ram_transition_seen'])
    def test_missing_file(self):
      self.paths[1].unlink()
      with self.assertRaises(EvidenceError):self.chk()
    def test_duplicate_pair(self):
      with self.assertRaises(EvidenceError):audit(self.paths[0],self.paths[1],self.paths[0],self.paths[3])
    def test_reg_pointer_mismatch(self):
      x=self.paths[1];x.write_text(x.read_text().replace(PTR,'06060000'))
      with self.assertRaisesRegex(EvidenceError,'register_memory_stream_mismatch'):self.chk()
    def test_bad_header(self):
      self.paths[1].write_text(self.paths[1].read_text().replace(RAM_HEAD,'wrong\n'))
      with self.assertRaisesRegex(EvidenceError,'invalid_trace_shape'):self.chk()
    def test_broken_pair_number(self):
      p=self.paths[1];p.write_text(p.read_text().replace('0,post,','10,post,'))
      with self.assertRaisesRegex(EvidenceError,'invalid_trace_row'):self.chk()
    def test_bad_valid_flag(self):
      p=self.paths[1];p.write_text(p.read_text().replace(PTR+',00,1',PTR+',00,0'))
      with self.assertRaisesRegex(EvidenceError,'invalid_ram_address_flag'):self.chk()
    def test_unreported_private_values(self):
      self.assertFalse(self.chk()['private_addresses_bytes_or_register_values_emitted'])
    def test_truncated_odd_records(self):
      p=self.paths[1];p.write_text('\n'.join(p.read_text().splitlines()[:-1])+'\n')
      with self.assertRaisesRegex(EvidenceError,'invalid_trace_shape'):self.chk()
    def test_invalid_hex(self):
      p=self.paths[1];p.write_text(p.read_text().replace(PC,'GGGGGGGG'))
      with self.assertRaisesRegex(EvidenceError,'invalid_trace_row'):self.chk()
    def test_step_count_mismatch(self):
      r,m=make(5);self.paths[1].write_text(m)
      with self.assertRaisesRegex(EvidenceError,'step_count_mismatch'):self.chk()

if __name__=='__main__':unittest.main()