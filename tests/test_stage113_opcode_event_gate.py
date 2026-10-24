import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage113_opcode_event_gate import audit,GateError,HEADER

def row(step,phase,kind,pid='0000b002'):
 return f'{step},{phase},{kind},{pid},06000000,06000002,06000004,06000006,00000001,06000008'

def make(rows):
 t=tempfile.TemporaryDirectory();p=Path(t.name)/'event.csv';p.write_text(HEADER+'\n'+'\n'.join(rows)+'\n');return t,p

GOOD=[row(0,'pre','start'),row(0,'pre','selected'),row(0,'post','selected'),row(1,'post','pr_change'),row(2,'pre','selected','0000000b'),row(2,'post','selected','0000000b'),row(10,'post','step_limit')]

class Tests(unittest.TestCase):
 def check_failure(self,rows):
  t,p=make(rows)
  try:
   with self.assertRaises(GateError):audit(p)
  finally:t.cleanup()
 def test_good(self):
  t,p=make(GOOD)
  try:
   out=audit(p);self.assertEqual(out['selected_opcode_pre_post_pairs'],2);self.assertEqual(out['rts_selected_records'],1);self.assertEqual(out['bsr_selected_records'],1);self.assertFalse(out['complete_bsr_rts_return_proven'])
  finally:t.cleanup()
 def test_empty(self):self.check_failure([])
 def test_bad_header(self):
  t,p=make(GOOD);p.write_text('bogus\n'+'\n'.join(GOOD)+'\n')
  try:
   with self.assertRaises(GateError):audit(p)
  finally:t.cleanup()
 def test_missing_start(self):self.check_failure(GOOD[1:])
 def test_duplicate_start(self):self.check_failure(GOOD[:1]+GOOD[:1]+GOOD[1:])
 def test_missing_post(self):self.check_failure(GOOD[:2]+GOOD[3:])
 def test_post_without_pre(self):self.check_failure(GOOD[:1]+GOOD[2:])
 def test_pid_mismatch(self):self.check_failure(GOOD[:2]+[row(0,'post','selected','0000b004')]+GOOD[3:])
 def test_reverse_steps(self):self.check_failure(GOOD[:-1]+[row(1,'post','step_limit')])
 def test_bad_kind(self):self.check_failure(GOOD[:1]+[row(0,'post','magic')]+GOOD[1:])
 def test_event_after_end(self):self.check_failure(GOOD+[row(11,'post','sample')])
 def test_bad_width(self):self.check_failure(GOOD[:1]+[GOOD[1]+',bad']+GOOD[2:])
 def test_bad_hex(self):self.check_failure(GOOD[:1]+[GOOD[1].replace('06000000','zzzzzzzz')]+GOOD[2:])
 def test_negative_step(self):self.check_failure([GOOD[0].replace('0,pre','-1,pre')]+GOOD[1:])
 def test_out_of_bound(self):self.check_failure(GOOD[:-1]+[row(2000001,'post','step_limit')])
 def test_symlink_rejected(self):
  t,p=make(GOOD)
  try:
   link=p.parent/'link.csv';link.symlink_to(p)
   with self.assertRaises(GateError):audit(link)
  finally:t.cleanup()
 def test_incomplete_capture_is_not_success(self):
  t,p=make(GOOD[:-1])
  try:self.assertFalse(audit(p)['capture_finished_with_marker'])
  finally:t.cleanup()
 def test_jsr_opcode_generic(self):
  rows=[GOOD[0],row(1,'pre','selected','0000410b'),row(1,'post','selected','0000410b'),GOOD[-1]]
  t,p=make(rows)
  try:self.assertEqual(audit(p)['jsr_selected_records'],1)
  finally:t.cleanup()

if __name__=='__main__':unittest.main()