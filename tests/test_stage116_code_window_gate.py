import csv,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage116_code_window_gate import audit,AuditError,HEADER,MAGIC

BASE=0x06000100
PC=BASE+16
PIPE=0x6d00460b
WINDOW=bytearray(48); WINDOW[16:18]=bytes.fromhex('460b')
WINDOW_HEX=WINDOW.hex()
def step_row(kind='step',step='1',window_valid='1',matches='1',window=WINDOW_HEX,pc=f'{PC:08x}',pipe=f'{PIPE:08x}'):
 return [kind,step,'100','jsr','06000100',pc,pipe,'06000200','00000001',f'{PC+2:08x}','6e00000b','06000200','00000001',f'{BASE:08x}',window_valid,matches,window]
def write_log(path,rows,marker='complete'):
 with path.open('w',newline='') as f:
  w=csv.writer(f);w.writerow([MAGIC]);w.writerow(HEADER);w.writerows(rows)
  if marker:w.writerow([marker,'1','100']+['']*(len(HEADER)-3))
class GateTests(unittest.TestCase):
 def test_valid(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';write_log(p,[step_row()]);r=audit(p)
   self.assertTrue(r['capture_complete']);self.assertEqual(r['selected_instruction_words_match_window'],1)
 def test_bad_header(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';p.write_text('wrong\n')
   self.assertRaisesRegex(AuditError,'bad_header',audit,p)
 def test_mismatched_word_flag(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';write_log(p,[step_row(matches='0')])
   self.assertRaisesRegex(AuditError,'word_match_flag',audit,p)
 def test_bad_window_hex(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';write_log(p,[step_row(window='zz')])
   self.assertRaisesRegex(AuditError,'bad_window',audit,p)
 def test_pc_outside_window(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';write_log(p,[step_row(pc=f'{BASE+30:08x}')])
   self.assertRaisesRegex(AuditError,'word_match_flag|pc_outside_window',audit,p)
 def test_invalid_window_no_bytes(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';write_log(p,[step_row(window_valid='0',matches='0',window='')])
   r=audit(p);self.assertEqual(r['windows_without_direct_workram'],1)
 def test_event_after_terminal(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv'
   with p.open('w',newline='') as f:
    w=csv.writer(f);w.writerow([MAGIC]);w.writerow(HEADER);w.writerow(step_row());w.writerow(['complete','1','100']+['']*(len(HEADER)-3));w.writerow(step_row(step='2'))
   self.assertRaisesRegex(AuditError,'row_after_terminal',audit,p)
 def test_missing_complete_marker(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';write_log(p,[step_row()],marker=None)
   self.assertRaisesRegex(AuditError,'capture_incomplete',audit,p)
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);p=root/'x.csv';write_log(p,[step_row()]);ln=root/'ln.csv';ln.symlink_to(p)
   self.assertRaisesRegex(AuditError,'invalid_input',audit,ln)
 def test_no_private_output_fields(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x.csv';write_log(p,[step_row()]);r=audit(p)
   self.assertNotIn('pc_id',r);self.assertNotIn('window_hex',r);self.assertNotIn('opcode',r)
if __name__=='__main__': unittest.main()
