import sys,unittest,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage112_bounded_sh2_liveness_audit import read,tail_cycle,audit,AuditError

def row(n,phase,rpc=100,r13=1,pr=200):
    values=[0,0,rpc,r13,pr,2,3,4,5,6]
    return ','.join([str(n),phase]+[f'{v:08x}' for v in values])+'\n'

def contents(pairs):
    return 'stage109_sh2_steps_v1\n'+''.join(row(i,ph, rpc=20+(i%4)) for i in range(pairs) for ph in ('pre','post'))

class Tests(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory();self.addCleanup(self.d.cleanup)
        self.f=Path(self.d.name)/'trace.csv'
    def write(self,s):self.f.write_text(s,encoding='ascii');return self.f
    def test_valid(self):self.assertEqual(len(read(self.write(contents(32)))),32)
    def test_tail_four(self):self.assertEqual(tail_cycle([1,2,3,4]*80),(4,80))
    def test_short_not_cycle(self):self.assertEqual(tail_cycle([1,2,3,4]),(0,0))
    def test_sporadic_not_cycle(self):self.assertEqual(tail_cycle([1,2,3,4]*4+[1,2,4,3]),(0,0))
    def test_safe(self):
        x=audit(self.write(contents(32)))
        self.assertEqual(x['rpc_tail_cycle_period'],4)
        self.assertFalse(x['full_bsr_rts_return_verified'])
        self.assertFalse(x['exact_executing_opcode_attributed'])
        self.assertFalse(x['private_pc_or_register_values_emitted'])
        self.assertNotIn('000000',str(x))
    def assert_bad(self,text):
        with self.assertRaises(AuditError):read(self.write(text))
    def test_empty(self):self.assert_bad('')
    def test_no_rows(self):self.assert_bad('stage109_sh2_steps_v1\n')
    def test_header(self):self.assert_bad('not_real\n'+contents(2).split('\n',1)[1])
    def test_partial(self):self.assert_bad('stage109_sh2_steps_v1\n'+row(0,'pre'))
    def test_missing_pre(self):self.assert_bad('stage109_sh2_steps_v1\n'+row(0,'post'))
    def test_reversed(self):self.assert_bad('stage109_sh2_steps_v1\n'+row(0,'post')+row(0,'pre'))
    def test_skipped_n(self):self.assert_bad('stage109_sh2_steps_v1\n'+row(4,'pre')+row(4,'post'))
    def test_extra_columns(self):self.assert_bad('stage109_sh2_steps_v1\n'+row(0,'pre').strip()+',00\n'+row(0,'post'))
    def test_bad_hex(self):self.assert_bad('stage109_sh2_steps_v1\n'+row(0,'pre').replace('00000001','0000zzzz')+row(0,'post'))
    def test_strict_encoding(self):self.assert_bad('stage109_sh2_steps_v1\n'+row(0,'pre').replace('00000001','0x000001')+row(0,'post'))
    def test_pr_change_not_return(self):
        s='stage109_sh2_steps_v1\n'+row(0,'pre',pr=1)+row(0,'post',pr=1)+row(1,'pre',pr=2)+row(1,'post',pr=2)
        x=audit(self.write(s));self.assertTrue(x['pr_changed_in_observed_pre_step_states']);self.assertFalse(x['full_bsr_rts_return_verified'])
    def test_symlink(self):
        src=Path(self.d.name)/'src';src.write_text(contents(4))
        self.f.symlink_to(src)
        with self.assertRaises(AuditError):read(self.f)

if __name__=='__main__':unittest.main()