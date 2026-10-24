import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage112_event_log_gate import audit,AuditError

HEAD='stage112_sh2_events_v1\n'
def r(n,k):return f'{n},{k},00000000,00000001,00000001,00\n'
class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.p=Path(t.name)/'events.csv'
    def write(self,s):self.p.write_text(s,encoding='ascii');return self.p
    def bad(self,s):
        with self.assertRaises(AuditError):audit(self.write(s))
    def test_good(self):
        x=audit(self.write(HEAD+r(0,'start')+r(1,'byte_change')+r(10,'sample')+r(20,'step_limit')))
        self.assertEqual(x['control_byte_change_events'],1)
        self.assertTrue(x['step_limit_observed'])
        self.assertFalse(x['full_call_return_proven'])
    def test_short(self):
        x=audit(self.write(HEAD+r(0,'start')))
        self.assertFalse(x['step_limit_observed'])
    def test_no_header(self):self.bad('invalid\n'+r(0,'start'))
    def test_no_start(self):self.bad(HEAD+r(1,'sample'))
    def test_duplicate_start(self):self.bad(HEAD+r(0,'start')+r(0,'start'))
    def test_order(self):self.bad(HEAD+r(0,'start')+r(4,'sample')+r(3,'sample'))
    def test_stop(self):self.bad(HEAD+r(0,'start')+r(10,'step_limit')+r(11,'sample'))
    def test_kind(self):self.bad(HEAD+r(0,'start')+r(1,'return_proven'))
    def test_register(self):self.bad(HEAD+r(0,'start').replace('00000001','0x000001'))
    def test_byte(self):self.bad(HEAD+r(0,'start').replace(',00\n',',0x\n'))
    def test_missing(self):self.bad(HEAD)
    def test_limit(self):self.bad(HEAD+r(0,'start')+r(2000001,'sample'))
    def test_columns(self):self.bad(HEAD+r(0,'start').strip()+',extra\n')
    def test_alias(self):
        p=Path(self.p.parent)/'orig';p.write_text(HEAD+r(0,'start'))
        self.p.symlink_to(p)
        with self.assertRaises(AuditError):audit(self.p)
if __name__=='__main__':unittest.main()