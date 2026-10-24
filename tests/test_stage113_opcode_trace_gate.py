import csv,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage113_opcode_trace_gate import audit,TraceError,HEADER

def row(cpu,step,phase,opcode,pc=0x1000,rpc=0x1004,r13=1,pr=0x2004):
    pipe=opcode
    return [str(cpu),str(step),phase,f"{pipe:08x}",f"{opcode:04x}",f"{pipe>>24:08x}",
            f"{pc:08x}",f"{pc+2:08x}",f"{pc+4:08x}",f"{rpc:08x}",f"{r13:08x}",f"{pr:08x}"]

def trace(*pairs):
    out=HEADER+"\n"
    for cpu,step,opcode,pre,post in pairs:
        out+=",".join(row(cpu,step,"pre",opcode,**pre))+"\n"
        out+=",".join(row(cpu,step,"post",opcode,**post))+"\n"
    return out

class GateTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/"trace.csv"
    def write(self,s):self.path.write_text(s,encoding="ascii");return self.path
    def bad(self,s):
        with self.assertRaises(TraceError):audit(self.write(s),16)
    def test_valid_bsr_rts_is_only_candidate(self):
        data=trace((0,0,0xB001,{"pr":0x1004},{"pr":0x2004}),
                   (0,1,0x000B,{"pr":0x2004},{"pr":0x2004}))
        result=audit(self.write(data),16)
        self.assertEqual(result["completed_bsr_dispatches"],1)
        self.assertEqual(result["completed_rts_dispatches"],1)
        self.assertEqual(result["rts_after_bsr_same_pr_candidates"],1)
        self.assertFalse(result["actual_call_return_proven"])
    def test_complete_configured_limit(self):
        pairs=[]
        for i in range(16):
            pairs.append((0,i,0x0009,{"pc":0x1000+i*2},{"pc":0x1002+i*2}))
        result=audit(self.write(trace(*pairs)),16)
        self.assertTrue(result["configured_step_limit_reached_for_all_traced_cpus"])
        self.assertEqual(result["completed_instruction_pairs"],16)
    def test_empty_rejected(self):self.bad(HEADER+"\n")
    def test_wrong_header_rejected(self):self.bad("private\n")
    def test_incomplete_pre_post_rejected(self):
        self.bad(HEADER+"\n"+",".join(row(0,0,"pre",0x0009))+"\n")
    def test_orphan_post_rejected(self):
        self.bad(HEADER+"\n"+",".join(row(0,0,"post",0x0009))+"\n")
    def test_step_gap_rejected(self):
        self.bad(trace((0,0,0x0009,{},{}),(0,2,0x0009,{},{})))
    def test_pipe_opcode_mismatch_rejected(self):
        line=",".join(row(0,0,"pre",0x0009)).replace(",0009,00000000,",",0008,00000000,")
        self.bad(HEADER+"\n"+line+"\n")
    def test_pre_post_opcode_mismatch_rejected(self):
        data=HEADER+"\n"+",".join(row(0,0,"pre",0x0009))+"\n"+",".join(row(0,0,"post",0x000B))+"\n"
        self.bad(data)
    def test_bad_cpu_rejected(self):
        self.bad(HEADER+"\n"+",".join(row(2,0,"pre",0x0009))+"\n")
    def test_symlink_rejected(self):
        original=self.path.with_name("original.csv")
        original.write_text(HEADER+"\n"+",".join(row(0,0,"pre",0x0009))+"\n",encoding="ascii")
        self.path.symlink_to(original)
        with self.assertRaises(TraceError):audit(self.path,16)
    def test_private_values_not_in_aggregate_schema(self):
        result=audit(self.write(trace((0,0,0x0009,{},{}))),16)
        self.assertNotIn("private_pc",result)
        self.assertNotIn("opcode_words",result)
if __name__=="__main__":unittest.main()
