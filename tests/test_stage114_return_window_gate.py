import sys, tempfile, unittest, csv
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage114_return_window_gate import audit, AuditError, HEADER

TRIGGER = 0x06000000
TARGET = 0x06000010
RET = TRIGGER + 4

def hx(n): return f"{n & 0xffffffff:08x}"

def step(rel, glob, *, pc=0x06000100, pc_id=0, pc_if=0,
         pipe_id=0x0100e001, pipe_if=0x0000e002,
         r3=TARGET, r13=1, r15=0x0600ff00, pr=RET, sr=0,
         byte=1, post_pc=None, post_pc_id=0, post_pc_if=0,
         post_pipe_id=0x0100e002, post_pipe_if=0x0000e003,
         post_r3=None, post_r13=None, post_r15=None, post_pr=None,
         post_sr=None, post_byte=None, changed=0, bsr=0, rts=0):
    vals = {
      "kind":"step","relative_step":str(rel),"global_step":str(glob),
      "pre_pc":hx(pc),"pre_pc_id":hx(pc_id),"pre_pc_if":hx(pc_if),
      "pre_pipe_id":hx(pipe_id),"pre_pipe_if":hx(pipe_if),
      "pre_r3":hx(r3),"pre_r13":hx(r13),"pre_r15":hx(r15),"pre_pr":hx(pr),"pre_sr":hx(sr),
      "pre_byte":f"{byte:02x}",
      "post_pc":hx(pc if post_pc is None else post_pc),
      "post_pc_id":hx(post_pc_id),"post_pc_if":hx(post_pc_if),
      "post_pipe_id":hx(post_pipe_id),"post_pipe_if":hx(post_pipe_if),
      "post_r3":hx(r3 if post_r3 is None else post_r3),
      "post_r13":hx(r13 if post_r13 is None else post_r13),
      "post_r15":hx(r15 if post_r15 is None else post_r15),
      "post_pr":hx(pr if post_pr is None else post_pr),
      "post_sr":hx(sr if post_sr is None else post_sr),
      "post_byte":f"{(byte if post_byte is None else post_byte):02x}",
      "byte_changed":str(changed),"target_bsr":str(bsr),"target_rts_candidate":str(rts)
    }
    return [vals[k] for k in HEADER]

def marker(kind, rel, glob):
    return [kind, str(rel), str(glob)] + [""] * 25

def fixture():
    rows=[]
    rows.append(step(1,1,pc=TRIGGER,pc_id=0,pc_if=0,pipe_id=0x0100e000,pipe_if=0x0000e001))
    rows.append(step(2,2,pc=TRIGGER+2,pc_id=0,pc_if=0,pipe_id=0x0100e001,pipe_if=0x0000e002))
    rows.append(step(3,3,pc=TRIGGER+4,pipe_id=0x6a00b000,pipe_if=0x00002300,
                     pr=0x0600ff00,post_pc=0x06001000,post_pr=RET,
                     post_pipe_id=0x9a002300,post_pipe_if=0x00001000,bsr=1))
    rows.append(step(4,4,pc=0x06001002,pipe_id=0x9a002300,pipe_if=0x00001002,
                     r3=TARGET,byte=0,post_byte=1,changed=1,pr=RET,
                     post_pc=0x06001004,post_pipe_id=0x0100e001,post_pipe_if=0x0000e002))
    for n in range(5,10):
        rows.append(step(n,n,pc=0x06001000+n*2,pipe_id=0x0100e001,pipe_if=0x0000e002,pr=RET))
    rows.append(step(10,10,pc=0x06010004,pc_id=0x06010002,pc_if=0x06010004,
                     pipe_id=0x6e00000b,pipe_if=0x00000009,pr=RET,post_pc=RET+2,
                     post_pc_id=0x06010002,post_pc_if=RET,
                     post_pipe_id=0xf5000009,post_pipe_if=0x0000e001,
                     post_pr=RET,rts=1))
    rows.append(step(11,11,pc=RET+2,pc_id=0x06010002,pc_if=RET,
                     pipe_id=0xf5000009,pipe_if=0x0000e001,pr=RET,
                     post_pc=RET+4,post_pc_id=RET,post_pc_if=RET+2,
                     post_pipe_id=0x0100e001,post_pipe_if=0x0000e002,post_pr=RET))
    rows.append(step(12,12,pc=RET+4,pc_id=RET,pc_if=RET+2,
                     pipe_id=0x0100e001,pipe_if=0x0000e002,pr=RET,
                     post_pc=RET+6,post_pc_id=RET+2,post_pc_if=RET+4,
                     post_pipe_id=0x0100e002,post_pipe_if=0x0000e003,post_pr=RET))
    rows.append(step(13,13,pc=RET+6,pipe_id=0x0100e002,pipe_if=0x0000e003,pr=RET))
    rows.append(step(14,14,pc=RET+8,pipe_id=0x0100e003,pipe_if=0x0000e004,pr=RET))
    rows.append(marker("complete",14,14))
    return rows

def write(rows):
    td=tempfile.TemporaryDirectory()
    p=Path(td.name)/"private.csv"
    with p.open("w",encoding="ascii",newline="") as fp:
        fp.write("stage114_return_window_v1\n")
        w=csv.writer(fp);w.writerow(HEADER);w.writerows(rows)
    return td,p

class Stage114GateTests(unittest.TestCase):
    def run_good(self, rows=None):
        td,p=write(fixture() if rows is None else rows)
        try:return audit(p,TRIGGER,TARGET)
        finally:td.cleanup()
    def test_full_observed_return_path(self):
        out=self.run_good()
        self.assertTrue(out["capture_structure_valid"])
        self.assertTrue(out["target_bsr_normal_dispatch_and_return_token"])
        self.assertTrue(out["mov_b_delay_slot_and_target_byte_transition"])
        self.assertTrue(out["rts_normal_dispatch_pr_match_and_return_fetch"])
        self.assertTrue(out["rts_delay_slot_pipeline_match"])
        self.assertTrue(out["return_site_instruction_selected_and_step_completed"])
        self.assertTrue(out["return_pc_pipeline_match"])
        self.assertTrue(out["r13_preserved_on_observed_call_path"])
        self.assertTrue(out["complete_observed_call_return_proven"])
        self.assertFalse(out["all_path_r13_preservation_proven"])
    def test_r13_change_inside_observed_window_not_preserved(self):
        rows = fixture()
        # A transient change and restoration inside the call must not be hidden
        # by matching R13 snapshots at BSR, RTS, and the return-site instruction.
        rows[5][20] = hx(2)
        rows[6][9] = hx(2)
        rows[6][20] = hx(1)
        out = self.run_good(rows)
        self.assertTrue(out["complete_observed_call_return_proven"])
        self.assertFalse(out["r13_preserved_on_observed_call_path"])

    def test_512_step_rows_plus_terminal_marker_accepted(self):
        rows = [step(n, n) for n in range(1, 513)]
        rows.append(marker("event_cap", 512, 512))
        td, p = write(rows)
        try:
            out = audit(p)
            self.assertTrue(out["capture_structure_valid"])
            self.assertEqual(out["recorded_step_rows"], 512)
            self.assertEqual(out["terminal_marker"], "event_cap")
        finally:
            td.cleanup()

    def test_513_step_rows_rejected(self):
        rows = [step(n, n) for n in range(1, 514)]
        rows.append(marker("event_cap", 513, 513))
        td, p = write(rows)
        try:
            with self.assertRaisesRegex(AuditError, "row_limit"):
                audit(p)
        finally:
            td.cleanup()

    def test_large_absolute_global_counter_allowed(self):
        rows = fixture()
        for row in rows:
            if row[0] in ("step", "complete", "step_limit", "event_cap"):
                row[2] = str(int(row[2]) + 198_000_000)
        out = self.run_good(rows)
        self.assertTrue(out["capture_structure_valid"])
        self.assertTrue(out["complete_observed_call_return_proven"])

    def test_global_counter_drift_rejected(self):
        rows = fixture()
        rows[5][2] = str(int(rows[5][2]) + 1)
        td, p = write(rows)
        try:
            with self.assertRaisesRegex(AuditError, "relative_global_step_mismatch"):
                audit(p, TRIGGER, TARGET)
        finally:
            td.cleanup()

    def test_missing_marker_rejected(self):
        rows=fixture()[:-1];td,p=write(rows)
        try:
            with self.assertRaisesRegex(AuditError,"missing_terminal_marker"):audit(p,TRIGGER,TARGET)
        finally:td.cleanup()
    def test_rows_after_marker_rejected(self):
        rows=fixture()+[step(15,15)]
        td,p=write(rows)
        try:
            with self.assertRaisesRegex(AuditError,"rows_after_marker"):audit(p,TRIGGER,TARGET)
        finally:td.cleanup()
    def test_wrong_bsr_dispatch_not_proven(self):
        rows=fixture(); rows[2][6]=hx(0x6b00b000)
        out=self.run_good(rows)
        self.assertFalse(out["target_bsr_normal_dispatch_and_return_token"])
        self.assertFalse(out["complete_observed_call_return_proven"])
    def test_wrong_trigger_not_proven(self):
        out=self.run_good()
        self.assertTrue(out["capture_structure_valid"])
        td,p=write(fixture())
        try:
            result=audit(p,TRIGGER+2,TARGET)
            self.assertFalse(result["target_bsr_normal_dispatch_and_return_token"])
        finally:td.cleanup()
    def test_wrong_r3_target_not_proven(self):
        rows=fixture(); rows[3][8]=hx(TARGET+4)
        out=self.run_good(rows)
        self.assertFalse(out["mov_b_delay_slot_and_target_byte_transition"])
        self.assertFalse(out["complete_observed_call_return_proven"])
    def test_byte_transition_outside_delay_slot_not_proven(self):
        rows=fixture(); rows[3][25]="0"; rows[3][13]="00"; rows[3][24]="00"
        rows[4][25]="1"; rows[4][13]="00"; rows[4][24]="01"
        out=self.run_good(rows)
        self.assertFalse(out["mov_b_delay_slot_and_target_byte_transition"])
    def test_wrong_delay_slot_dispatch_not_proven(self):
        rows=fixture(); rows[3][6]=hx(0x1a002300)
        out=self.run_good(rows)
        self.assertFalse(out["mov_b_delay_slot_and_target_byte_transition"])
    def test_wrong_rts_dispatch_not_proven(self):
        rows=fixture(); rows[9][6]=hx(0xee00000b)
        out=self.run_good(rows)
        self.assertFalse(out["rts_normal_dispatch_pr_match_and_return_fetch"])
    def test_rts_pr_mismatch_not_proven(self):
        rows=fixture(); rows[9][11]=hx(RET+8)
        out=self.run_good(rows)
        self.assertFalse(out["rts_normal_dispatch_pr_match_and_return_fetch"])
    def test_rts_delay_slot_mismatch_not_proven(self):
        rows=fixture(); rows[9][17]=hx(0xf5000009+2)
        out=self.run_good(rows)
        self.assertFalse(out["rts_delay_slot_pipeline_match"])
    def test_return_site_opcode_mismatch_not_proven(self):
        rows=fixture(); rows[10][17]=hx(0x0100e002)
        out=self.run_good(rows)
        self.assertFalse(out["return_site_instruction_selected_and_step_completed"])
    def test_r13_change_reported_but_not_all_paths(self):
        rows=fixture(); rows[11][9]=hx(2)
        out=self.run_good(rows)
        self.assertFalse(out["r13_preserved_on_observed_call_path"])
        self.assertFalse(out["all_path_r13_preservation_proven"])
    def test_step_limit_is_incomplete(self):
        rows=fixture()[:-1]+[marker("step_limit",14,14)]
        out=self.run_good(rows)
        self.assertFalse(out["complete_observed_call_return_proven"])
        self.assertEqual(out["terminal_marker"],"step_limit")
    def test_bad_hex_rejected(self):
        rows=fixture(); rows[2][3]="nothex"
        td,p=write(rows)
        try:
            with self.assertRaisesRegex(AuditError,"bad_hex_field"):audit(p,TRIGGER,TARGET)
        finally:td.cleanup()
    def test_bad_columns_rejected(self):
        rows=fixture(); rows[2].pop()
        td,p=write(rows)
        try:
            with self.assertRaisesRegex(AuditError,"column_count"):audit(p,TRIGGER,TARGET)
        finally:td.cleanup()
    def test_symlink_rejected(self):
        td,p=write(fixture())
        try:
            link=p.parent/"link.csv";link.symlink_to(p)
            with self.assertRaisesRegex(AuditError,"invalid_input"):audit(link,TRIGGER,TARGET)
        finally:td.cleanup()

if __name__=="__main__": unittest.main()
