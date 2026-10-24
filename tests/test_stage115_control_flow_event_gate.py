import csv, json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage115_control_flow_event_gate import audit, AuditError, HEADER, MAGIC

def h(x): return f"{x & 0xffffffff:08x}"

def row(step, *, control="none", pre_rpc=0x1000, pre_pc_id=0x1000, pre_pc_if=0x1002,
        pre_pid=0x01000009, pre_pif=0x01000009, pre_pr=0x1004, pre_r13=1, pre_r15=0x8000,
        post_rpc=0x1002, post_pc_id=0x1002, post_pc_if=0x1004, post_pid=0x01000009,
        post_pif=0x01000009, post_pr=0x1004, post_r13=1, post_r15=0x8000,
        target_bsr=0, target_rts=0):
    vals=[pre_rpc,pre_pc_id,pre_pc_if,pre_pid,pre_pif,pre_pr,pre_r13,pre_r15,
          post_rpc,post_pc_id,post_pc_if,post_pid,post_pif,post_pr,post_r13,post_r15]
    d={"kind":"step","relative_step":str(step),"global_step":str(1000+step)}
    d.update({k:h(v) for k,v in zip(HEADER[3:19],vals)})
    d.update(control_kind=control,r13_changed="1" if pre_r13!=post_r13 else "0",
             target_bsr=str(target_bsr),target_rts_candidate=str(target_rts))
    return d

def fixture(nested=False, change=True):
    # Target BSR -> delay slot -> callee; optional R13 transitions; target RTS -> delay -> return site.
    rows=[]
    rows.append(row(1))
    rows.append(row(2,control="bsr",pre_rpc=0x1004,pre_pc_id=0x1000,pre_pc_if=0x1002,
                    pre_pid=0x6a00b001,pre_pif=0x01000009,pre_pr=0x0ff0,
                    post_rpc=0x2002,post_pc_id=0x1002,post_pc_if=0x2000,post_pid=0x85001234,
                    post_pif=0x01000009,post_pr=0x1004,target_bsr=1))
    rows.append(row(3,pre_rpc=0x2002,pre_pc_id=0x1002,pre_pc_if=0x1ffe,
                    pre_pid=0x85001234,pre_pif=0x01000009,
                    post_rpc=0x2004,post_pc_id=0x2000,post_pc_if=0x2002,post_pid=0x01005678,
                    post_pif=0x01000009))
    rows.append(row(4,pre_rpc=0x2004,pre_pc_id=0x2000,pre_pc_if=0x2002,
                    pre_pid=0x01005678,pre_pif=0x01000009,
                    post_rpc=0x2006,post_pc_id=0x2002,post_pc_if=0x2004,post_pid=0x02000009,
                    post_pif=0x02000009))
    if nested:
        rows.append(row(5,control="jsr",pre_rpc=0x2008,pre_pc_id=0x2004,pre_pc_if=0x2006,
                        pre_pid=0x6d00400b,pre_pif=0x02000009,pre_pr=0x1004,
                        post_rpc=0x3002,post_pc_id=0x2006,post_pc_if=0x3000,post_pid=0x85002222,
                        post_pif=0x02000009,post_pr=0x2008))
        rows.append(row(6,pre_rpc=0x3002,pre_pc_id=0x2006,pre_pc_if=0x2ffe,
                        pre_pid=0x85002222,pre_pif=0x02000009,
                        post_rpc=0x3004,post_pc_id=0x3000,post_pc_if=0x3002,post_pid=0x01003333,
                        post_pif=0x01003333))
        rows.append(row(7,pre_rpc=0x3004,pre_pc_id=0x3000,pre_pc_if=0x3002,
                        pre_pid=0x01003333,pre_pif=0x01003333,
                        post_rpc=0x3006,post_pc_id=0x3002,post_pc_if=0x3004,post_pid=0x02000009,
                        post_pif=0x02000009))
        rows.append(row(8,control="rts",pre_rpc=0x3008,pre_pc_id=0x3004,pre_pc_if=0x3006,
                        pre_pid=0x6e00000b,pre_pif=0x02000009,pre_pr=0x2008,
                        post_rpc=0x200a,post_pc_id=0x3006,post_pc_if=0x2008,post_pid=0xf5000009,
                        post_pif=0x02000009,post_pr=0x2008))
        rows.append(row(9,pre_rpc=0x200a,pre_pc_id=0x3006,pre_pc_if=0x2008,
                        pre_pid=0xf5000009,pre_pif=0x02000009,
                        post_rpc=0x200c,post_pc_id=0x2008,post_pc_if=0x200a,post_pid=0x03001234,
                        post_pif=0x03001234))
        rows.append(row(10,pre_rpc=0x200c,pre_pc_id=0x2008,pre_pc_if=0x200a,
                        pre_pid=0x03001234,pre_pif=0x03001234,
                        post_rpc=0x200e,post_pc_id=0x200a,post_pc_if=0x200c,post_pid=0x04000009,
                        post_pif=0x04000009))
    else:
        rows.append(row(5,pre_rpc=0x2008,pre_pc_id=0x2004,pre_pc_if=0x2006,
                        pre_pid=0x02000009,pre_pif=0x02000009,
                        post_rpc=0x200a,post_pc_id=0x2006,post_pc_if=0x2008,post_pid=0x02000009,
                        post_pif=0x02000009))
    if change:
        rows.append(row(11 if nested else 6,pre_rpc=0x2010,pre_pc_id=0x2010,pre_pc_if=0x2012,
                        pre_pid=0x0100ed00,pre_pif=0x01000009,pre_r13=1,
                        post_rpc=0x2012,post_pc_id=0x2012,post_pc_if=0x2014,post_pid=0x01000009,
                        post_pif=0x01000009,post_r13=0))
        rows.append(row(12 if nested else 7,pre_rpc=0x2014,pre_pc_id=0x2014,pre_pc_if=0x2016,
                        pre_pid=0x0100ed01,pre_pif=0x01000009,pre_r13=0,
                        post_rpc=0x2016,post_pc_id=0x2016,post_pc_if=0x2018,post_pid=0x01000009,
                        post_pif=0x01000009,post_r13=1))
    # RTS target return follows after any optional nested call and R13 transitions.
    start=13 if nested else (8 if change else 6)
    # ensure steps are contiguous only where required; next two steps after RTS are always present
    rows.append(row(start,control="rts",pre_rpc=0x200c,pre_pc_id=0x2008,pre_pc_if=0x200a,
                    pre_pid=0x6e00000b,pre_pif=0x04000009 if nested else 0x02000009,pre_pr=0x1004,
                    post_rpc=0x1006,post_pc_id=0x200a,post_pc_if=0x1004,post_pid=0xf5000009,
                    post_pif=0x04000009 if nested else 0x02000009,post_pr=0x1004,target_rts=1))
    rows.append(row(start+1,pre_rpc=0x1006,pre_pc_id=0x200a,pre_pc_if=0x1004,
                    pre_pid=0xf5000009,pre_pif=0x04000009 if nested else 0x02000009,
                    post_rpc=0x1008,post_pc_id=0x1004,post_pc_if=0x1006,post_pid=0x03001234,
                    post_pif=0x03001234))
    rows.append(row(start+2,pre_rpc=0x1008,pre_pc_id=0x1004,pre_pc_if=0x1006,
                    pre_pid=0x03001234,pre_pif=0x03001234,
                    post_rpc=0x100a,post_pc_id=0x1006,post_pc_if=0x1008,post_pid=0x04000009,
                    post_pif=0x04000009))
    return rows

def write_trace(rows, marker="complete"):
    tmp=tempfile.NamedTemporaryFile(mode="w",encoding="ascii",newline="",delete=False)
    with tmp:
        wr=csv.writer(tmp);wr.writerow(MAGIC);wr.writerow(HEADER)
        for d in rows: wr.writerow([d[k] for k in HEADER])
        tail=[marker,str(int(rows[-1]["relative_step"])),str(int(rows[-1]["global_step"])+1)]+[""]*(len(HEADER)-3)
        wr.writerow(tail)
    return Path(tmp.name)

class Stage115EventGateTests(unittest.TestCase):
    def test_valid_boundary_preservation_with_intermediate_r13_changes(self):
        p=write_trace(fixture(change=True))
        try:
            out=audit(p)
            self.assertTrue(out["target_call_r13_entry_return_equal"])
            self.assertFalse(out["r13_unchanged_throughout_target_call"])
            self.assertEqual(out["target_window_r13_change_events"],2)
            self.assertFalse(out["all_path_r13_preservation_proven"])
        finally:p.unlink()

    def test_valid_nested_call_stack(self):
        p=write_trace(fixture(nested=True,change=True))
        try:
            out=audit(p)
            self.assertTrue(out["inferred_call_stack_closed_at_target_return"])
            self.assertEqual(out["normal_jsr_events"],1)
            self.assertEqual(out["inferred_returned_frames_r13_boundary_mismatches"],0)
        finally:p.unlink()

    def test_rejects_missing_delay_slot(self):
        rows=fixture(change=False)
        rows=[x for x in rows if int(x["relative_step"])!=3]
        p=write_trace(rows)
        try:
            with self.assertRaisesRegex(AuditError,"missing_control_window"):audit(p)
        finally:p.unlink()

    def test_rejects_bad_selector(self):
        rows=fixture(change=False)
        rows[1]["pre_pipe_id"]=h(0x0100b001)
        p=write_trace(rows)
        try:
            with self.assertRaisesRegex(AuditError,"bsr_selector_mismatch"):audit(p)
        finally:p.unlink()

    def test_rejects_wrong_return_token(self):
        rows=fixture(change=False)
        target_rts=next(x for x in rows if x["target_rts_candidate"]=="1")
        target_rts["pre_pr"]=h(0xdeadbeef)
        target_rts["post_pc_if"]=h(0xdeadbeef)
        return_site=next(x for x in rows if int(x["relative_step"])==int(target_rts["relative_step"])+2)
        return_site["pre_pc_id"]=h(0xdeadbeef)
        return_site["pre_pc_if"]=h(0xdeadbef1)
        p=write_trace(rows)
        try:
            with self.assertRaisesRegex(AuditError,"target_return_token_mismatch"):audit(p)
        finally:p.unlink()

    def test_rejects_incomplete_capture(self):
        p=write_trace(fixture(change=False),marker="step_limit")
        try:
            with self.assertRaisesRegex(AuditError,"capture_incomplete"):audit(p)
        finally:p.unlink()

    def test_rejects_any_row_after_terminal_marker(self):
        rows=fixture(change=False)
        p=write_trace(rows,marker="complete")
        try:
            final_row=rows[-1]
            with p.open("a",encoding="ascii",newline="") as f:
                csv.writer(f).writerow([final_row[k] for k in HEADER])
            with self.assertRaisesRegex(AuditError,"row_after_terminal"): audit(p)
        finally:p.unlink()

    def test_rejects_terminal_marker_before_last_observed_step(self):
        rows=fixture(change=False)
        p=write_trace(rows,marker="complete")
        try:
            lines=p.read_text(encoding="ascii").splitlines()
            fields=next(csv.reader([lines[-1]]))
            fields[1]="0"
            lines[-1]=",".join(fields)
            p.write_text("\n".join(lines)+"\n",encoding="ascii")
            with self.assertRaisesRegex(AuditError,"terminal_before_last_step"): audit(p)
        finally:p.unlink()

    def test_rejects_symlink_input(self):
        source=write_trace(fixture(change=False))
        link=source.with_name(source.name+" .link".replace(" ",""))
        try:
            link.symlink_to(source)
            with self.assertRaisesRegex(AuditError,"invalid_input"): audit(link)
        finally:
            if link.exists() or link.is_symlink(): link.unlink()
            source.unlink()

    def test_rejects_event_count_above_hard_limit(self):
        p=Path(tempfile.mkstemp()[1])
        try:
            with p.open("w",encoding="ascii",newline="") as f:
                wr=csv.writer(f); wr.writerow(MAGIC); wr.writerow(HEADER)
                for i in range(1,16386):
                    d=row(i)
                    wr.writerow([d[k] for k in HEADER])
                tail=["complete","16385","17385"]+[""]*(len(HEADER)-3)
                wr.writerow(tail)
            with self.assertRaisesRegex(AuditError,"row_limit"): audit(p)
        finally:p.unlink()

    def test_safe_output_has_no_raw_register_fields(self):
        p=write_trace(fixture(change=True))
        try:
            encoded=json.dumps(audit(p))
            self.assertNotIn("pre_r13",encoded)
            self.assertNotIn("pre_pc_id",encoded)
            self.assertNotIn("deadbeef",encoded)
        finally:p.unlink()

if __name__=='__main__':unittest.main()
