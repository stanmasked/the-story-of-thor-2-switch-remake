import csv, tempfile, unittest
from pathlib import Path
from tools.stage113_opcode_window_gate import audit, AuditError, HEADER


def row(kind, rel, glob, pre_opcode='00000000', pre_byte='00', post_byte='', post_pc='00000000', post_pr='00000000', candidate='0'):
    d={k:'' for k in HEADER}
    d.update(kind=kind,relative_step=str(rel),global_step=str(glob),pre_pc='00000010',pre_pc_id='00000010',pre_pc_if='00000012',pre_pipe_id=pre_opcode,pre_pipe_if='00000000',pre_r3='06000010',pre_r13='00000001',pre_r15='00000100',pre_pr='00000020',pre_sr='00000000',pre_byte=pre_byte,byte_changed='0',rpc_equals_pr_candidate='0')
    if kind=='step':
        d.update(post_pc=post_pc,post_pc_id='00000012',post_pc_if='00000014',post_pipe_id='00000000',post_pipe_if='00000000',post_r3='06000010',post_r13='00000001',post_r15='00000100',post_pr=post_pr,post_sr='00000000',post_byte=post_byte or pre_byte,byte_changed='1' if pre_byte!=(post_byte or pre_byte) else '0',rpc_equals_pr_candidate=candidate)
    return [d[k] for k in HEADER]


def make_file(rows):
    t=tempfile.NamedTemporaryFile('w',encoding='ascii',newline='',delete=False)
    with t:
        t.write('stage113_opcode_witness_v1\n')
        w=csv.writer(t);w.writerow(HEADER);w.writerows(rows)
    return Path(t.name)

class Stage113GateTests(unittest.TestCase):
    def test_valid_transition_and_rts_candidate_window(self):
        rows=[row('context',-1,1)]
        rows.append(row('step',1,2,pre_opcode='000023d0',pre_byte='00',post_byte='01'))
        rows.append(row('step',2,3,pre_opcode='0000000b',pre_byte='01',post_byte='01',post_pc='00000020',post_pr='00000020',candidate='1'))
        for n in range(3,67): rows.append(row('step',n,n+1,pre_opcode='00000000',pre_byte='01',post_byte='01'))
        p=make_file(rows)
        try:
            out=audit(p)
            self.assertTrue(out['capture_structure_valid'])
            self.assertEqual(out['target_byte_transition_rows'],1)
            self.assertEqual(out['rpc_equals_pr_candidate_rows'],1)
            self.assertTrue(out['candidate_has_rts_opcode_and_return_pc_match'])
            self.assertTrue(out['candidate_window_complete'])
            self.assertFalse(out['complete_call_return_proven'])
        finally: p.unlink()

    def test_bad_magic_rejected(self):
        p=make_file([row('step',1,1)])
        p.write_text('wrong\n'+p.read_text().split('\n',1)[1],encoding='ascii')
        try:
            with self.assertRaisesRegex(AuditError,'bad_magic'): audit(p)
        finally: p.unlink()

    def test_wrong_column_count_rejected(self):
        p=make_file([row('step',1,1)])
        p.write_text(p.read_text().replace('step,1,1,','step,1,',1),encoding='ascii')
        try:
            with self.assertRaises(AuditError): audit(p)
        finally: p.unlink()

    def test_multiple_byte_changes_rejected(self):
        rows=[row('step',1,1,pre_byte='00',post_byte='01'),row('step',2,2,pre_byte='01',post_byte='00')]
        p=make_file(rows)
        try:
            with self.assertRaisesRegex(AuditError,'multiple_byte_transitions'): audit(p)
        finally: p.unlink()

    def test_multiple_candidates_rejected(self):
        rows=[row('step',1,1,pre_opcode='0000000b',post_pc='00000020',post_pr='00000020',candidate='1'),row('step',2,2,pre_opcode='0000000b',post_pc='00000020',post_pr='00000020',candidate='1')]
        p=make_file(rows)
        try:
            with self.assertRaisesRegex(AuditError,'multiple_candidates'): audit(p)
        finally: p.unlink()

    def test_context_cannot_have_post_values(self):
        r=row('context',-1,1);r[14]='00000010'
        p=make_file([r])
        try:
            with self.assertRaisesRegex(AuditError,'context_has_post'): audit(p)
        finally: p.unlink()

    def test_nonmonotonic_steps_rejected(self):
        p=make_file([row('step',2,2),row('step',1,3)])
        try:
            with self.assertRaisesRegex(AuditError,'relative_order'): audit(p)
        finally: p.unlink()

if __name__ == '__main__': unittest.main()