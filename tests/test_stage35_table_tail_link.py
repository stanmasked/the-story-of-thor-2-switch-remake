"""Stage35 synthetic pointer-table, tail-call and wrapper tests. No game data."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
try:
    from test_stage31_entry_guard_audit import fixture as stage31_fixture, put
except ImportError:
    from test_stage31_entry_guard_audit import synthetic as stage31_fixture, put
from stage35_table_tail_link import (
    CODE_LOAD_BASE, movl_literal, branch_destination, extended_reader_entries,
    discover_inner_wrappers, find_tail_callers, find_table_runs,
    disc_word_counts, summarize_references,
)

WRAPPER = 0x700
TAIL = 0x760
BRANCH = 0x790
TABLE = 0x900
ENTRIES = (0x100, 0x300, TAIL, 0x500, 0x440, 0x600)


def fixture(mutation=None, table=True, tail=True, wrapper=True,
            table_cell_reference=True):
    data = bytearray(stage31_fixture())
    data.extend(bytes(0x500))
    if wrapper:
        for pos, op in ((WRAPPER, 0x4F22), (WRAPPER+2, 0xD307),
                        (WRAPPER+4, 0x7FFC), (WRAPPER+6, 0x2F42),
                        (WRAPPER+8, 0x430B), (WRAPPER+10, 0xE502)):
            put(data, pos, op)
        data[WRAPPER+0x20:WRAPPER+0x24] = (CODE_LOAD_BASE+0x500).to_bytes(4, "big")
    if tail:
        for pos, op in (
            (TAIL, 0x2FE6), (TAIL+2, 0x4F22), (TAIL+4, 0x6E43),
            (BRANCH-4, 0x64E3), (BRANCH-2, 0x4F26),
            (BRANCH, 0xA000 | (((WRAPPER-BRANCH-4)//2) & 0xFFF)),
            (BRANCH+2, 0x6EF6)
        ):
            put(data, pos, op)
    if table:
        for i, target in enumerate(ENTRIES):
            data[TABLE+i*4:TABLE+i*4+4] = (CODE_LOAD_BASE+target).to_bytes(4,"big")
        put(data, 0xA00, 0xD207)
        data[0xA20:0xA24] = (CODE_LOAD_BASE+TABLE).to_bytes(4,"big")
        if table_cell_reference:
            put(data, 0xA40, 0xD207)
            data[0xA60:0xA64] = (CODE_LOAD_BASE+TABLE+2*4).to_bytes(4,"big")
    if mutation:
        put(data, *mutation)
    return bytes(data)


class Stage35Tests(unittest.TestCase):
    def report(self, *args, **kwargs):
        return summarize_references(fixture(*args, **kwargs))["analysis"]

    def test_full_static_chain(self):
        self.assertEqual(self.report()["full_function_table_to_tail_to_wrapper_chains"],1)

    def test_table_size(self):
        self.assertEqual(self.report()["table_entry_count"],6)

    def test_one_based_slot(self):
        self.assertEqual(self.report()["tail_function_slot_one_based"],3)

    def test_linked_reader(self):
        self.assertEqual(extended_reader_entries(fixture()),{0x500})

    def test_wrapper_one_match(self):
        self.assertEqual(len(discover_inner_wrappers(fixture())),1)

    def test_tail_one_match(self):
        self.assertEqual(len(find_tail_callers(fixture(),WRAPPER)),1)

    def test_tail_restores_registers(self):
        r=self.report()
        self.assertTrue(r["tail_bra_delay_slot_restores_r14"])
        self.assertTrue(r["tail_route_restores_pr_before_bra"])

    def test_outer_pointer_only(self):
        r=self.report()
        self.assertEqual(r["absolute_pointer_to_tail_in_executable"],
                         {"big_endian":1,"little_endian":0})

    def test_inner_pointer_not_present(self):
        self.assertEqual(self.report()["absolute_pointer_to_inner_wrapper_in_executable"],
                         {"big_endian":0,"little_endian":0})

    def test_table_base_referenced(self):
        self.assertEqual(self.report()["table_base_address_occurrences"],1)

    def test_cell_address_referenced(self):
        self.assertEqual(self.report()["table_entry_cell_address_occurrences"],1)

    def test_movl_load_references(self):
        r=self.report()
        self.assertEqual(r["pc_relative_movl_refs_to_table_base"],1)
        self.assertEqual(r["pc_relative_movl_refs_to_entry_cell"],1)

    def test_word_pc_alignment(self):
        self.assertEqual(movl_literal(fixture(),0xA00),
                         (0xA20,CODE_LOAD_BASE+TABLE,2))
        self.assertIsNone(movl_literal(fixture(),0xA01))

    def test_relative_bra(self):
        code=int.from_bytes(fixture()[BRANCH:BRANCH+2],"big")
        self.assertEqual(branch_destination(BRANCH,code),("BRA",WRAPPER))

    def test_bsr_signed_reference(self):
        self.assertEqual(branch_destination(0x100,0xBFFE),("BSR",0x100))

    def test_invalid_branch(self):
        self.assertIsNone(branch_destination(0x100,0x0009))

    def test_broken_wrapped_jsr(self):
        self.assertEqual(self.report(mutation=(WRAPPER+8,0x0009))
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_invalid_r5_delay(self):
        self.assertEqual(self.report(mutation=(WRAPPER+10,0x0009))
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_missing_tail_bra(self):
        self.assertEqual(self.report(mutation=(BRANCH,0x0009))
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_missing_bra_restore(self):
        self.assertEqual(self.report(mutation=(BRANCH+2,0x0009))
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_missing_pr_restore(self):
        self.assertEqual(self.report(mutation=(BRANCH-2,0x0009))
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_missing_r14_copy(self):
        self.assertEqual(self.report(mutation=(TAIL+4,0x0009))
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_no_table(self):
        self.assertEqual(self.report(table=False)
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_invalid_pointer_cell(self):
        self.assertEqual(self.report(mutation=(TABLE+2*4,0x0000))
                         ["full_function_table_to_tail_to_wrapper_chains"],0)

    def test_bad_aligned_table_neighbor(self):
        self.assertLess(self.report(mutation=(TABLE+4*4,0))
                        ["table_entry_count"],6)

    def test_missing_pc_entry_pointer_allowed(self):
        r=self.report(table_cell_reference=False)
        self.assertEqual(r["full_function_table_to_tail_to_wrapper_chains"],1)
        self.assertEqual(r["pc_relative_movl_refs_to_entry_cell"],0)

    def test_disc_stream_scan(self):
        import tempfile
        payload=(b"012"+(CODE_LOAD_BASE+TAIL).to_bytes(4,"big")+
                 b"x"*1020+(CODE_LOAD_BASE+WRAPPER).to_bytes(4,"little"))
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/"synthetic.iso"
            image.write_bytes(payload)
            r=disc_word_counts(image,{"outer":CODE_LOAD_BASE+TAIL,
                                      "inner":CODE_LOAD_BASE+WRAPPER})
        self.assertEqual(r["outer"],{"big_endian":1,"little_endian":0})
        self.assertEqual(r["inner"],{"big_endian":0,"little_endian":1})

    def test_no_program_offsets_in_output(self):
        r=self.report()
        for key in ("table_start","table_end","entry_cell","entry",
                    "target_reader","literal_pos","tail_branch",
                    "program_offset","raw_bytes"):
            self.assertNotIn(key,r)

    def test_empty(self):
        self.assertEqual(summarize_references(b"")["analysis"]
                         ["full_function_table_to_tail_to_wrapper_chains"],0)


if __name__=="__main__":
    unittest.main()
