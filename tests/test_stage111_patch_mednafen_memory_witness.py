"""Synthetic-only tests. No original Saturn game, BIOS, addresses or raw trace."""
import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from stage111_patch_mednafen_memory_witness import patch, SIGNATURE, WITNESS
from stage109_patch_mednafen_observer import patch as stage109_patch
BASE='''#include <mednafen/mednafen.h>\nnamespace MDFN_IEN_SS {\nSH7095 CPU[2]{ {"a",0,nullptr}, {"b",1,nullptr} };\nstatic uint16 WorkRAMH[1024 * 1024 / sizeof(uint16)];\nvoid loop() {\n CPU[0].Step<0, EmulateICache, DebugMode>();\n}\n}\n'''

class Stage111PatchTests(unittest.TestCase):
    def setUp(self):self.source=stage109_patch(BASE)
    def test_patch_applies(self):self.assertIn(SIGNATURE,patch(self.source))
    def test_patch_keeps_old_trace(self):self.assertIn('stage109_sh2_steps_v1',patch(self.source))
    def test_two_brackets_around_same_cpu_step(self):
        s=patch(self.source)
        a=s.index('stage111_witness.Record(CPU[0],"pre")')
        b=s.index('CPU[0].Step<0, EmulateICache, DebugMode>();')
        c=s.index('stage111_witness.Record(CPU[0],"post")')
        self.assertLess(a,b);self.assertLess(b,c)
    def test_reader_uses_direct_backing_memory(self):self.assertIn('ne16_rbo_be<uint8>(WorkRAMH',patch(self.source))
    def test_no_mmio_reads(self):self.assertNotIn('BSC_BusRead',WITNESS)
    def test_direct_read_after_array_declaration(self):
        s=patch(self.source);self.assertLess(s.index('static uint16 WorkRAMH['),s.index(SIGNATURE))
    def test_fail_without_ram_backing(self):
        with self.assertRaisesRegex(ValueError,'unsupported_high_ram_backing'):patch(self.source.replace('WorkRAMH','WorkRAML'))
    def test_fail_without_stage109(self):
        with self.assertRaisesRegex(ValueError,'stage109_observer_required'):patch(BASE)
    def test_fail_no_pre_anchor(self):
        with self.assertRaisesRegex(ValueError,'record_anchors_mismatch'):patch(self.source.replace('Record(CPU[0],"pre")','Record(CPU[1],"pre")'))
    def test_fail_no_post_anchor(self):
        with self.assertRaisesRegex(ValueError,'record_anchors_mismatch'):patch(self.source.replace('Record(CPU[0],"post")','Record(CPU[1],"post")'))
    def test_repatch_forbidden(self):
        with self.assertRaisesRegex(ValueError,'already_patched_stage111'):patch(patch(self.source))
    def test_only_with_explicit_enable(self):self.assertIn('std::strcmp(yes,"1")',WITNESS)
    def test_pc_runtime_only(self):self.assertIn('STAGE111_RAM_WITNESS_PC',WITNESS)
    def test_destination_runtime_only(self):self.assertIn('STAGE111_RAM_WITNESS_OUT',WITNESS)
    def test_pre_only_trigger(self):self.assertIn('if(std::strcmp(phase,"pre")) return;',WITNESS)
    def test_bounds_reject_untrusted_mmio(self):self.assertIn('address>=0x06000000U && address<0x08000000U',WITNESS)
    def test_max_steps_bounded(self):self.assertIn('v>4096',WITNESS)
    def test_no_private_game_path_or_address(self):
        s=patch(self.source)
        self.assertNotIn('/mnt/data',s)
        self.assertNotIn('The Story of Thor',s)
        self.assertNotIn('.iso',s)
    def test_trace_format_header(self):self.assertIn('stage111_sh2_highram_witness_v1',WITNESS)

if __name__=='__main__':unittest.main()