"""Stage108 synthetic-only regression tests; never authenticates runtime."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'tools'))
from stage108_service_slot_external_crosscheck import (SafeInputError, safe_crosscheck)


class SlotCrosscheckTests(unittest.TestCase):
    def run_ok(self):
        return safe_crosscheck(slot_text="06000344", iso_verified=True,bios_verified=True)
    def test_matching_documented_slot(self):
        self.assertTrue(self.run_ok()['analysis']['observed_private_slot_matches_independent_public_sgl_example'])
    def test_r13_remains_unproved(self):
        a=self.run_ok()['analysis']
        self.assertFalse(a['unconditional_r13_preservation_proven'])
        self.assertFalse(a['actual_runtime_callee_return_observed'])
        self.assertFalse(a['actual_bios_callee_identity_independently_verified'])
    def test_no_private_values_in_output(self):
        text=__import__('json').dumps(self.run_ok())
        self.assertNotIn('06000344',text)
        self.assertNotIn('000007c0',text)
    def test_invalid_slot_rejected(self):
        for s in ('', '123', '000000001', '../secret', '0x6000344', '???', '1234567G'):
            with self.subTest(s=s),self.assertRaises(SafeInputError):
                safe_crosscheck(slot_text=s,iso_verified=True,bios_verified=True)
    def test_mismatch_rejected_and_no_leak(self):
        with self.assertRaisesRegex(SafeInputError,'documented_service_slot_mismatch') as ctx:
            safe_crosscheck(slot_text='06000340',iso_verified=True,bios_verified=True)
        self.assertNotIn('06000340',str(ctx.exception))
    def test_wrong_iso_rejected(self):
        with self.assertRaisesRegex(SafeInputError,'source_identity_mismatch'):
            safe_crosscheck(slot_text='06000344',iso_verified=False,bios_verified=True)
    def test_wrong_bios_rejected(self):
        with self.assertRaisesRegex(SafeInputError,'source_identity_mismatch'):
            safe_crosscheck(slot_text='06000344',iso_verified=True,bios_verified=False)
    def test_boolean_forgery_rejected(self):
        with self.assertRaises(SafeInputError):
            safe_crosscheck(slot_text='06000344',iso_verified=1,bios_verified=True)
    def test_immutable_public_references(self):
        self.assertEqual(len(self.run_ok()['public_references']),2)

if __name__=='__main__': unittest.main()