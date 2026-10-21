"""Stage17 synthetic-only direct-call checks."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage17_writer_callsite_audit import audit_direct_references

class Stage17Tests(unittest.TestCase):
    def test_empty(self):
        a = audit_direct_references(bytes(64), [32], 0x06004000)
        self.assertEqual(a["direct_bsr_to_writer_count"], 0)
    def test_direct_bsr(self):
        data = bytearray(64)
        # instruction at 0, PC+4, destination 32: displacement 14
        data[0:2] = (0xB00E).to_bytes(2, "big")
        a = audit_direct_references(data, [32], 0x06004000)
        self.assertEqual(a["direct_bsr_to_writer_count"], 1)
    def test_bsr_wrong_destination(self):
        data = bytearray(64)
        data[0:2] = (0xB00D).to_bytes(2, "big")
        self.assertEqual(audit_direct_references(data, [32], 0)["direct_bsr_to_writer_count"], 0)
    def test_movl_literal_then_jsr(self):
        data = bytearray(64)
        data[0:2] = (0xD202).to_bytes(2, "big")
        data[2:4] = (0x420B).to_bytes(2, "big")
        data[12:16] = (0x06004020).to_bytes(4, "big")
        a = audit_direct_references(data, [32], 0x06004000)
        self.assertEqual(a["pc_relative_absolute_writer_literal_references"], 1)
        self.assertEqual(a["nearby_jsr_using_literal_register_candidates"], 1)
    def test_literal_without_jsr(self):
        data = bytearray(64)
        data[0:2] = (0xD202).to_bytes(2, "big")
        data[12:16] = (0x06004020).to_bytes(4, "big")
        self.assertEqual(audit_direct_references(data, [32], 0x06004000)["nearby_jsr_using_literal_register_candidates"], 0)
    def test_no_raw_offsets(self):
        result = audit_direct_references(bytes(64), [32], 0)
        self.assertNotIn("offsets", result)
        self.assertNotIn("raw_bytes", result)
    def test_multi_targets(self):
        data = bytearray(64)
        data[0:2] = (0xB00E).to_bytes(2, "big")
        self.assertEqual(audit_direct_references(data, [30,32], 0)["direct_bsr_to_writer_count"], 1)

if __name__ == "__main__":
    unittest.main()
