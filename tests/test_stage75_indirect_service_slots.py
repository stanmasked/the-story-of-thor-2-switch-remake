import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage75_indirect_service_slots import SERVICE_SLOTS, scan_slot_writes, summarize


def fixture(with_store=True):
    data = bytearray(128)
    data[0:2] = (0xD108).to_bytes(2, "big")  # MOV.L @(8,PC),R1; literal at 36
    data[36:40] = SERVICE_SLOTS[0].to_bytes(4, "big")
    data[2:4] = (0x2212 if with_store else 0x0009).to_bytes(2, "big")
    return bytes(data)


class Stage75SlotTests(unittest.TestCase):
    def test_direct_store_candidate(self):
        result = scan_slot_writes(fixture(), SERVICE_SLOTS[0])
        self.assertEqual(result["pointer_literal_loads"], 1)
        self.assertEqual(result["bounded_direct_longword_store_candidates"], 1)
        self.assertFalse(result["all_writers_proven"])

    def test_no_store_does_not_claim_writer(self):
        result = scan_slot_writes(fixture(False), SERVICE_SLOTS[0])
        self.assertEqual(result["bounded_direct_longword_store_candidates"], 0)

    def test_nonmatching_slot(self):
        result = scan_slot_writes(fixture(), SERVICE_SLOTS[1])
        self.assertEqual(result["pointer_literal_loads"], 0)

    def test_control_transfer_breaks_scan(self):
        data = bytearray(fixture())
        data[2:4] = (0xA000).to_bytes(2, "big")
        data[4:6] = (0x2212).to_bytes(2, "big")
        self.assertEqual(scan_slot_writes(bytes(data), SERVICE_SLOTS[0])["bounded_direct_longword_store_candidates"], 0)

    def test_output_contains_no_private_addresses(self):
        rendered = str(summarize(fixture()))
        for slot in SERVICE_SLOTS:
            self.assertNotIn(hex(slot), rendered)
        self.assertFalse(summarize(fixture())["private_addresses_or_offsets_emitted"])


if __name__ == "__main__":
    unittest.main()
