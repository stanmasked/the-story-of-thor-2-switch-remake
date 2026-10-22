import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage70_vdp1_status_trigger_audit import (
    CODE_LOAD_ADDRESS,
    VDP1_REGISTER_BASE,
    find_negative_writer_callback_ids,
    scan_status_writes,
    scan_vdp1_register_writes,
    summarize,
)

STATUS_ADDRESS = 0x06090020


def put16(data, position, value):
    data[position:position + 2] = value.to_bytes(2, "big")


def put32(data, position, value):
    data[position:position + 4] = value.to_bytes(4, "big")


def put_pc_literal_load(data, position, register, target, value):
    pc_base = (position + 4) & ~3
    displacement = (target - pc_base) // 4
    assert (target - pc_base) % 4 == 0
    assert 0 <= displacement <= 0xFF
    put16(data, position, 0xD000 | (register << 8) | displacement)
    put32(data, target, value)


def status_store_fixture(value=-1):
    data = bytearray(0x60)
    put16(data, 0, 0xE200 | (value & 0xFF))  # MOV #imm,R2
    put_pc_literal_load(data, 2, 3, 0x40, STATUS_ADDRESS)
    put16(data, 4, 0x2320)  # MOV.B R2,@R3
    return bytes(data)


def ptmr_store_fixture(mode):
    data = bytearray(0x60)
    put_pc_literal_load(data, 0, 3, 0x40, VDP1_REGISTER_BASE + 2)
    put16(data, 2, 0x2321)  # MOV.W R2,@R3 (FBCR)
    put16(data, 4, 0xE200 | mode)  # MOV #mode,R2
    put16(data, 6, 0x7302)  # ADD #2,R3 (FBCR -> PTMR)
    put16(data, 8, 0x2321)  # MOV.W R2,@R3 (PTMR)
    return bytes(data)


def callback_registration_fixture():
    data = bytearray(0x400)
    writer_entry = 0x100
    dispatcher_entry = 0x200
    writer_address = CODE_LOAD_ADDRESS + writer_entry
    dispatcher_address = CODE_LOAD_ADDRESS + dispatcher_entry

    # Registration caller: callback pointer in R5, dispatcher in R2,
    # and callback id 64 in the JSR delay slot.
    put_pc_literal_load(data, 0x20, 5, 0x340, writer_address)
    put_pc_literal_load(data, 0x22, 2, 0x344, dispatcher_address)
    put16(data, 0x24, 0x420B)
    put16(data, 0x26, 0xE440)

    # Callback writes -1 through the shared status pointer.
    put16(data, writer_entry, 0xE2FF)
    put_pc_literal_load(data, writer_entry + 2, 3, 0x354, STATUS_ADDRESS)
    put16(data, writer_entry + 4, 0x2320)

    # Dispatcher signature: R4 is scaled by four and R5 is stored into
    # the selected callback-table slot.
    put_pc_literal_load(data, dispatcher_entry, 0, 0x348, 0x06090000)
    put16(data, dispatcher_entry + 2, 0x7FF8)
    put_pc_literal_load(data, dispatcher_entry + 4, 2, 0x34C, 0x06091000)
    put16(data, dispatcher_entry + 6, 0x6343)
    put_pc_literal_load(data, dispatcher_entry + 8, 1, 0x350, 0x06092000)
    put16(data, dispatcher_entry + 10, 0x4308)
    put16(data, dispatcher_entry + 12, 0x2F42)
    put16(data, dispatcher_entry + 14, 0x1F31)
    put16(data, dispatcher_entry + 16, 0x0356)
    return bytes(data)


class Stage70StatusTriggerAuditTests(unittest.TestCase):
    def test_explicit_negative_status_write_is_detected(self):
        loads, writes = scan_status_writes(status_store_fixture(), STATUS_ADDRESS)
        self.assertEqual(len(loads), 1)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["constant_class"], "negative")
        self.assertEqual(writes[0]["constant_value"], -1)

    def test_negative_status_writer_is_registered_through_indexed_dispatcher(self):
        self.assertEqual(
            find_negative_writer_callback_ids(
                callback_registration_fixture(), STATUS_ADDRESS
            ),
            [64],
        )

    def test_status_store_in_branch_delay_slot_is_detected(self):
        data = bytearray(0x60)
        put_pc_literal_load(data, 0, 1, 0x40, STATUS_ADDRESS)
        put16(data, 2, 0x430B)  # JSR @R3
        put16(data, 4, 0x21D0)  # delay slot: MOV.B R13,@R1
        loads, writes = scan_status_writes(bytes(data), STATUS_ADDRESS)
        self.assertEqual(len(loads), 1)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["constant_class"], "other")

    def test_fbcr_pointer_increment_identifies_ptmr_auto_mode(self):
        writes = scan_vdp1_register_writes(ptmr_store_fixture(2))
        ptmr = [item for item in writes if item["register_offset"] == 0x04]
        self.assertEqual(len(ptmr), 1)
        self.assertEqual(ptmr[0]["value"], 2)

    def test_ptmr_manual_start_value_is_classified_separately(self):
        writes = scan_vdp1_register_writes(ptmr_store_fixture(1))
        ptmr = [item for item in writes if item["register_offset"] == 0x04]
        self.assertEqual(len(ptmr), 1)
        self.assertEqual(ptmr[0]["value"], 1)

    def test_summary_contains_aggregates_not_private_addresses_or_offsets(self):
        summary = summarize(status_store_fixture(), STATUS_ADDRESS, 1)
        self.assertFalse(summary["private_addresses_or_code_offsets_emitted"])
        self.assertNotIn("status_address", summary)
        self.assertNotIn("store_position", str(summary))
        self.assertNotIn(hex(STATUS_ADDRESS), str(summary))


if __name__ == "__main__":
    unittest.main()
