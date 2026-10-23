import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage85_disc_slot_writer_census import MAX_FILE_SIZE, SECTOR
from stage86_set_module_signature_audit import (
    SERVICE_SLOT_A,
    SERVICE_SLOT_B,
    read_root_payloads,
    summarize_set_payload,
)

WRITER = 0x060085A8
CALLBACK = 0x0600444E


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | delta // 4)
    put32(data, literal_pos, value)


def record(name, extent, size, flags=0):
    name = name if isinstance(name, bytes) else name.encode()
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    out = bytearray(length)
    out[0] = length
    out[2:6] = extent.to_bytes(4, "little")
    out[6:10] = extent.to_bytes(4, "big")
    out[10:14] = size.to_bytes(4, "little")
    out[14:18] = size.to_bytes(4, "big")
    out[25] = flags
    out[28:30] = (1).to_bytes(2, "little")
    out[30:32] = (1).to_bytes(2, "big")
    out[32] = len(name)
    out[33:33 + len(name)] = name
    return bytes(out)


def synthetic_iso(file_name=b"SET07.BIN;1", file_size=8, magic=b"TEST"):
    extent = 21
    total_size = max(24 * SECTOR, extent * SECTOR + file_size)
    image = bytearray(total_size)
    pvd = 16 * SECTOR
    image[pvd:pvd + 7] = b"\x01CD001\x01"
    root_rec = record(b"\x00", 20, SECTOR, 2)
    image[pvd + 156:pvd + 156 + len(root_rec)] = root_rec
    directory = bytearray(SECTOR)
    records = (
        record(b"\x00", 20, SECTOR, 2),
        record(b"\x01", 20, SECTOR, 2),
        record(file_name, extent, file_size),
    )
    offset = 0
    for item in records:
        directory[offset:offset + len(item)] = item
        offset += len(item)
    image[20 * SECTOR:21 * SECTOR] = directory
    if file_size:
        image[extent * SECTOR:extent * SECTOR + min(file_size, len(magic))] = magic[:file_size]
    return bytes(image)


class Stage86SetModuleSignatureTests(unittest.TestCase):
    def test_slot_dispatch_candidates_are_recognized(self):
        data = bytearray(0x240)
        literal_load(data, 0x10, 2, 0x180, SERVICE_SLOT_A)
        put16(data, 0x12, 0x6222)  # MOV.L @R2,R2
        put16(data, 0x14, 0x420B)  # JSR @R2
        result = summarize_set_payload("SET07.BIN", data)
        self.assertEqual(result["slot_a_pc_literal_refs"], 1)
        self.assertEqual(result["slot_a_indirect_dispatch_candidates"], 1)

    def test_slot_b_dispatch_candidate_is_separate(self):
        data = bytearray(0x240)
        literal_load(data, 0x10, 3, 0x180, SERVICE_SLOT_B)
        put16(data, 0x12, 0x6332)  # MOV.L @R3,R3
        put16(data, 0x14, 0x430B)  # JSR @R3
        result = summarize_set_payload("SET07.BIN", data)
        self.assertEqual(result["slot_b_pc_literal_refs"], 1)
        self.assertEqual(result["slot_b_indirect_dispatch_candidates"], 1)

    def test_no_slot_store_is_inferred_from_a_reader(self):
        data = bytearray(0x240)
        literal_load(data, 0x10, 2, 0x180, SERVICE_SLOT_A)
        put16(data, 0x12, 0x6222)
        put16(data, 0x14, 0x420B)
        result = summarize_set_payload("SET07.BIN", data)
        self.assertEqual(result["slot_a_bounded_store_candidates"], 0)
        self.assertFalse(result["runtime_execution_proven"])

    def test_writer_and_callback_literal_jsr_targets_are_counted(self):
        data = bytearray(0x240)
        literal_load(data, 0x20, 1, 0x180, WRITER)
        put16(data, 0x22, 0x410B)
        literal_load(data, 0x26, 2, 0x184, CALLBACK)
        put16(data, 0x28, 0x420B)
        result = summarize_set_payload("SET07.BIN", data, WRITER, CALLBACK)
        self.assertEqual(result["writer_target_literal_jsr_sites"], 1)
        self.assertEqual(result["callback_target_literal_jsr_sites"], 1)

    def test_code_like_metrics_are_aggregate_only(self):
        data = bytearray(0x240)
        put16(data, 0x10, 0x000B)
        put16(data, 0x12, 0x420B)
        result = summarize_set_payload("SET00.BIN", data)
        self.assertEqual(result["rts_like_halfwords"], 1)
        self.assertEqual(result["jsr_like_halfwords"], 1)
        rendered = json.dumps(result)
        self.assertNotIn("0x10", rendered)
        self.assertNotIn(hex(SERVICE_SLOT_A), rendered)

    def test_small_iso_file_payload_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "small.iso"
            path.write_bytes(synthetic_iso(file_size=8, magic=b"HELLO"))
            result = read_root_payloads(path)
        self.assertEqual(result["payloads"]["SET07.BIN"], b"HELLO" + b"\x00" * 3)
        self.assertEqual(result["large_files_prefix_scanned"], 0)

    def test_large_file_prefix_is_read_without_full_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large.iso"
            path.write_bytes(
                synthetic_iso(file_name=b"CPK0.BIN;1", file_size=MAX_FILE_SIZE + 1, magic=b"FILM")
            )
            result = read_root_payloads(path)
        self.assertNotIn("CPK0.BIN", result["payloads"])
        self.assertEqual(result["large_prefixes"]["CPK0.BIN"][:4], b"FILM")
        self.assertEqual(result["large_files_skipped_from_code_scan"], 1)

    def test_invalid_iso_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.iso"
            path.write_bytes(b"invalid" + bytes(40 * SECTOR))
            with self.assertRaises(ValueError):
                read_root_payloads(path)

    def test_empty_payload_has_no_dispatch(self):
        result = summarize_set_payload("SET00.BIN", b"")
        self.assertEqual(result["slot_a_indirect_dispatch_candidates"], 0)
        self.assertEqual(result["slot_b_indirect_dispatch_candidates"], 0)

    def test_no_code_execution_claim_is_made(self):
        result = summarize_set_payload("SET07.BIN", bytes(0x100))
        self.assertFalse(result["runtime_execution_proven"])


if __name__ == "__main__":
    unittest.main()
