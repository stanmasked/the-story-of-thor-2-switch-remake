import unittest

from stage69_vdp1_field_writer_census import (
    count_derivation_window,
    field_write_candidates,
    metadata_pointer_sentinel_guard_candidates,
    summarize,
)


def put16(data: bytearray, offset: int, value: int) -> None:
    data[offset:offset + 2] = value.to_bytes(2, "big")


def put_pc_word_r0(data: bytearray, pos: int, literal_pos: int, value: int) -> None:
    displacement = (literal_pos - (pos + 4)) // 2
    assert literal_pos % 2 == 0 and (literal_pos - (pos + 4)) % 2 == 0
    assert 0 <= displacement <= 0xFF
    put16(data, pos, 0x9000 | displacement)  # MOV.W @(disp,PC),R0
    put16(data, literal_pos, value)


def field_writer_fixture() -> bytes:
    data = bytearray(128)
    put16(data, 0, 0xE211)  # MOV #17,R2
    put16(data, 2, 0xE07A)  # MOV #0x7A,R0
    put16(data, 4, 0x0D25)  # MOV.W R2,@(R0,R13)
    put16(data, 8, 0xE307)  # MOV #7,R3
    put_pc_word_r0(data, 10, 0x70, 0x0098)
    put16(data, 12, 0x0E36)  # MOV.L R3,@(R0,R14)
    put16(data, 16, 0xE405)  # MOV #5,R4
    put_pc_word_r0(data, 18, 0x72, 0x00AC)
    put16(data, 20, 0x0E46)  # MOV.L R4,@(R0,R14)
    return bytes(data)


def metadata_sentinel_fixture(sentinel: int = 0xFFFF) -> bytes:
    data = bytearray(128)
    put16(data, 0, 0xD00F)  # MOV.L literal 0x20000002,R0
    put16(data, 2, 0x4600)  # SHLL R6
    put16(data, 4, 0xD20F)  # MOV.L literal 0x0000FFFF,R2
    for pos, word in ((6, 0x6563), (8, 0x354C), (10, 0x055D),
                      (12, 0x635D), (14, 0x3320), (16, 0x8B0A)):
        put16(data, pos, word)
    put16(data, 0x28, 0x901A)  # target: MOV.W literal 0x00AC,R0
    put16(data, 0x40, 0x2000)
    put16(data, 0x42, 0x0002)
    put16(data, 0x44, 0x0000)
    put16(data, 0x46, sentinel)
    put16(data, 0x60, 0x00AC)
    return bytes(data)


def count_window_fixture(with_zero_test: bool = False) -> bytes:
    words = [
        0x6243,  # MOV R4,R2
        0x6382,  # MOV.L @R8,R3
        0x4221,  # SHAR R2
        0x85F8,  # unrelated stack load
        0x7304,  # ADD #4,R3
        0x2301,  # unrelated word store
        0x4221,  # SHAR R2
        0x6382,  # MOV.L @R8,R3
        0x4221,  # SHAR R2
    ]
    if with_zero_test:
        words.append(0x2228)  # TST R2,R2
    words.extend([0x7306, 0x2321])  # ADD #6,R3; MOV.W R2,@R3
    data = bytearray(len(words) * 2)
    for i, word in enumerate(words):
        put16(data, i * 2, word)
    return bytes(data)


class Stage69FieldWriterCensusTests(unittest.TestCase):
    def test_recognizes_three_fields_and_expected_widths(self):
        candidates = field_write_candidates(field_writer_fixture())
        self.assertEqual(
            [(c["field"], c["base_register"], c["source_register"]) for c in candidates],
            [("destination_slot", 13, 2),
             ("source_base", 14, 3),
             ("metadata_pointer", 14, 4)],
        )

    def test_summary_is_aggregate_only(self):
        report = summarize(field_writer_fixture())
        self.assertEqual(report["candidate_write_total"], 3)
        self.assertEqual(report["candidate_write_counts"]["destination_slot"], 1)
        self.assertEqual(report["candidate_write_counts"]["source_base"], 1)
        self.assertEqual(report["candidate_write_counts"]["metadata_pointer"], 1)
        rendered = str(report)
        for forbidden in ("position", "raw_bytes", "program_offsets"):
            self.assertNotIn(forbidden, rendered)

    def test_rejects_r0_clobber_before_store(self):
        data = bytearray(12)
        put16(data, 0, 0xE07A)  # intended field offset
        put16(data, 2, 0xE001)  # overwrite R0
        put16(data, 4, 0x0D25)
        self.assertEqual(field_write_candidates(bytes(data)), [])

    def test_rejects_control_flow_before_store(self):
        data = bytearray(12)
        put16(data, 0, 0xE07A)
        put16(data, 2, 0x8900)  # BT: conservatively stop the back-scan
        put16(data, 4, 0x0D25)
        self.assertEqual(field_write_candidates(bytes(data)), [])

    def test_rejects_wrong_store_width_for_pointer_field(self):
        data = bytearray(64)
        put16(data, 0, 0xE307)
        put_pc_word_r0(data, 2, 0x30, 0x0098)
        put16(data, 4, 0x0E35)  # MOV.W, but source_base expects MOV.L
        self.assertEqual(field_write_candidates(bytes(data)), [])

    def test_recognizes_ffff_sentinel_before_metadata_pointer_path(self):
        self.assertEqual(metadata_pointer_sentinel_guard_candidates(
            metadata_sentinel_fixture()), 1)

    def test_rejects_non_ffff_table_sentinel(self):
        self.assertEqual(metadata_pointer_sentinel_guard_candidates(
            metadata_sentinel_fixture(0xFFFE)), 0)

    def test_recognizes_count_shift_path_without_zero_guard(self):
        result = count_derivation_window(count_window_fixture(), 0)
        self.assertEqual(result, {
            "recognized": True,
            "explicit_zero_test_candidate": False,
        })

    def test_detects_explicit_zero_test_candidate(self):
        result = count_derivation_window(count_window_fixture(True), 0)
        self.assertEqual(result, {
            "recognized": True,
            "explicit_zero_test_candidate": True,
        })

    def test_empty_data(self):
        report = summarize(bytes(128))
        self.assertEqual(report["candidate_write_total"], 0)
        self.assertEqual(report["recognized_producer_count_windows"], 0)
        self.assertFalse(report["runtime_zero_count_invariant_proven"])


if __name__ == "__main__":
    unittest.main()
