import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage94_error_helper_return_audit import _summarize_error_helper


def put16(data, pos, value):
    data[pos:pos + 2] = value.to_bytes(2, "big")


def put32(data, pos, value):
    data[pos:pos + 4] = value.to_bytes(4, "big")


def put_literal_load(data, pos, register, literal_pos, value):
    pc_base = (pos + 4) & ~3
    delta = literal_pos - pc_base
    assert delta >= 0 and delta % 4 == 0 and delta // 4 <= 255
    put16(data, pos, 0xD000 | register << 8 | (delta // 4))
    put32(data, literal_pos, value)


def error_helper_fixture():
    data = bytearray(0x300)
    entry = 0x100
    pool_start = entry + 0x2C
    pool_values = [
        0x0609BA9C, 0x06078B42, 0x06088B03, 0x06078498, 0x06078AB0,
        0x06078A72, 0x06088AF5, 0x002E20F8, 0x0600026C, 0x002E227C,
    ]
    for i, value in enumerate(pool_values):
        put32(data, pool_start + i * 4, value)
    put_literal_load(data, entry, 2, 0x200, 0x06088AF5)
    put16(data, entry + 2, 0x6020)
    put16(data, entry + 4, 0x2008)
    put16(data, entry + 6, 0x8902)
    put_literal_load(data, entry + 8, 0, 0x204, 0x002E20F8)
    put16(data, entry + 10, 0x402B)
    put16(data, entry + 12, 0x0009)
    put_literal_load(data, entry + 0x0E, 1, 0x208, 0x0600026C)
    put16(data, entry + 0x10, 0x6312)
    put16(data, entry + 0x12, 0x432B)
    put16(data, entry + 0x14, 0x0009)
    put_literal_load(data, entry + 0x16, 2, 0x20C, 0x06088AF5)
    put16(data, entry + 0x18, 0x6020)
    put16(data, entry + 0x1A, 0x2008)
    put16(data, entry + 0x1C, 0x8902)
    put_literal_load(data, entry + 0x1E, 0, 0x210, 0x002E227C)
    put16(data, entry + 0x20, 0x402B)
    put16(data, entry + 0x22, 0x0009)
    put_literal_load(data, entry + 0x24, 1, 0x214, 0x0600026C)
    put16(data, entry + 0x26, 0x6312)
    put16(data, entry + 0x28, 0x432B)
    put16(data, entry + 0x2A, 0x0009)
    return data, entry


class Stage94ErrorHelperReturnTests(unittest.TestCase):
    def test_error_helper_has_two_gates_and_shared_final_dispatch(self):
        data, entry = error_helper_fixture()
        result = _summarize_error_helper(bytes(data), entry)
        self.assertTrue(result["error_helper_signature_found"])
        self.assertTrue(result["both_conditionals_test_same_global_byte"])
        self.assertTrue(result["two_optional_indirect_calls_to_distinct_targets_found"])
        self.assertTrue(result["both_paths_call_same_indirect_dispatch_slot"])
        self.assertTrue(result["pointer_pool_immediately_follows_final_indirect_call"])
        self.assertTrue(result["pointer_pool_candidate_found"])
        self.assertFalse(result["local_rts_or_rte_before_pointer_pool_found"])
        self.assertTrue(result["bounded_cfg_reaches_final_indirect_call"])
        self.assertTrue(result["helper_appears_nonreturning_by_layout"])

    def test_second_gate_must_use_same_state_byte(self):
        data, entry = error_helper_fixture()
        put_literal_load(data, entry + 0x16, 2, 0x20C, 0x06088AF7)
        result = _summarize_error_helper(bytes(data), entry)
        self.assertFalse(result["error_helper_signature_found"])
        self.assertFalse(result["both_conditionals_test_same_global_byte"])

    def test_visible_rts_before_pool_disproves_nonreturning_layout(self):
        data, entry = error_helper_fixture()
        put16(data, entry + 0x20, 0x000B)
        result = _summarize_error_helper(bytes(data), entry)
        self.assertTrue(result["local_rts_or_rte_before_pointer_pool_found"])
        self.assertFalse(result["bounded_cfg_has_no_local_return"])
        self.assertFalse(result["helper_appears_nonreturning_by_layout"])

    def test_pointer_pool_must_look_like_address_literals(self):
        data, entry = error_helper_fixture()
        for pos in range(entry + 0x2C, entry + 0x54, 4):
            put32(data, pos, 0x11111111)
        result = _summarize_error_helper(bytes(data), entry)
        self.assertFalse(result["pointer_pool_candidate_found"])
        self.assertFalse(result["helper_appears_nonreturning_by_layout"])

    def test_final_indirect_call_and_delay_slot_are_required(self):
        data, entry = error_helper_fixture()
        put16(data, entry + 0x28, 0x432A)  # JMP @R3, not JSR @R3
        result = _summarize_error_helper(bytes(data), entry)
        self.assertFalse(result["error_helper_signature_found"])
        self.assertFalse(result["pointer_pool_immediately_follows_final_indirect_call"])

    def test_summary_does_not_emit_raw_addresses(self):
        data, entry = error_helper_fixture()
        result = _summarize_error_helper(bytes(data), entry)
        rendered = repr(result)
        self.assertNotIn("0x", rendered)
        self.assertNotIn("address", rendered.lower())


if __name__ == "__main__":
    unittest.main()
