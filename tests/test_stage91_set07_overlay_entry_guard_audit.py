import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage91_set07_overlay_entry_guard_audit import (
    _branch,
    _entry_stub_summary,
    _find_main_th2_low_load,
    _find_set07_callsite,
    _find_set_table_loader_targets,
    _gate_summary,
    _generic_prologues,
    _walk_cfg,
)


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


def set_table():
    return b"".join(f"SET{i:02d}.BIN".encode("ascii") + b"\x00" for i in range(7))


class Stage91Set07OverlayEntryTests(unittest.TestCase):
    def test_bf_branch_destination_is_decoded(self):
        self.assertEqual(_branch(0x20, 0x8B03), ("BF", 0x2A, False))

    def test_cfg_follows_conditional_target_and_fallthrough(self):
        data = bytearray(0x20)
        put16(data, 0x00, 0x8B02)
        put16(data, 0x02, 0x0009)
        put16(data, 0x04, 0x0009)
        put16(data, 0x06, 0x0009)
        put16(data, 0x08, 0x000B)
        reachable = _walk_cfg(bytes(data), 0, len(data))
        self.assertTrue({0x00, 0x02, 0x04, 0x08}.issubset(reachable))
        self.assertNotIn(0x0A, reachable)

    def test_generic_function_prologue_is_detected(self):
        data = bytearray(0x80)
        for pos, op in [(0x10, 0x2FE6), (0x16, 0x2FD6), (0x18, 0x2FC6), (0x1A, 0x4F22)]:
            put16(data, pos, op)
        self.assertIn(0x10, _generic_prologues(bytes(data)))

    def test_three_comparison_guards_and_tst_mask_are_found(self):
        data = bytearray(0x100)
        name_pos = 0x50
        continuation = name_pos + 14
        start = 0x20
        put16(data, 0x10, 0xC860)
        put16(data, 0x12, 0x8D00 | ((continuation - (0x12 + 4)) // 2))
        for delta, op in [(0, 0x6031), (2, 0x8860), (6, 0x6053), (8, 0x8806), (12, 0x604F), (14, 0x880F)]:
            put16(data, start + delta, op)
        for branch_pos in (start + 4, start + 10, start + 16):
            put16(data, branch_pos, 0x8B00 | ((continuation - (branch_pos + 4)) // 2))
        result = _gate_summary(bytes(data), name_pos, continuation)
        self.assertEqual(result["conditional_skip_branches_to_post_entry_path"], 4)
        self.assertTrue(result["three_value_guard_signature_found"])
        self.assertTrue(result["tst_mask_skip_guard_found"])

    def test_main_th2_low_call_yields_one_candidate_load_base(self):
        data = bytearray(0x400)
        name_pos = 0x200
        data[name_pos:name_pos + 8] = b"TH2.LOW\x00"
        put_literal_load(data, 0x2E, 5, 0xF8, 0x002DA000)
        put_literal_load(data, 0x30, 4, 0x100, CODE_LOAD_ADDRESS + name_pos)
        put_literal_load(data, 0x32, 3, 0x104, CODE_LOAD_ADDRESS + 0x300)
        put16(data, 0x34, 0x430B)
        put16(data, 0x36, 0x0009)
        summary, targets, bases = _find_main_th2_low_load(bytes(data))
        self.assertEqual(summary["literal_backed_load_call_candidates"], 1)
        self.assertEqual(targets, [CODE_LOAD_ADDRESS + 0x300])
        self.assertEqual(bases, [0x002DA000])

    def test_set_table_consumer_uses_index_times_ten(self):
        data = bytearray(0x500)
        table_pos = 0x280
        data[table_pos:table_pos + len(set_table())] = set_table()
        put_literal_load(data, 0x10, 1, 0x100, CODE_LOAD_ADDRESS + table_pos)
        for delta, op in {2: 0x6343, 4: 0x4408, 6: 0x343C, 10: 0x4400, 12: 0x644E, 14: 0x430B, 16: 0x341C}.items():
            put16(data, 0x10 + delta, op)
        put_literal_load(data, 0x18, 3, 0x104, CODE_LOAD_ADDRESS + 0x400)
        summary, targets = _find_set_table_loader_targets(bytes(data))
        self.assertTrue(summary["contiguous_set_table_found"])
        self.assertEqual(summary["set_table_loader_candidates"], 1)
        self.assertEqual(targets, [CODE_LOAD_ADDRESS + 0x400])

    def test_set07_load_then_entry_call_uses_same_buffer(self):
        data = bytearray(0x400)
        string_pos = 0x200
        data[string_pos:string_pos + 10] = b"SET07.BIN\x00"
        load_base = 0x002DA000
        loader_target = CODE_LOAD_ADDRESS + 0xA0F8
        put_literal_load(data, 0x2E, 5, 0xF8, 0x060D8000)
        put_literal_load(data, 0x30, 4, 0x100, load_base + string_pos)
        put_literal_load(data, 0x32, 2, 0x104, loader_target)
        put16(data, 0x34, 0x420B)
        put16(data, 0x36, 0x0009)
        put_literal_load(data, 0x38, 3, 0x108, 0x060D8000)
        put16(data, 0x3A, 0x430B)
        put16(data, 0x3C, 0x0009)
        self.assertEqual(_find_set07_callsite(bytes(data), load_base, {loader_target}), (0x30, 0x060D8000))

    def test_set07_entry_stub_sets_stack_inside_buffer(self):
        data = bytearray(0x100)
        base = 0x060D8000
        put_literal_load(data, 0x00, 0, 0x48, base + 0x80)
        put16(data, 0x02, 0x6F03)
        ok, count = _entry_stub_summary(bytes(data), base)
        self.assertTrue(ok)
        self.assertGreaterEqual(count, 1)

    def test_entry_stub_outside_buffer_is_rejected(self):
        data = bytearray(0x100)
        put_literal_load(data, 0x00, 0, 0x48, 0x06001000)
        put16(data, 0x02, 0x6F03)
        ok, count = _entry_stub_summary(bytes(data), 0x060D8000)
        self.assertFalse(ok)
        self.assertEqual(count, 0)

    def test_wrong_loader_target_does_not_match_set07_callsite(self):
        data = bytearray(0x400)
        string_pos = 0x200
        data[string_pos:string_pos + 10] = b"SET07.BIN\x00"
        load_base = 0x002DA000
        put_literal_load(data, 0x2E, 5, 0xF8, 0x060D8000)
        put_literal_load(data, 0x30, 4, 0x100, load_base + string_pos)
        put_literal_load(data, 0x32, 2, 0x104, CODE_LOAD_ADDRESS + 0x300)
        put16(data, 0x34, 0x420B)
        put16(data, 0x36, 0x0009)
        put_literal_load(data, 0x38, 3, 0x108, 0x060D8000)
        put16(data, 0x3A, 0x430B)
        put16(data, 0x3C, 0x0009)
        self.assertIsNone(_find_set07_callsite(bytes(data), load_base, {CODE_LOAD_ADDRESS + 0xA0F8}))


if __name__ == "__main__":
    unittest.main()
