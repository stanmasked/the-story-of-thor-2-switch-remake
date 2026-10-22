import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage77_callee_register_preservation import (
    _reachable_function,
    _resolve_indirect_call_target,
    _r13_preserved_by_saver,
)


def put16(data, position, value):
    data[position:position + 2] = value.to_bytes(2, "big")


def put32(data, position, value):
    data[position:position + 4] = value.to_bytes(4, "big")


def put_pc_literal_load(data, position, register, literal_position, value):
    pc_base = (position + 4) & ~3
    delta = literal_position - pc_base
    assert delta % 4 == 0
    displacement = delta // 4
    assert 0 <= displacement <= 0xFF
    put16(data, position, 0xD000 | (register << 8) | displacement)
    put32(data, literal_position, value)


class Stage77CalleePreservationTests(unittest.TestCase):
    def test_leaf_callee_returns_without_touching_r10_or_r13(self):
        data = bytearray(0x100)
        put16(data, 0x20, 0xE101)  # MOV #1,R1
        put16(data, 0x22, 0x000B)  # RTS
        put16(data, 0x24, 0x0009)  # delay slot
        graph = _reachable_function(data, 0x20)
        self.assertEqual(graph["returns"], {0x22})
        self.assertFalse(graph["direct_calls"])
        self.assertFalse(graph["indirect_calls"])
        self.assertFalse(graph["node_limit_reached"])

    def test_indirect_call_target_resolves_from_unchanged_register_literal(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 2, 0x80, CODE_LOAD_ADDRESS + 0xC0)
        put16(data, 0x22, 0x0009)
        put16(data, 0x24, 0x420B)  # JSR @R2
        self.assertEqual(_resolve_indirect_call_target(data, 0x24), 0xC0)

    def test_indirect_call_target_is_rejected_after_register_clobber(self):
        data = bytearray(0x100)
        put_pc_literal_load(data, 0x20, 2, 0x80, CODE_LOAD_ADDRESS + 0xC0)
        put16(data, 0x22, 0xE201)  # MOV #1,R2 clobbers target register
        put16(data, 0x24, 0x420B)
        self.assertIsNone(_resolve_indirect_call_target(data, 0x24))

    def test_r13_saver_requires_push_write_restore_before_tail_exit(self):
        data = bytearray(0x100)
        entry = 0x20
        for offset, opcode in (
            (0x00, 0x2FE6), (0x02, 0x6E63), (0x04, 0x2FD6),
            (0x06, 0xE60A), (0x08, 0x2FC6), (0x0A, 0x6D53),
            (0x20, 0x6DF6), (0x22, 0xAFE5), (0x24, 0x6EF6),
        ):
            put16(data, entry + offset, opcode)
        graph = {
            "nodes": {entry, entry + 0x04, entry + 0x0A, entry + 0x20, entry + 0x22},
            "tail_branches": {(entry + 0x22, 0x10)},
            "direct_calls": {0x10},
        }
        self.assertTrue(_r13_preserved_by_saver(data, entry, graph))
        put16(data, entry + 0x20, 0x0009)
        self.assertFalse(_r13_preserved_by_saver(data, entry, graph))

    def test_unresolved_tail_target_does_not_count_as_a_preservation_proof(self):
        data = bytearray(0x100)
        entry = 0x20
        for offset, opcode in (
            (0x00, 0x2FE6), (0x02, 0x6E63), (0x04, 0x2FD6),
            (0x06, 0xE60A), (0x08, 0x2FC6), (0x0A, 0x6D53),
            (0x20, 0x6DF6), (0x22, 0xA000), (0x24, 0x6EF6),
        ):
            put16(data, entry + offset, opcode)
        graph = {
            "nodes": {entry, entry + 0x04, entry + 0x0A, entry + 0x20, entry + 0x22},
            "tail_branches": {(entry + 0x22, 0x10)},
            "direct_calls": set(),
        }
        self.assertFalse(_r13_preserved_by_saver(data, entry, graph))


if __name__ == "__main__":
    unittest.main()
