import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage71_callback_dispatch_chain import CODE_LOAD_ADDRESS
from stage93_loader_wrapper_and_set07_entry_audit import (
    _summarize_loader_wrapper,
    _summarize_set07_entry,
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


def branch8(opbase, pos, target):
    delta = (target - (pos + 4)) // 2
    assert (target - (pos + 4)) % 2 == 0
    return opbase | (delta & 0xFF)


def bsr(pos, target):
    delta = (target - (pos + 4)) // 2
    assert (target - (pos + 4)) % 2 == 0
    return 0xB000 | (delta & 0xFFF)


def loader_wrapper_fixture():
    data = bytearray(0x200)
    entry = 0x20
    helper_a = CODE_LOAD_ADDRESS + 0x110
    helper_b = CODE_LOAD_ADDRESS + 0x120
    error_target = 0x80
    put16(data, entry, 0x2FE6)
    put16(data, entry + 2, 0x4F22)
    put_literal_load(data, entry + 4, 3, 0x140, helper_a)
    put16(data, entry + 6, 0x7FFC)
    put16(data, entry + 8, 0x2F52)
    put16(data, entry + 10, 0x430B)
    put16(data, entry + 12, 0x0009)
    put16(data, entry + 14, 0x6E03)
    put16(data, entry + 16, 0x4E11)
    put16(data, entry + 18, branch8(0x8900, entry + 18, entry + 0x18))
    put16(data, entry + 20, bsr(entry + 20, error_target))
    put16(data, entry + 22, 0xE401)
    put16(data, entry + 24, 0x66F2)
    put16(data, entry + 26, 0xE500)
    put_literal_load(data, entry + 28, 3, 0x144, helper_b)
    put16(data, entry + 30, 0xE7FF)
    put16(data, entry + 32, 0x430B)
    put16(data, entry + 34, 0x64E3)
    put16(data, entry + 36, 0x6E03)
    put16(data, entry + 38, 0x4E11)
    put16(data, entry + 40, branch8(0x8900, entry + 40, entry + 0x2E))
    put16(data, entry + 42, bsr(entry + 42, error_target))
    put16(data, entry + 44, 0xE402)
    put16(data, entry + 46, 0x60E3)
    put16(data, entry + 48, 0x7F04)
    put16(data, entry + 50, 0x4F26)
    put16(data, entry + 52, 0x000B)
    put16(data, entry + 54, 0x6EF6)
    return data, entry


def set07_fixture():
    buffer_base = 0x060D8000
    data = bytearray(0x18000)
    put_literal_load(data, 0x00, 0, 0x48, buffer_base + 0x10660)
    put16(data, 0x02, 0x6F03)
    put_literal_load(data, 0x3A, 3, 0x4C, buffer_base + 0x84)
    put16(data, 0x3C, 0x430B)
    put16(data, 0x3E, 0x0009)
    put16(data, 0x84, 0x2FE6)
    put16(data, 0x9A, 0x4F22)
    put16(data, 0x0C, 0xE200)
    put16(data, 0x0E, 0x2420)
    put16(data, 0x10, 0x7401)
    put16(data, 0x16, 0x3432)
    put16(data, 0x18, branch8(0x8B00, 0x18, 0x0C))
    put16(data, 0x24, 0x6250)
    put16(data, 0x26, 0x2420)
    put16(data, 0x28, 0x7401)
    put16(data, 0x2A, 0x7501)
    put16(data, 0x2E, 0x3432)
    put16(data, 0x30, branch8(0x8B00, 0x30, 0x24))
    put_literal_load(data, 0xF0, 12, 0x200, buffer_base + 0x650)
    put16(data, 0xF2, 0x4C0B)
    put16(data, 0xF4, 0x0009)
    put_literal_load(data, 0x144, 3, 0x204, buffer_base + 0x500)
    put16(data, 0x14A, 0x430B)
    put16(data, 0x14C, 0xE401)
    put16(data, 0x14E, 0xEA40)
    put16(data, 0x152, 0x4C0B)
    put16(data, 0x154, 0x0009)
    put16(data, 0x156, 0x600D)
    put16(data, 0x158, 0x20A8)
    put16(data, 0x15A, branch8(0x8900, 0x15A, 0x152))
    return data, buffer_base


class Stage93LoaderWrapperAndEntryTests(unittest.TestCase):
    def test_wrapper_checks_both_results_and_rejoins_after_error_calls(self):
        data, entry = loader_wrapper_fixture()
        result = _summarize_loader_wrapper(bytes(data), entry)
        self.assertTrue(result["wrapper_signature_found"])
        self.assertTrue(result["first_internal_helper_call_found"])
        self.assertTrue(result["second_internal_helper_call_found"])
        self.assertTrue(result["first_negative_path_uses_error_code_1"])
        self.assertTrue(result["first_error_path_rejoins_second_helper"])
        self.assertTrue(result["second_negative_path_uses_error_code_2"])
        self.assertTrue(result["second_error_path_rejoins_return"])
        self.assertTrue(result["wrapper_returns_second_helper_result"])
        self.assertFalse(result["wrapper_short_circuits_after_first_negative_result"])

    def test_wrapper_rejects_wrong_first_error_code(self):
        data, entry = loader_wrapper_fixture()
        put16(data, entry + 22, 0xE402)
        result = _summarize_loader_wrapper(bytes(data), entry)
        self.assertFalse(result["first_result_checked_for_nonnegative_value"])
        self.assertFalse(result["first_negative_path_uses_error_code_1"])

    def test_wrapper_rejects_helper_target_outside_main_image(self):
        data, entry = loader_wrapper_fixture()
        put_literal_load(data, entry + 4, 3, 0x140, 0x07000000)
        result = _summarize_loader_wrapper(bytes(data), entry)
        self.assertFalse(result["first_internal_helper_call_found"])
        self.assertFalse(result["both_helpers_have_internal_targets"])

    def test_set07_entry_stack_and_startup_target_are_inside_module(self):
        data, base = set07_fixture()
        result = _summarize_set07_entry(bytes(data), base)
        self.assertTrue(result["entry_stub_found"])
        self.assertTrue(result["entry_stack_pointer_literal_inside_module"])
        self.assertTrue(result["entry_calls_internal_startup_routine"])
        self.assertTrue(result["startup_routine_prologue_found"])

    def test_set07_startup_mask_loop_is_not_misclassified_as_callback_registration(self):
        data, base = set07_fixture()
        result = _summarize_set07_entry(bytes(data), base)
        self.assertTrue(result["startup_has_two_bounded_byte_loops"])
        self.assertTrue(result["startup_calls_internal_helper_before_mask_poll"])
        self.assertTrue(result["startup_polls_until_return_value_has_mask_0x40"])
        self.assertTrue(result["mask_poll_target_is_inside_module"])
        self.assertFalse(result["callback_registration_proven_by_mask_poll_signature"])

    def test_wrong_mask_poll_branch_target_is_rejected(self):
        data, base = set07_fixture()
        put16(data, 0x15A, branch8(0x8900, 0x15A, 0x154))
        result = _summarize_set07_entry(bytes(data), base)
        self.assertFalse(result["startup_polls_until_return_value_has_mask_0x40"])

    def test_stack_literal_outside_module_is_rejected(self):
        data, base = set07_fixture()
        put_literal_load(data, 0x00, 0, 0x48, 0x06001000)
        put16(data, 0x02, 0x6F03)
        result = _summarize_set07_entry(bytes(data), base)
        self.assertFalse(result["entry_stack_pointer_literal_inside_module"])
        self.assertFalse(result["entry_stub_found"])


if __name__ == "__main__":
    unittest.main()
