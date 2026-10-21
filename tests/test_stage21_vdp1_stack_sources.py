"""Stage21 synthetic SH-2 SP-relative byte-load tests."""
import unittest
from test_stage20_vdp1_product_flow import fixture, put16
from stage21_vdp1_stack_sources import matching_stack_source_chains, summarize_stack_sources, STACK_FACTOR_PREFIX


def stack_fixture(change_index=None, missing_writer=False):
    data = bytearray(fixture(bad_writer_guard=missing_writer))
    prefix = list(STACK_FACTOR_PREFIX)
    if change_index is not None:
        prefix[change_index] ^= 1
    for idx, word in enumerate(prefix):
        put16(data, 0x06 + 2 * idx, word)
    return bytes(data)


class Stage21StackSourcesTests(unittest.TestCase):
    def test_full_stack_sources(self):
        self.assertEqual(len(matching_stack_source_chains(stack_fixture())), 1)

    def test_static_stack_byte_offsets(self):
        result = summarize_stack_sources(stack_fixture())
        self.assertEqual(result['byte_factor_stack_offsets'], [20, 32])
        self.assertEqual(result['writer_enable_flag_stack_offset'], 80)

    def test_count_formula(self):
        result = summarize_stack_sources(stack_fixture())
        self.assertEqual(result['per_source_count_formula'], '(u8(stack[SP+20]) * u8(stack[SP+32])) >> 3')

    def test_missing_first_address(self):
        self.assertEqual(matching_stack_source_chains(stack_fixture(change_index=0)), [])

    def test_missing_first_load(self):
        self.assertEqual(matching_stack_source_chains(stack_fixture(change_index=1)), [])

    def test_missing_second_address(self):
        self.assertEqual(matching_stack_source_chains(stack_fixture(change_index=2)), [])

    def test_missing_second_load(self):
        self.assertEqual(matching_stack_source_chains(stack_fixture(change_index=3)), [])

    def test_writer_must_be_matched(self):
        self.assertEqual(matching_stack_source_chains(stack_fixture(missing_writer=True)), [])

    def test_no_raw_offsets(self):
        result = summarize_stack_sources(stack_fixture())
        self.assertNotIn('block_start', result)
        self.assertNotIn('raw_bytes', result)
        self.assertNotIn('source_code_offset', result)

    def test_absent_signature(self):
        self.assertEqual(summarize_stack_sources(bytes(120))['matching_three_stack_byte_sources'], 0)


if __name__ == '__main__':
    unittest.main()
