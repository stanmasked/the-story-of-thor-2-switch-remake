import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from stage104_r13_abi_evidence_gate import evaluate


def reports():
    stage99 = {
        "schema_version": 1,
        "stage": "stage99_callee_register_preservation_audit",
        "analysis": {
            "second_writer_source_register_seeded_to_one": True,
            "pre_store_call_count": 3,
            "second_writer_is_final_call_delay_slot": True,
            "first_callee_has_unresolved_indirect_pointer_call": True,
            "first_callee_direct_r13_write_count": 0,
            "loader_wrapper_normal_success_path_preserves_r13": True,
            "pre_store_call_summaries": [
                {
                    "role": "in_image_callee",
                    "r13_preservation_proven": False,
                    "r13_preservation_unresolved": True,
                },
                {
                    "role": "in_image_direct_callee",
                    "r13_preservation_proven": True,
                    "r13_preservation_unresolved": False,
                },
                {
                    "role": "loader_wrapper",
                    "r13_preservation_proven": False,
                    "r13_preservation_unresolved": True,
                },
            ],
        },
    }
    stage103 = {
        "schema_version": 1,
        "stage": "stage103_sys_chgscuim_argument_audit",
        "analysis": {
            "all_scanned_slot_call_pairs_resolved": 11,
            "documented_sys_chgscuim_argument_shape_compatible": True,
            "runtime_target_identified_as_sys_chgscuim": False,
        },
    }
    return stage99, stage103


class Stage104R13EvidenceGateTests(unittest.TestCase):
    def test_complete_evidence_supports_only_conditional_claim(self):
        stage99, stage103 = reports()
        result = evaluate(stage99, stage103)["analysis"]
        self.assertTrue(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )
        self.assertFalse(result["runtime_r13_preservation_confirmed"])
        self.assertFalse(result["unconditional_r13_one_proven"])

    def test_argument_shape_mismatch_blocks_conditional_claim(self):
        stage99, stage103 = reports()
        stage103["analysis"]["documented_sys_chgscuim_argument_shape_compatible"] = False
        result = evaluate(stage99, stage103)["analysis"]
        self.assertFalse(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )

    def test_missing_direct_callee_preservation_blocks_claim(self):
        stage99, stage103 = reports()
        stage99["analysis"]["pre_store_call_summaries"][1]["r13_preservation_proven"] = False
        result = evaluate(stage99, stage103)["analysis"]
        self.assertFalse(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )

    def test_wrapper_success_path_must_preserve_r13(self):
        stage99, stage103 = reports()
        stage99["analysis"]["loader_wrapper_normal_success_path_preserves_r13"] = False
        result = evaluate(stage99, stage103)["analysis"]
        self.assertFalse(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )

    def test_initial_seed_must_be_one(self):
        stage99, stage103 = reports()
        stage99["analysis"]["second_writer_source_register_seeded_to_one"] = False
        result = evaluate(stage99, stage103)["analysis"]
        self.assertFalse(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )

    def test_dynamic_callee_must_have_no_direct_r13_writes(self):
        stage99, stage103 = reports()
        stage99["analysis"]["first_callee_direct_r13_write_count"] = 1
        result = evaluate(stage99, stage103)["analysis"]
        self.assertFalse(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )

    def test_runtime_claim_remains_false_even_when_static_gate_passes(self):
        stage99, stage103 = reports()
        stage103["analysis"]["runtime_target_identified_as_sys_chgscuim"] = True
        result = evaluate(stage99, stage103)["analysis"]
        self.assertTrue(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )
        self.assertFalse(result["runtime_slot_target_confirmed"])
        self.assertFalse(result["runtime_r13_preservation_confirmed"])

    def test_output_contract_has_no_private_locations_or_values(self):
        stage99, stage103 = reports()
        result = evaluate(stage99, stage103)
        analysis = result["analysis"]
        self.assertFalse(analysis["private_addresses_or_code_offsets_emitted"])
        self.assertFalse(any("offset" in key or "address" in key or "raw" in key for key in analysis))

    def test_missing_evidence_fails_closed(self):
        result = evaluate({}, {})["analysis"]
        self.assertFalse(
            result["conditional_static_r13_one_supported_if_slot_is_sys_chgscuim_and_uses_default_shc_abi"]
        )


if __name__ == "__main__":
    unittest.main()
