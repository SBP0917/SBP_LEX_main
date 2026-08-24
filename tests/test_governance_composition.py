from __future__ import annotations

import unittest

from sbp_lex.governance.engine import GovernanceEngine
from sbp_lex.governance.authority_provenance import (
    evaluate_authority_provenance,
)
from tests.authority_provenance_support import (
    AuthorityProvenanceFixture,
    append_authority_provenance_binding,
)


class GovernanceCompositionTests(unittest.TestCase):
    def valid_state(self) -> dict:
        fixture = AuthorityProvenanceFixture.create()
        state = fixture.state()
        evaluate_authority_provenance(
            state, dependencies=fixture.dependencies
        )
        append_authority_provenance_binding(state)
        self.authority_provenance_dependencies = fixture.dependencies
        state.update({
            "action": "inspect",
            "payload": {
                "policy": {
                    "active": True,
                    "policy_id": "owner-policy",
                    "version": "1",
                    "permitted_actions": ["inspect"],
                    "restricted_actions": [],
                }
            },
            "authority_first_result": "ALLOW",
            "classification_result": "ALLOW",
            "licensing_result": "ALLOW",
            "procedural_truth_result": "PASS",
            "filed_framework_results": {
                "PTODF": "PASS",
                "AJ-SAAF": "PASS",
            },
            "collective_signals": {"policy_conflict_signal": {}},
        })
        return state

    def execute(self, state: dict) -> None:
        GovernanceEngine().execute(
            state,
            authority_provenance_dependencies=(
                self.authority_provenance_dependencies
            ),
        )

    def test_missing_explicit_policy_denies(self) -> None:
        state = self.valid_state()
        state["governance_policy_record"] = {}
        self.execute(state)
        self.assertEqual(state["governance_result"], "DENY")

    def test_explicit_permitted_policy_allows(self) -> None:
        state = self.valid_state()
        self.execute(state)
        self.assertEqual(state["governance_result"], "ALLOW")

    def test_high_conflict_escalates_even_with_valid_policy(self) -> None:
        state = self.valid_state()
        state["collective_signals"]["policy_conflict_signal"] = {
            "conflicts_detected": True,
            "severity": "HIGH",
        }
        self.execute(state)
        self.assertEqual(state["governance_result"], "ESCALATE")

    def test_missing_ptodf_pass_denies(self) -> None:
        state = self.valid_state()
        del state["filed_framework_results"]["PTODF"]
        self.execute(state)
        self.assertEqual(state["governance_result"], "DENY")

    def test_missing_aj_saaf_pass_denies(self) -> None:
        state = self.valid_state()
        del state["filed_framework_results"]["AJ-SAAF"]
        self.execute(state)
        self.assertEqual(state["governance_result"], "DENY")


if __name__ == "__main__":
    unittest.main()
