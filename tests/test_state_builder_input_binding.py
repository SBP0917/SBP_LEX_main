from __future__ import annotations

from copy import deepcopy
import unittest

from sbp_lex.classification.router import run_classification
from sbp_lex.shared.state_builder import build_state
from sbp_lex.security.integrity import canonical_integrity_hash
from tests.licence_support import (
    filed_licence_request_fields,
)


class StateBuilderInputBindingTests(unittest.TestCase):
    def request(self) -> dict:
        return {
            **filed_licence_request_fields(),
            "action": "review",
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "ap_acf_class": "CLASS_4A",
            "ap_acf_subclass": "CLASS_4A",
            "requested_autonomy_level": 40,
            "requested_system_mode": "supervised",
            "autonomy_ceiling": 50,
            "operational_environment": "contained-industrial",
            "public_exposure": "restricted",
            "operational_scope": "site-limited",
            "environment_modifiers": {
                "human_proximity": "low",
                "geographic_isolation": "high",
                "operational_containment": "verified",
            },
            "deployment_restrictions": ["named-site-only"],
            "deployment_scope": "licensed-site",
            "license_profile": {
                "allowed_classes": ["CLASS_4A"],
                "max_autonomy_level": 50,
            },
        }

    def test_canonical_state_preserves_exact_classification_and_licence_inputs(
        self,
    ) -> None:
        request = self.request()
        original = deepcopy(request)
        state = build_state(request)

        for field in (
            "requested_autonomy_level",
            "requested_system_mode",
            "autonomy_ceiling",
            "operational_environment",
            "public_exposure",
            "operational_scope",
            "environment_modifiers",
            "deployment_restrictions",
            "deployment_scope",
            "identity",
            "license_tier",
            "execution_rights",
            "license_profile",
        ):
            self.assertEqual(state[field], original[field])

        self.assertEqual(
            state["submitted_ap_acf_class"], original["ap_acf_class"]
        )
        self.assertEqual(
            state["submitted_ap_acf_subclass"],
            original["ap_acf_subclass"],
        )
        self.assertEqual(
            state["submitted_authority_claim"],
            original["resolved_authority"],
        )
        self.assertEqual(
            state["requested_jurisdiction"], original["jurisdiction"]
        )
        self.assertIsNone(state["ap_acf_class"])
        self.assertIsNone(state["ap_acf_subclass"])
        self.assertEqual(state["resolved_authority"], "")
        self.assertEqual(state["jurisdiction"], "")

        request["environment_modifiers"]["human_proximity"] = "changed"
        request["license_profile"]["allowed_classes"].append("CLASS_5")
        self.assertEqual(state["environment_modifiers"]["human_proximity"], "low")
        self.assertEqual(
            state["license_profile"]["allowed_classes"],
            ["CLASS_4A"],
        )

    def test_submitted_classification_cannot_reach_active_router_without_provenance(
        self,
    ) -> None:
        state = build_state(self.request())
        state["request_fingerprint"] = canonical_integrity_hash(self.request())
        state = run_classification(state)

        self.assertEqual(state["classification_result"], "DENY")
        self.assertEqual(
            state["classification_reason"],
            "authority_provenance_not_current_and_valid",
        )


if __name__ == "__main__":
    unittest.main()
