from __future__ import annotations

from copy import deepcopy
import unittest

from sbp_lex.classification.router import evaluate_ap_acf_profile


class ApAcfBlueprintProfileTests(unittest.TestCase):
    def profile(self) -> dict:
        return {
            "ap_acf_class": "CLASS_5",
            "ap_acf_subclass": "CLASS_5B",
            "requested_autonomy_level": 75,
            "autonomy_ceiling": 75,
            "operational_environment": "constrained",
            "public_exposure": "restricted",
            "operational_scope": "bounded",
            "environment_modifiers": {
                "human_proximity": "low",
                "geographic_isolation": "high",
                "operational_containment": "verified",
            },
        }

    def assert_denied(self, state: dict, reason: str) -> None:
        self.assertEqual(evaluate_ap_acf_profile(state), (False, reason))

    def test_exact_blueprint_class_5_ceiling_is_admitted(self) -> None:
        self.assertEqual(
            evaluate_ap_acf_profile(self.profile()),
            (True, "classification_profile_accepted"),
        )

    def test_unknown_class_and_mismatched_subclass_fail_closed(self) -> None:
        unknown = self.profile()
        unknown["ap_acf_class"] = "CLASS_6"
        self.assert_denied(unknown, "ap_acf_class_unknown")

        mismatch = self.profile()
        mismatch["ap_acf_subclass"] = "CLASS_4B"
        self.assert_denied(mismatch, "ap_acf_subclass_mismatch")

    def test_class_5_declared_and_requested_ceiling_mismatch_fail_closed(self) -> None:
        declared = self.profile()
        declared["autonomy_ceiling"] = 74
        self.assert_denied(declared, "ap_acf_class_ceiling_mismatch")

        requested = self.profile()
        requested["requested_autonomy_level"] = 76
        self.assert_denied(requested, "requested_autonomy_exceeds_ceiling")

    def test_every_environment_input_is_required(self) -> None:
        for field in (
            "operational_environment",
            "public_exposure",
            "operational_scope",
        ):
            with self.subTest(field=field):
                state = self.profile()
                state[field] = None
                self.assert_denied(state, f"{field}_missing")

        for modifier in (
            "human_proximity",
            "geographic_isolation",
            "operational_containment",
        ):
            with self.subTest(modifier=modifier):
                state = deepcopy(self.profile())
                del state["environment_modifiers"][modifier]
                self.assert_denied(
                    state,
                    f"environment_modifier_{modifier}_missing",
                )

    def test_no_unstated_numeric_ceiling_is_invented_for_classes_one_to_four(self) -> None:
        state = self.profile()
        state.update(
            ap_acf_class="CLASS_4",
            ap_acf_subclass="CLASS_4A",
            requested_autonomy_level=40,
            autonomy_ceiling=50,
        )
        self.assertEqual(
            evaluate_ap_acf_profile(state),
            (True, "classification_profile_accepted"),
        )


if __name__ == "__main__":
    unittest.main()
