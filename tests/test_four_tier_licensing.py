from __future__ import annotations

from copy import deepcopy
import unittest

from sbp_lex.licensing.filed_licensing import (
    FILED_LICENCE_TIERS,
    LICENCE_ALLOW,
    LICENCE_DENY,
    LICENCE_REVALIDATION_STAGE,
    LICENCE_ROOT_BINDING_STAGE,
    LICENCE_VALIDATION_STAGE,
    evaluate_filed_licence,
    invalidate_filed_licence,
    verify_filed_licence,
)
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.security.signature_provider import HybridMLDSA87Ed448SoftwareProvider
from sbp_lex.shared.state_builder import build_state
from tests.licence_support import (
    PassingFiledLicenceEvaluator,
    append_filed_licence_evaluation,
    filed_licence_request_fields,
)


class FourTierFiledLicensingTests(unittest.TestCase):
    def provider(self) -> HybridMLDSA87Ed448SoftwareProvider:
        return HybridMLDSA87Ed448SoftwareProvider.generate(
            provider_id="TEST_ONLY:FOUR_TIER_LICENSING_HYBRID",
            licence_attestation_admitted=True,
        )

    def pins(self, provider) -> dict:
        context = provider.hybrid_verification_context(allow_test_only=True)
        return {
            "trust_context": context,
            "owner_pinned_context_digest": context.context_digest,
        }

    def state(self, tier: str = "TIER_2_COMMERCIAL") -> dict:
        request = {
            **filed_licence_request_fields(),
            "license_tier": tier,
            "action": "review",
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "ap_acf_class": "CLASS_2",
            "requested_autonomy_level": 20,
            "evaluation_time": 1_700_000_000,
        }
        state = build_state(request)
        state["request_fingerprint"] = canonical_integrity_hash(request)
        state.update(
            {
                "resolved_authority": "owner",
                "jurisdiction": "AU",
                "ap_acf_class": "CLASS_2",
            }
        )
        return state

    def evaluate_all(
        self,
        state: dict,
        evaluator: PassingFiledLicenceEvaluator,
        provider: HybridMLDSA87Ed448SoftwareProvider,
    ) -> None:
        for stage in (
            LICENCE_ROOT_BINDING_STAGE,
            LICENCE_VALIDATION_STAGE,
            LICENCE_REVALIDATION_STAGE,
        ):
            append_filed_licence_evaluation(
                state,
                stage=stage,
                evaluator=evaluator,
                provider=provider,
            )

    def test_exact_filed_four_tiers_are_accepted_without_inferred_privileges(
        self,
    ) -> None:
        provider = self.provider()
        for tier in FILED_LICENCE_TIERS:
            with self.subTest(tier=tier):
                state = self.state(tier)
                evaluator = PassingFiledLicenceEvaluator(provider)
                self.evaluate_all(state, evaluator, provider)

                self.assertEqual(state["filed_licence_result"], LICENCE_ALLOW)
                self.assertEqual(state["license_tier"], tier)
                self.assertEqual(
                    state["filed_licence_record"]["evaluation_source"][
                        "determination"
                    ]["bindings"]["execution_rights"],
                    {"allowed_actions": ["review"]},
                )
                self.assertTrue(
                    verify_filed_licence(
                        state,
                        evaluator=evaluator,
                        attestation_provider=provider,
                        require_revalidation=True,
                        **self.pins(provider),
                    )
                )

    def test_unknown_or_case_variant_tier_fails_closed(self) -> None:
        provider = self.provider()
        for tier in ("TIER_5", "tier_2_commercial", "Tier 2 Commercial"):
            with self.subTest(tier=tier):
                state = self.state(tier)
                evaluate_filed_licence(
                    state,
                    stage=LICENCE_ROOT_BINDING_STAGE,
                    evaluator=PassingFiledLicenceEvaluator(provider),
                    attestation_provider=provider,
                    **self.pins(provider),
                )
                self.assertEqual(state["filed_licence_result"], LICENCE_DENY)
                self.assertEqual(
                    state["filed_licence_reason"],
                    "FILED_LICENCE_TIER_INVALID",
                )

    def test_each_filed_binding_is_mandatory(self) -> None:
        provider = self.provider()
        mutations = {
            "identity": None,
            "jurisdiction": "",
            "resolved_authority": "",
            "execution_rights": {},
            "requested_autonomy_level": None,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                state = self.state()
                state[field] = value
                evaluate_filed_licence(
                    state,
                    stage=LICENCE_ROOT_BINDING_STAGE,
                    evaluator=PassingFiledLicenceEvaluator(provider),
                    attestation_provider=provider,
                    **self.pins(provider),
                )
                self.assertEqual(state["filed_licence_result"], LICENCE_DENY)
                self.assertEqual(
                    state["filed_licence_reason"],
                    "FILED_LICENCE_REQUIRED_BINDING_MISSING",
                )

    def test_action_outside_signed_execution_rights_fails_at_every_tier(
        self,
    ) -> None:
        provider = self.provider()
        for tier in FILED_LICENCE_TIERS:
            with self.subTest(tier=tier):
                state = self.state(tier)
                state["action"] = "delete"
                evaluate_filed_licence(
                    state,
                    stage=LICENCE_ROOT_BINDING_STAGE,
                    evaluator=PassingFiledLicenceEvaluator(provider),
                    attestation_provider=provider,
                    **self.pins(provider),
                )
                self.assertEqual(state["filed_licence_result"], LICENCE_DENY)
                self.assertEqual(
                    state["filed_licence_reason"],
                    "FILED_LICENCE_ACTION_NOT_IN_SIGNED_EXECUTION_RIGHTS",
                )

    def test_signed_autonomy_binding_cannot_differ_from_live_state(self) -> None:
        provider = self.provider()
        evaluator = PassingFiledLicenceEvaluator(provider)
        evaluator.binding_overrides = {"autonomy_level": 10}
        state = self.state()

        evaluate_filed_licence(
            state,
            stage=LICENCE_ROOT_BINDING_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.pins(provider),
        )

        self.assertEqual(state["filed_licence_result"], LICENCE_DENY)
        self.assertEqual(
            state["filed_licence_reason"],
            "FILED_LICENCE_FIVE_BINDING_MISMATCH",
        )

    def test_unavailable_or_untrusted_attestation_provider_fails_closed(
        self,
    ) -> None:
        signing_provider = self.provider()
        evaluator = PassingFiledLicenceEvaluator(signing_provider)
        for verifier in (None, self.provider()):
            with self.subTest(verifier=verifier):
                state = self.state()
                evaluate_filed_licence(
                    state,
                    stage=LICENCE_ROOT_BINDING_STAGE,
                    evaluator=evaluator,
                    attestation_provider=verifier,
                )
                self.assertEqual(state["filed_licence_result"], LICENCE_DENY)

    def test_signature_tamper_fails_even_after_trace_digest_recalculation(
        self,
    ) -> None:
        provider = self.provider()
        evaluator = PassingFiledLicenceEvaluator(provider)
        state = self.state()
        self.evaluate_all(state, evaluator, provider)
        state["filed_licence_trace"][-1]["evaluation_source"][
            "determination"
        ]["bindings"]["identity"] = {"subject_id": "attacker"}
        state["filed_licence_trace"][-1]["evaluation_source_digest"] = (
            canonical_integrity_hash(
                state["filed_licence_trace"][-1]["evaluation_source"]
            )
        )
        state["filed_licence_record"] = deepcopy(
            state["filed_licence_trace"][-1]
        )
        state["filed_licence_digest"] = canonical_integrity_hash(
            state["filed_licence_trace"]
        )

        self.assertFalse(
            verify_filed_licence(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                require_revalidation=True,
                require_hash_binding=False,
                **self.pins(provider),
            )
        )

    def test_revocation_sequence_rollback_is_rejected(self) -> None:
        provider = self.provider()
        evaluator = PassingFiledLicenceEvaluator(provider)
        state = self.state()
        append_filed_licence_evaluation(
            state,
            stage=LICENCE_ROOT_BINDING_STAGE,
            evaluator=evaluator,
            provider=provider,
        )
        evaluator.revocation_sequence = 4
        append_filed_licence_evaluation(
            state,
            stage=LICENCE_VALIDATION_STAGE,
            evaluator=evaluator,
            provider=provider,
        )
        evaluator.revocation_sequence = 3
        append_filed_licence_evaluation(
            state,
            stage=LICENCE_REVALIDATION_STAGE,
            evaluator=evaluator,
            provider=provider,
        )

        self.assertFalse(
            verify_filed_licence(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                require_revalidation=True,
                **self.pins(provider),
            )
        )

    def test_revocation_before_validation_fails_closed(self) -> None:
        provider = self.provider()
        evaluator = PassingFiledLicenceEvaluator(provider)
        state = self.state()
        append_filed_licence_evaluation(
            state,
            stage=LICENCE_ROOT_BINDING_STAGE,
            evaluator=evaluator,
            provider=provider,
        )
        evaluator.revocation_status = "REVOKED"
        evaluator.revocation_sequence = 2

        append_filed_licence_evaluation(
            state,
            stage=LICENCE_VALIDATION_STAGE,
            evaluator=evaluator,
            provider=provider,
        )

        self.assertEqual(state["filed_licence_result"], LICENCE_DENY)
        self.assertEqual(state["licence_revocation_status"], "REVOKED")

    def test_revocation_before_runtime_revalidation_fails_closed(self) -> None:
        provider = self.provider()
        evaluator = PassingFiledLicenceEvaluator(provider)
        state = self.state()
        for stage in (
            LICENCE_ROOT_BINDING_STAGE,
            LICENCE_VALIDATION_STAGE,
        ):
            append_filed_licence_evaluation(
                state,
                stage=stage,
                evaluator=evaluator,
                provider=provider,
            )
        evaluator.revocation_status = "REVOKED"
        evaluator.revocation_sequence = 2

        append_filed_licence_evaluation(
            state,
            stage=LICENCE_REVALIDATION_STAGE,
            evaluator=evaluator,
            provider=provider,
        )

        self.assertEqual(state["filed_licence_result"], LICENCE_DENY)
        self.assertFalse(
            verify_filed_licence(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                require_revalidation=True,
                **self.pins(provider),
            )
        )

    def test_invalidation_is_separate_from_revocation(self) -> None:
        provider = self.provider()
        evaluator = PassingFiledLicenceEvaluator(provider)
        state = self.state()
        self.evaluate_all(state, evaluator, provider)

        invalidate_filed_licence(
            state,
            stage="governance:gala",
            reason="governance_failure",
        )

        self.assertEqual(state["licence_invalidation_status"], "INVALIDATED")
        self.assertEqual(state["licence_revocation_status"], "ACTIVE")
        self.assertEqual(state["licensing_result"], "INVALIDATED")


if __name__ == "__main__":
    unittest.main()
