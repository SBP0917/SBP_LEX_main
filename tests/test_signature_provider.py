from __future__ import annotations

import unittest
from unittest.mock import patch

from main import run_sbp_lex
from sbp_lex.security.signature_provider import (
    HybridMLDSA87Ed448SoftwareProvider,
    SignatureProviderUnavailable,
    build_signed_object,
    verify_signed_object,
)
from sbp_lex.security.token_stack import issue_token, verify_token
from sbp_lex.security.integrity import (
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.governance.three_p_doctrine import (
    THREE_P_ATTESTATION_PURPOSE,
    evaluate_three_p_core,
    three_p_hash_payload,
)
from sbp_lex.licensing.filed_licensing import invalidate_filed_licence
from tests.licence_support import (
    filed_licence_request_fields,
)
from sbp_lex.pipeline.runner import PipelineHybridTrustContexts
from tests import test_controlled_local_adapter as controlled_local_adapter


class PassingThreePCoreEvaluator:
    evaluator_id = "three-p-contract-fixture"
    evaluator_version = "1"
    authority_role = "CONSTITUTIONAL_3P_EVALUATOR"
    authority_credential_id = "three-p-contract-credential"

    def __init__(self, provider: HybridMLDSA87Ed448SoftwareProvider) -> None:
        self.provider = provider

    def evaluate(self, *, stage: str, snapshot: dict) -> dict:
        return build_signed_object(
            {
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_three_p_digest": snapshot["prior_three_p_digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determinations": {
                    primitive: {
                        "result": "SATISFIED",
                        "evidence_references": [
                            {
                                "evidence_id": (
                                    f"{primitive}:{snapshot['evaluation_sequence']}"
                                ),
                                "source": "controlled-test-evidence",
                                "digest": canonical_integrity_hash(
                                    {
                                        "primitive": primitive,
                                        "stage": stage,
                                        "sequence": snapshot[
                                            "evaluation_sequence"
                                        ],
                                    }
                                ),
                            }
                        ],
                    }
                    for primitive in ("P1", "P2", "P3")
                },
            },
            provider=self.provider,
            purpose=THREE_P_ATTESTATION_PURPOSE,
        )


class SignatureProviderTests(unittest.TestCase):
    def provider(self) -> HybridMLDSA87Ed448SoftwareProvider:
        return HybridMLDSA87Ed448SoftwareProvider.generate(
            provider_id="TEST_ONLY:SIGNATURE_PROVIDER_TESTS",
            three_p_attestation_admitted=True,
            licence_attestation_admitted=True,
            skg_attestation_admitted=True,
        )

    @staticmethod
    def trust_contexts(
        provider: HybridMLDSA87Ed448SoftwareProvider,
        *,
        include_signature: bool = True,
    ) -> PipelineHybridTrustContexts:
        context = provider.hybrid_verification_context(allow_test_only=True)
        return PipelineHybridTrustContexts(
            signature=context if include_signature else None,
            signature_owner_pin=(
                context.context_digest if include_signature else None
            ),
            three_p=context,
            three_p_owner_pin=context.context_digest,
            skg=context,
            skg_owner_pin=context.context_digest,
            filed_licence=context,
            filed_licence_owner_pin=context.context_digest,
        )

    def authority_request(self) -> dict:
        return {
            **filed_licence_request_fields(),
            "action": "review",
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "anchors": {
                "procedural_truth": True,
                "sovereign_knowledge_graph": True,
                "digital_twin_network": True,
                "planetary_population_constraints": True,
            },
            "attestation": {"verified": True, "attested": True},
            "indexed_attestations": [{"verified": True, "source": "authority-a"}],
            "output": {"result": "reviewed"},
            "payload": {"output": {"fact_verified_ratio": 1.0}},
            "ap_acf_class": "CLASS_2",
            "ap_acf_subclass": "CLASS_2",
            "requested_autonomy_level": 20,
            "requested_system_mode": "supervised",
            "autonomy_ceiling": 30,
            "operational_environment": "controlled",
            "public_exposure": "limited",
            "operational_scope": "local",
            "environment_modifiers": {
                "human_proximity": "controlled",
                "geographic_isolation": "not-applicable",
                "operational_containment": "verified",
            },
            "deployment_restrictions": ["licensed-environment-only"],
            "deployment_scope": "licensed-local-scope",
            "license_profile": {
                "allowed_classes": ["CLASS_2"],
                "max_autonomy_level": 30,
            },
        }

    def test_signing_without_injected_provider_has_no_fallback(self) -> None:
        with self.assertRaisesRegex(
            SignatureProviderUnavailable,
            "SIGNATURE_PROVIDER_NOT_INJECTED",
        ):
            build_signed_object({"request": "r-1"}, provider=None)

    def test_real_hybrid_signature_and_mutation_rejection(self) -> None:
        provider = self.provider()
        record = build_signed_object({"request": "r-2"}, provider=provider)
        context = provider.hybrid_verification_context(allow_test_only=True)

        self.assertTrue(
            verify_signed_object(
                record,
                provider=provider,
                trust_context=context,
                owner_pinned_context_digest=context.context_digest,
            )
        )
        record["request"] = "mutated"
        self.assertFalse(
            verify_signed_object(
                record,
                provider=provider,
                trust_context=context,
                owner_pinned_context_digest=context.context_digest,
            )
        )

    def test_software_provider_authenticates_tokens_but_has_no_effect_authority(self) -> None:
        provider = self.provider()
        foundation = controlled_local_adapter.ControlledLocalAdapterTests(
            "test_real_local_effect_requires_point_of_use_receipt"
        )
        foundation.setUp()
        try:
            state = foundation.ready_state()
            state["tokens"].pop("authority")
            evaluate_three_p_core(
                state,
                evaluator=PassingThreePCoreEvaluator(provider),
                attestation_provider=provider,
                stage="token_fixture",
                trust_context=self.trust_contexts(provider).three_p,
                owner_pinned_context_digest=(
                    self.trust_contexts(provider).three_p_owner_pin
                ),
            )
            three_p_entry = build_hash_chain_entry(
                previous_hash=state["state_hash"],
                stage="three_p_core:token_fixture",
                payload=three_p_hash_payload(state),
            )
            state["hash_chain"].append(three_p_entry)
            state["state_hash"] = three_p_entry["hash"]
            licence_record = state["filed_licence_trace"][0]
            determination = licence_record["evaluation_source"][
                "determination"
            ]
            bindings = licence_record["evaluation_snapshot"]["bindings"]
            issue_token(
                state,
                token_name="authority",
                issuer="root_of_trust",
                issued_at_stage="root_of_trust",
                payload={
                    "authority_first_result": "ALLOW",
                    "authority_first_reason": state[
                        "authority_first_reason"
                    ],
                    "licence_id": determination["licence_id"],
                    "license_tier": determination["tier"],
                    "filed_licence_digest": canonical_integrity_hash(
                        state["filed_licence_trace"][:1]
                    ),
                    "licence_bindings_digest": canonical_integrity_hash(
                        bindings
                    ),
                },
                provider=provider,
                three_p_attestation_provider=provider,
                three_p_trust_context=self.trust_contexts(provider).three_p,
                three_p_owner_pinned_context_digest=(
                    self.trust_contexts(provider).three_p_owner_pin
                ),
            )

            self.assertTrue(
                verify_token(
                    state,
                    "authority",
                    provider=provider,
                    require_effect_authority=False,
                    trust_context=self.trust_contexts(provider).signature,
                    owner_pinned_context_digest=(
                        self.trust_contexts(provider).signature_owner_pin
                    ),
                )
            )
            self.assertFalse(
                verify_token(
                    state,
                    "authority",
                    provider=provider,
                    require_effect_authority=True,
                    trust_context=self.trust_contexts(provider).signature,
                    owner_pinned_context_digest=(
                        self.trust_contexts(provider).signature_owner_pin
                    ),
                )
            )

            next_entry = build_hash_chain_entry(
                previous_hash=state["state_hash"],
                stage="procedural_truth",
                payload={"procedural_truth_result": "PASS"},
            )
            state["hash_chain"].append(next_entry)
            state["state_hash"] = next_entry["hash"]
            self.assertTrue(
                verify_token(
                    state,
                    "authority",
                    provider=provider,
                    require_effect_authority=False,
                    trust_context=self.trust_contexts(provider).signature,
                    owner_pinned_context_digest=(
                        self.trust_contexts(provider).signature_owner_pin
                    ),
                )
            )
        finally:
            foundation.tearDown()

    def test_pipeline_without_injection_halts_when_signing_is_reached(self) -> None:
        foundation = controlled_local_adapter.ControlledLocalAdapterTests(
            "test_real_local_effect_requires_point_of_use_receipt"
        )
        foundation.setUp()
        try:
            state = foundation.ready_state()
            state["tokens"].pop("authority")
            licence_record = state["filed_licence_trace"][0]
            determination = licence_record["evaluation_source"]["determination"]
            bindings = licence_record["evaluation_snapshot"]["bindings"]
            with self.assertRaisesRegex(
                ValueError,
                "TOKEN_ISSUANCE_HYBRID_SIGNATURE_REQUIRED",
            ):
                issue_token(
                    state,
                    token_name="authority",
                    issuer="root_of_trust",
                    issued_at_stage="root_of_trust",
                    payload={
                        "authority_first_result": "ALLOW",
                        "authority_first_reason": state["authority_first_reason"],
                        "licence_id": determination["licence_id"],
                        "license_tier": determination["tier"],
                        "filed_licence_digest": canonical_integrity_hash(
                            state["filed_licence_trace"][:1]
                        ),
                        "licence_bindings_digest": canonical_integrity_hash(bindings),
                    },
                    provider=None,
                    three_p_attestation_provider=foundation.authority,
                    three_p_trust_context=foundation.authority_context,
                    three_p_owner_pinned_context_digest=(
                        foundation.authority_owner_pin
                    ),
                )
        finally:
            foundation.tearDown()

    def test_pipeline_uses_injected_real_provider_until_framework_boundary(self) -> None:
        provider = self.provider()
        contexts = self.trust_contexts(provider)
        expected = {"decision": "DENY", "sentinel": "forwarded"}
        with patch("main.run_v2", return_value=expected) as delegated:
            result = run_sbp_lex(
                {"action": "review", "payload": {}, "context": {}},
                signature_provider=provider,
                hybrid_trust_contexts=contexts,
            )
        self.assertIs(result, expected)
        self.assertIs(
            delegated.call_args.kwargs["hybrid_trust_contexts"], contexts
        )
        self.assertIs(delegated.call_args.kwargs["signature_provider"], provider)

    def test_skg_failure_after_root_binding_invalidates_licence(self) -> None:
        result = invalidate_filed_licence(
            {
                "licence_id": "licence-one",
                "filed_licence_digest": canonical_integrity_hash(
                    {"licence": "active"}
                ),
                "licence_revocation_status": "ACTIVE",
            },
            stage="skg_authority",
            reason="SKG_AUTHORITY_TRUST_PIN_INVALID",
        )
        self.assertEqual(
            result["licence_invalidation_status"],
            "INVALIDATED",
        )
        self.assertTrue(result["licence_execution_disabled"])
        self.assertEqual(
            result["licensing_reason"],
            "SKG_AUTHORITY_TRUST_PIN_INVALID",
        )

if __name__ == "__main__":
    unittest.main()
