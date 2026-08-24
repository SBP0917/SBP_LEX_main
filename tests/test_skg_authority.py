from __future__ import annotations

from copy import deepcopy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.governance.skg_authority import (
    SKG_AUTHORITY_ROLE,
    SKG_AUTHORITY_ATTESTATION_PURPOSE,
    SKG_CONTENT_CLASSES,
    SKG_DENY,
    SKG_HASH_STAGE_PREFIX,
    SKG_NOT_SATISFIED,
    SKG_PASS,
    SKG_SATISFIED,
    SKG_SCHEMA_STATUS,
    SKG_V2_CONTRACT_ID,
    evaluate_skg_authority,
    skg_authority_hash_payload,
    verify_skg_authority,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.hybrid_signature import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_hybrid_signed_object,
)


class AdmittedSKGProvider:
    def __init__(self) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
            MLDSA87PrivateKey.generate(),
            Ed448PrivateKey.generate(),
            provider_id="TEST_ONLY:SKG_AUTHORITY",
            key_epoch=1,
            key_version="test-1",
            skg_attestation_admitted=True,
        )
        self.token_signing_admitted = True
        self.three_p_attestation_admitted = False
        self.framework_attestation_admitted = False
        self.licence_attestation_admitted = False
        self.skg_attestation_admitted = True

    def __getattr__(self, name):
        return getattr(self._provider, name)


class SignedSKGEvaluator:
    evaluator_id = "skg-v2-authority-evaluator"
    evaluator_version = "1"
    authority_role = SKG_AUTHORITY_ROLE
    authority_credential_id = "skg-v2-authority-credential"

    def __init__(
        self,
        provider: AdmittedSKGProvider,
        *,
        denied_class: str | None = None,
    ) -> None:
        self.provider = provider
        self.signing_purpose = SKG_AUTHORITY_ATTESTATION_PURPOSE
        self.denied_class = denied_class
        self.omit_evidence_class: str | None = None
        self.override_determination: dict | None = None
        self.cached_source: dict | None = None
        self.replay = False

    def evaluate_skg_authority(
        self,
        *,
        stage: str,
        snapshot: dict,
    ) -> dict:
        if self.replay and self.cached_source is not None:
            return deepcopy(self.cached_source)
        class_results = {
            content_class: (
                SKG_NOT_SATISFIED
                if content_class == self.denied_class
                else SKG_SATISFIED
            )
            for content_class in SKG_CONTENT_CLASSES
        }
        evidence = [
            {
                "content_class": content_class,
                "evidence_id": f"skg-evidence-{index}",
                "source": "admitted-skg-authority-source",
                "digest": canonical_integrity_hash(
                    {
                        "content_class": content_class,
                        "stage": stage,
                        "sequence": snapshot["evaluation_sequence"],
                    }
                ),
            }
            for index, content_class in enumerate(SKG_CONTENT_CLASSES, start=1)
            if content_class != self.omit_evidence_class
        ]
        determination = {
            "result": (
                SKG_DENY if self.denied_class is not None else SKG_PASS
            ),
            "content_class_results": class_results,
            "evidence_references": evidence,
            "authority_granted": False,
            "execution_authority_granted": False,
            "downstream_override_permitted": False,
        }
        if self.override_determination is not None:
            determination.update(deepcopy(self.override_determination))
        source = build_hybrid_signed_object(
            {
                "contract_id": SKG_V2_CONTRACT_ID,
                "schema_status": SKG_SCHEMA_STATUS,
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot[
                    "pre_evaluation_state_hash"
                ],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_skg_digest": snapshot["prior_skg_digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": determination,
            },
            provider=self.provider,
            purpose=self.signing_purpose,
        )
        self.cached_source = deepcopy(source)
        return source


class SKGAuthorityTests(unittest.TestCase):
    @staticmethod
    def trust(provider: AdmittedSKGProvider | None) -> dict:
        if provider is None:
            return {
                "attestation_trust_context": None,
                "owner_pinned_context_digest": None,
            }
        context = provider.hybrid_verification_context(allow_test_only=True)
        return {
            "attestation_trust_context": context,
            "owner_pinned_context_digest": context.context_digest,
        }

    def state(self) -> dict:
        return {
            "request_fingerprint": canonical_integrity_hash(
                {"action": "review", "payload": {}}
            ),
            "evaluation_time": 1_700_000_000,
            "hash_chain": [],
            "state_hash": GENESIS_HASH,
        }

    def evaluate_and_bind(
        self,
        state: dict,
        *,
        stage: str,
        evaluator: SignedSKGEvaluator,
        provider: AdmittedSKGProvider,
    ) -> None:
        evaluate_skg_authority(
            state,
            stage=stage,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )
        entry = build_hash_chain_entry(
            previous_hash=state["state_hash"],
            stage=f"{SKG_HASH_STAGE_PREFIX}{stage}",
            payload=skg_authority_hash_payload(state),
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]

    def test_exact_classes_and_implementation_defined_status_are_locked(
        self,
    ) -> None:
        self.assertEqual(
            SKG_CONTENT_CLASSES,
            (
                "Authority hierarchies",
                "Jurisdictional legitimacy",
                "Statutory and constitutional precedence",
                "Procedural obligations",
                "Evidentiary sufficiency",
                "Conflict resolution precedence",
                "Treaty and delegated mandates",
            ),
        )
        self.assertEqual(
            SKG_SCHEMA_STATUS,
            "IMPLEMENTATION_DEFINED_V2_MECHANICS",
        )

    def test_signed_all_class_evaluation_is_bound_and_non_authorizing(
        self,
    ) -> None:
        provider = AdmittedSKGProvider()
        evaluator = SignedSKGEvaluator(provider)
        state = self.state()
        self.evaluate_and_bind(
            state,
            stage="authority_resolution",
            evaluator=evaluator,
            provider=provider,
        )

        self.assertEqual(state["skg_authority_result"], SKG_PASS)
        self.assertFalse(state["skg_authority_granted"])
        self.assertFalse(state["skg_execution_authority_granted"])
        self.assertFalse(state["skg_downstream_override_permitted"])
        self.assertEqual(
            [
                reference["content_class"]
                for reference in state["skg_authority_record"][
                    "evidence_references"
                ]
            ],
            list(SKG_CONTENT_CLASSES),
        )
        self.assertTrue(
            verify_skg_authority(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

    def test_each_unsatisfied_class_fails_closed(self) -> None:
        for content_class in SKG_CONTENT_CLASSES:
            with self.subTest(content_class=content_class):
                provider = AdmittedSKGProvider()
                evaluator = SignedSKGEvaluator(
                    provider,
                    denied_class=content_class,
                )
                state = self.state()
                evaluate_skg_authority(
                    state,
                    stage="authority_resolution",
                    evaluator=evaluator,
                    attestation_provider=provider,
                    **self.trust(provider),
                )
                self.assertEqual(state["skg_authority_result"], SKG_DENY)
                self.assertFalse(state["skg_authority_granted"])
                self.assertFalse(state["skg_execution_authority_granted"])
                self.assertFalse(state["skg_downstream_override_permitted"])

    def test_missing_or_untrusted_dependencies_fail_closed(self) -> None:
        provider = AdmittedSKGProvider()
        evaluator = SignedSKGEvaluator(provider)

        missing_evaluator = self.state()
        evaluate_skg_authority(
            missing_evaluator,
            stage="authority_resolution",
            evaluator=None,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(missing_evaluator["skg_authority_result"], SKG_DENY)

        missing_provider = self.state()
        evaluate_skg_authority(
            missing_provider,
            stage="authority_resolution",
            evaluator=evaluator,
            attestation_provider=None,
            **self.trust(None),
        )
        self.assertEqual(missing_provider["skg_authority_result"], SKG_DENY)

        substituted_provider = AdmittedSKGProvider()
        substituted = self.state()
        evaluate_skg_authority(
            substituted,
            stage="authority_resolution",
            evaluator=evaluator,
            attestation_provider=substituted_provider,
            **self.trust(substituted_provider),
        )
        self.assertEqual(substituted["skg_authority_result"], SKG_DENY)
        self.assertEqual(substituted["skg_authority_reason"], "SKG_ATTESTATION_INVALID")

    def test_missing_evidence_or_override_attempt_fails_closed(self) -> None:
        provider = AdmittedSKGProvider()

        missing_evidence = SignedSKGEvaluator(provider)
        missing_evidence.omit_evidence_class = SKG_CONTENT_CLASSES[-1]
        missing_state = self.state()
        evaluate_skg_authority(
            missing_state,
            stage="authority_resolution",
            evaluator=missing_evidence,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(missing_state["skg_authority_result"], SKG_DENY)
        self.assertEqual(
            missing_state["skg_authority_reason"],
            "SKG_EVIDENCE_CONTRACT_INVALID",
        )

        override = SignedSKGEvaluator(provider)
        override.override_determination = {
            "downstream_override_permitted": True
        }
        override_state = self.state()
        evaluate_skg_authority(
            override_state,
            stage="authority_resolution",
            evaluator=override,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(override_state["skg_authority_result"], SKG_DENY)
        self.assertEqual(
            override_state["skg_authority_reason"],
            "SKG_DOWNSTREAM_OVERRIDE_PROHIBITED",
        )

    def test_replay_at_later_stage_fails_binding(self) -> None:
        provider = AdmittedSKGProvider()
        evaluator = SignedSKGEvaluator(provider)
        state = self.state()
        self.evaluate_and_bind(
            state,
            stage="authority_resolution",
            evaluator=evaluator,
            provider=provider,
        )
        evaluator.replay = True
        state["evaluation_time"] += 1

        evaluate_skg_authority(
            state,
            stage="lifecycle_boundary",
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )

        self.assertEqual(state["skg_authority_result"], SKG_DENY)
        self.assertEqual(
            state["skg_authority_reason"],
            "SKG_EVALUATION_BINDING_MISMATCH",
        )

    def test_second_evaluation_binds_prior_digest_and_chain_tip(self) -> None:
        provider = AdmittedSKGProvider()
        evaluator = SignedSKGEvaluator(provider)
        state = self.state()
        self.evaluate_and_bind(
            state,
            stage="authority_resolution",
            evaluator=evaluator,
            provider=provider,
        )
        prior_digest = state["skg_authority_digest"]
        prior_chain_tip = state["state_hash"]
        state["evaluation_time"] += 1
        self.evaluate_and_bind(
            state,
            stage="lifecycle_boundary",
            evaluator=evaluator,
            provider=provider,
        )

        second_snapshot = state["skg_authority_record"][
            "evaluation_snapshot"
        ]
        self.assertEqual(second_snapshot["prior_skg_digest"], prior_digest)
        self.assertEqual(
            second_snapshot["pre_evaluation_state_hash"],
            prior_chain_tip,
        )
        self.assertTrue(
            verify_skg_authority(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

    def test_trace_signature_and_hash_binding_tamper_fail_closed(self) -> None:
        provider = AdmittedSKGProvider()
        evaluator = SignedSKGEvaluator(provider)
        state = self.state()
        self.evaluate_and_bind(
            state,
            stage="authority_resolution",
            evaluator=evaluator,
            provider=provider,
        )

        trace_tampered = deepcopy(state)
        trace_tampered["skg_authority_trace"][0]["stage"] = "changed"
        trace_tampered["skg_authority_trace_digest"] = (
            canonical_integrity_hash(trace_tampered["skg_authority_trace"])
        )
        self.assertFalse(
            verify_skg_authority(
                trace_tampered,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

        signature_tampered = deepcopy(state)
        signature_tampered["skg_authority_trace"][0]["evaluation_source"][
            "determination"
        ]["content_class_results"][SKG_CONTENT_CLASSES[0]] = (
            SKG_NOT_SATISFIED
        )
        signature_tampered["skg_authority_record"] = deepcopy(
            signature_tampered["skg_authority_trace"][0]
        )
        signature_tampered["skg_authority_digest"] = (
            canonical_integrity_hash(signature_tampered["skg_authority_record"])
        )
        signature_tampered["skg_authority_trace_digest"] = (
            canonical_integrity_hash(signature_tampered["skg_authority_trace"])
        )
        self.assertFalse(
            verify_skg_authority(
                signature_tampered,
                evaluator=evaluator,
                attestation_provider=provider,
                require_hash_binding=False,
                **self.trust(provider),
            )
        )

        chain_tampered = deepcopy(state)
        chain_tampered["hash_chain"][0]["payload_hash"] = "0" * 128
        self.assertFalse(
            verify_skg_authority(
                chain_tampered,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

    def test_prior_digest_and_current_time_are_not_replayable(self) -> None:
        provider = AdmittedSKGProvider()
        evaluator = SignedSKGEvaluator(provider)
        state = self.state()
        self.evaluate_and_bind(
            state,
            stage="authority_resolution",
            evaluator=evaluator,
            provider=provider,
        )

        stale = deepcopy(state)
        stale["evaluation_time"] += 1
        self.assertFalse(
            verify_skg_authority(
                stale,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

        prior_tampered = deepcopy(state)
        prior_tampered["skg_authority_trace"][0]["evaluation_snapshot"][
            "prior_skg_digest"
        ] = "0" * 128
        prior_tampered["skg_authority_record"] = deepcopy(
            prior_tampered["skg_authority_trace"][0]
        )
        prior_tampered["skg_authority_digest"] = canonical_integrity_hash(
            prior_tampered["skg_authority_record"]
        )
        prior_tampered["skg_authority_trace_digest"] = (
            canonical_integrity_hash(prior_tampered["skg_authority_trace"])
        )
        self.assertFalse(
            verify_skg_authority(
                prior_tampered,
                evaluator=evaluator,
                attestation_provider=provider,
                require_hash_binding=False,
                **self.trust(provider),
            )
        )

    def test_owner_pin_purpose_and_legacy_provider_fail_closed(self) -> None:
        provider = AdmittedSKGProvider()
        evaluator = SignedSKGEvaluator(provider)
        context = provider.hybrid_verification_context(allow_test_only=True)
        state = self.state()
        evaluate_skg_authority(
            state,
            stage="authority_resolution",
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=context,
            owner_pinned_context_digest="0" * 128,
        )
        self.assertEqual(
            state["skg_authority_reason"],
            "SKG_OWNER_TRUST_PIN_INVALID",
        )

        wrong_purpose = SignedSKGEvaluator(provider)
        wrong_purpose.signing_purpose = "SBP_LEX_V2_WRONG_SKG_PURPOSE"
        state = self.state()
        evaluate_skg_authority(
            state,
            stage="authority_resolution",
            evaluator=wrong_purpose,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(
            state["skg_authority_reason"],
            "SKG_ATTESTATION_INVALID",
        )

        class LegacyAdmittedProvider:
            algorithm = "Ed25519"
            skg_attestation_admitted = True

        state = self.state()
        evaluate_skg_authority(
            state,
            stage="authority_resolution",
            evaluator=SignedSKGEvaluator(provider),
            attestation_provider=LegacyAdmittedProvider(),
            **self.trust(provider),
        )
        self.assertEqual(
            state["skg_authority_reason"],
            "SKG_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED",
        )
        complete = self.state()
        admitted_evaluator = SignedSKGEvaluator(provider)
        self.evaluate_and_bind(
            complete,
            stage="authority_resolution",
            evaluator=admitted_evaluator,
            provider=provider,
        )
        self.assertFalse(
            verify_skg_authority(
                complete,
                evaluator=admitted_evaluator,
                attestation_provider=LegacyAdmittedProvider(),
                **self.trust(provider),
            )
        )


if __name__ == "__main__":
    unittest.main()
