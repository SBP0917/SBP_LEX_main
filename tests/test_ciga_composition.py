from __future__ import annotations

from copy import deepcopy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sbp_lex.composition.ciga_composition import (
    CIGA_CAPABILITY_CLASSES,
    CIGA_COMPOSITION_ATTESTATION_STAGE,
    CIGA_COMPOSITION_CONTRACT_ID,
    CIGA_COMPOSITION_PROOF_SCOPE,
    CIGA_COMPOSITION_REVALIDATION_STAGE,
    CIGA_COMPOSITION_ROLE,
    CIGA_COMPOSITION_SCHEMA_STATUS,
    CIGA_COMPOSITION_SIGNING_PURPOSE,
    COMPOSITION_ACTIVE,
    COMPOSITION_DENY,
    COMPOSITION_PASS,
    COMPOSITION_REVOKED,
    evaluate_ciga_composition,
    verify_ciga_composition,
)
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.security.hybrid_signature import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_hybrid_signed_object,
)
from sbp_lex.security.signature_provider import (
    Ed25519SoftwareProvider,
    build_legacy_non_effect_signed_object,
    verify_legacy_non_effect_signed_object,
)


class CompositionEvidenceProvider:
    def __init__(self, *, admitted: bool = True) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.generate(
            provider_id="CIGA_COMPOSITION_TEST_ONLY_HYBRID",
            key_epoch=1,
        )
        self.composition_attestation_admitted = admitted

    def __getattr__(self, name):
        return getattr(self._provider, name)


class LegacyCompositionEvidenceProvider:
    composition_attestation_admitted = True

    def __init__(self) -> None:
        self._provider = Ed25519SoftwareProvider.from_private_key(
            Ed25519PrivateKey.generate()
        )

    def __getattr__(self, name):
        return getattr(self._provider, name)


class CompositionEvaluator:
    evaluator_id = "ciga-composition-attestation-authority"
    evaluator_version = "1"
    authority_role = CIGA_COMPOSITION_ROLE
    authority_credential_id = "ciga-composition-credential"

    def __init__(self, provider: CompositionEvidenceProvider) -> None:
        self.provider = provider
        self.revocation_status = COMPOSITION_ACTIVE
        self.revocation_sequence = 1
        self.capability_attestations = [
            {
                "capability_class": capability_class,
                "component_id": f"component-{index}",
                "component_version": "1",
                "component_digest": canonical_integrity_hash(
                    {"capability_class": capability_class, "version": 1}
                ),
            }
            for index, capability_class in enumerate(
                CIGA_CAPABILITY_CLASSES, start=1
            )
        ]
        self.source_overrides: dict = {}
        self.cached_source: dict | None = None
        self.replay = False

    def evaluate_ciga_composition(self, *, stage: str, snapshot: dict) -> dict:
        if self.replay and self.cached_source is not None:
            return deepcopy(self.cached_source)
        determination = {
            "result": (
                COMPOSITION_PASS
                if self.revocation_status == COMPOSITION_ACTIVE
                else COMPOSITION_DENY
            ),
            "composition_version": snapshot["composition_version"],
            "capability_attestations": deepcopy(self.capability_attestations),
            "revocation_status": self.revocation_status,
            "revocation_sequence": self.revocation_sequence,
            "composition_only": True,
            "substantive_ciga_proven": False,
            "authority_granted": False,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_authority_granted": False,
            "pipeline_bypass_permitted": False,
        }
        payload = {
            "contract_id": CIGA_COMPOSITION_CONTRACT_ID,
            "schema_status": CIGA_COMPOSITION_SCHEMA_STATUS,
            "proof_scope": CIGA_COMPOSITION_PROOF_SCOPE,
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
            "composition_version": snapshot["composition_version"],
            "prior_composition_digest": snapshot[
                "prior_composition_digest"
            ],
            "snapshot_digest": canonical_integrity_hash(snapshot),
            "determination": determination,
        }
        payload.update(deepcopy(self.source_overrides))
        source = build_hybrid_signed_object(
            payload,
            provider=self.provider,
            purpose=CIGA_COMPOSITION_SIGNING_PURPOSE,
        )
        self.cached_source = deepcopy(source)
        return source


class CIGACompositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.owner_pins: dict[int, object] = {}

    def provider(self, *, admitted: bool = True) -> CompositionEvidenceProvider:
        provider = CompositionEvidenceProvider(admitted=admitted)
        self.owner_pins[id(provider)] = provider.hybrid_verification_context(
            allow_test_only=True
        )
        return provider

    def state(self) -> dict:
        request = {"request_id": "ciga-composition-request-1"}
        return {
            "request_fingerprint": canonical_integrity_hash(request),
            "state_hash": canonical_integrity_hash(
                {"state": "pre-composition"}
            ),
            "evaluation_time": 1_700_000_000,
            "ciga_composition_version": "ciga-composition-v1",
        }

    def attest(self, state, evaluator, provider, *, stage=None) -> None:
        context = self.owner_pins.get(id(provider))
        evaluate_ciga_composition(
            state,
            stage=stage or CIGA_COMPOSITION_ATTESTATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=context,
            owner_pinned_context_digest=(
                context.context_digest if context is not None else None
            ),
        )

    def verify(self, state, evaluator, provider, **kwargs) -> bool:
        context = self.owner_pins.get(id(provider))
        return verify_ciga_composition(
            state,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=context,
            owner_pinned_context_digest=(
                context.context_digest if context is not None else None
            ),
            **kwargs,
        )

    def test_exact_four_classes_are_signed_but_substantive_ciga_is_not_proven(self) -> None:
        provider = self.provider()
        evaluator = CompositionEvaluator(provider)
        state = self.state()

        self.attest(state, evaluator, provider)

        record = state["ciga_composition_record"]
        self.assertEqual(
            [
                item["capability_class"]
                for item in record["capability_attestations"]
            ],
            list(CIGA_CAPABILITY_CLASSES),
        )
        self.assertTrue(record["composition_only"])
        self.assertFalse(record["substantive_ciga_proven"])
        for field in (
            "authority_granted",
            "licence_granted",
            "execution_authority_granted",
            "effect_authority_granted",
            "pipeline_bypass_permitted",
        ):
            self.assertFalse(record[field])
            self.assertFalse(state[f"ciga_composition_{field}"])
        self.assertTrue(state["ciga_composition_scope_only"])
        self.assertFalse(state["ciga_composition_substantive_ciga_proven"])
        self.assertTrue(
            self.verify(state, evaluator, provider)
        )

    def test_missing_duplicate_extra_and_reordered_capabilities_fail_closed(self) -> None:
        provider = self.provider()
        for mutation in ("missing", "duplicate", "extra", "reordered"):
            with self.subTest(mutation=mutation):
                evaluator = CompositionEvaluator(provider)
                if mutation == "missing":
                    evaluator.capability_attestations.pop()
                elif mutation == "duplicate":
                    evaluator.capability_attestations[-1] = deepcopy(
                        evaluator.capability_attestations[0]
                    )
                    evaluator.capability_attestations[-1]["component_id"] = (
                        "different-component-id"
                    )
                elif mutation == "extra":
                    evaluator.capability_attestations.append(
                        {
                            "capability_class": "additional capability",
                            "component_id": "additional-component",
                            "component_version": "1",
                            "component_digest": canonical_integrity_hash(
                                {"additional": True}
                            ),
                        }
                    )
                else:
                    evaluator.capability_attestations.reverse()
                state = self.state()
                self.attest(state, evaluator, provider)
                self.assertEqual(state["ciga_composition_result"], COMPOSITION_DENY)
                self.assertEqual(
                    state["ciga_composition_reason"],
                    "CIGA_COMPOSITION_CAPABILITY_SET_INVALID",
                )

    def test_unavailable_unadmitted_or_untrusted_dependencies_fail_closed(self) -> None:
        signing_provider = self.provider()
        evaluator = CompositionEvaluator(signing_provider)
        cases = (
            (None, signing_provider),
            (evaluator, None),
            (evaluator, self.provider(admitted=False)),
            (evaluator, self.provider()),
        )
        for candidate_evaluator, candidate_provider in cases:
            with self.subTest(
                evaluator=candidate_evaluator, provider=candidate_provider
            ):
                state = self.state()
                self.attest(state, candidate_evaluator, candidate_provider)
                self.assertEqual(state["ciga_composition_result"], COMPOSITION_DENY)

    def test_owner_pin_is_independent_and_legacy_is_non_effect_only(self) -> None:
        provider = self.provider()
        evaluator = CompositionEvaluator(provider)

        missing_pin_state = self.state()
        evaluate_ciga_composition(
            missing_pin_state,
            stage=CIGA_COMPOSITION_ATTESTATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=None,
            owner_pinned_context_digest=None,
        )
        self.assertEqual(
            missing_pin_state["ciga_composition_reason"],
            "CIGA_COMPOSITION_OWNER_PIN_NOT_INJECTED_OR_INVALID",
        )

        bad_digest_state = self.state()
        evaluate_ciga_composition(
            bad_digest_state,
            stage=CIGA_COMPOSITION_ATTESTATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=self.owner_pins[id(provider)],
            owner_pinned_context_digest="0" * 128,
        )
        self.assertEqual(
            bad_digest_state["ciga_composition_reason"],
            "CIGA_COMPOSITION_OWNER_PIN_NOT_INJECTED_OR_INVALID",
        )

        wrong_provider = self.provider()
        wrong_pin = self.owner_pins[id(wrong_provider)]
        wrong_pin_state = self.state()
        evaluate_ciga_composition(
            wrong_pin_state,
            stage=CIGA_COMPOSITION_ATTESTATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=wrong_pin,
            owner_pinned_context_digest=wrong_pin.context_digest,
        )
        self.assertEqual(
            wrong_pin_state["ciga_composition_reason"],
            "CIGA_COMPOSITION_ATTESTATION_INVALID",
        )

        legacy = LegacyCompositionEvidenceProvider()
        legacy_object = build_legacy_non_effect_signed_object(
            {"legacy_test_only_non_effect": True}, provider=legacy
        )
        self.assertTrue(
            verify_legacy_non_effect_signed_object(
                legacy_object, provider=legacy
            )
        )
        legacy_state = self.state()
        self.attest(legacy_state, evaluator, legacy)
        self.assertEqual(legacy_state["ciga_composition_result"], COMPOSITION_DENY)
        self.assertFalse(
            legacy_state["ciga_composition_effect_authority_granted"]
        )

    def test_tamper_is_rejected_even_after_local_digest_recalculation(self) -> None:
        provider = self.provider()
        evaluator = CompositionEvaluator(provider)
        state = self.state()
        self.attest(state, evaluator, provider)
        trace = state["ciga_composition_trace"]
        trace[0]["evaluation_source"]["determination"][
            "capability_attestations"
        ][0]["component_digest"] = "0" * 128
        trace[0]["evaluation_source_digest"] = canonical_integrity_hash(
            trace[0]["evaluation_source"]
        )
        trace[0]["capability_attestations"] = deepcopy(
            trace[0]["evaluation_source"]["determination"][
                "capability_attestations"
            ]
        )
        state["ciga_composition_record"] = deepcopy(trace[0])
        state["ciga_composition_digest"] = canonical_integrity_hash(trace)

        self.assertFalse(
            self.verify(state, evaluator, provider)
        )

    def test_request_state_time_version_and_prior_digest_are_bound(self) -> None:
        provider = self.provider()
        overrides = {
            "request_fingerprint": canonical_integrity_hash({"wrong": "request"}),
            "pre_evaluation_state_hash": canonical_integrity_hash(
                {"wrong": "state"}
            ),
            "evaluation_time": 1_700_000_001,
            "composition_version": "wrong-version",
            "prior_composition_digest": canonical_integrity_hash(
                {"wrong": "prior"}
            ),
        }
        for field, value in overrides.items():
            with self.subTest(field=field):
                evaluator = CompositionEvaluator(provider)
                evaluator.source_overrides = {field: value}
                state = self.state()
                self.attest(state, evaluator, provider)
                self.assertEqual(state["ciga_composition_result"], COMPOSITION_DENY)
                self.assertEqual(
                    state["ciga_composition_reason"],
                    "CIGA_COMPOSITION_EVALUATION_BINDING_MISMATCH",
                )

    def test_revalidation_binds_prior_digest_and_replay_is_rejected(self) -> None:
        provider = self.provider()
        evaluator = CompositionEvaluator(provider)
        state = self.state()
        self.attest(state, evaluator, provider)
        first_digest = state["ciga_composition_digest"]
        evaluator.revocation_sequence = 2
        self.attest(
            state,
            evaluator,
            provider,
            stage=CIGA_COMPOSITION_REVALIDATION_STAGE,
        )
        self.assertEqual(
            state["ciga_composition_record"]["evaluation_snapshot"][
                "prior_composition_digest"
            ],
            first_digest,
        )
        self.assertTrue(
            self.verify(
                state,
                evaluator,
                provider,
                require_revalidation=True,
            )
        )

        replay_state = self.state()
        replay_evaluator = CompositionEvaluator(provider)
        self.attest(replay_state, replay_evaluator, provider)
        replay_evaluator.replay = True
        self.attest(
            replay_state,
            replay_evaluator,
            provider,
            stage=CIGA_COMPOSITION_REVALIDATION_STAGE,
        )
        self.assertEqual(replay_state["ciga_composition_result"], COMPOSITION_DENY)
        self.assertEqual(
            replay_state["ciga_composition_reason"],
            "CIGA_COMPOSITION_ATTESTATION_REPLAY",
        )

    def test_revocation_rollback_and_revocation_fail_closed(self) -> None:
        provider = self.provider()
        rollback_evaluator = CompositionEvaluator(provider)
        rollback_evaluator.revocation_sequence = 4
        rollback_state = self.state()
        self.attest(rollback_state, rollback_evaluator, provider)
        rollback_evaluator.revocation_sequence = 3
        self.attest(
            rollback_state,
            rollback_evaluator,
            provider,
            stage=CIGA_COMPOSITION_REVALIDATION_STAGE,
        )
        self.assertEqual(
            rollback_state["ciga_composition_reason"],
            "CIGA_COMPOSITION_REVOCATION_ROLLBACK",
        )

        revoked_evaluator = CompositionEvaluator(provider)
        revoked_state = self.state()
        self.attest(revoked_state, revoked_evaluator, provider)
        revoked_evaluator.revocation_status = COMPOSITION_REVOKED
        revoked_evaluator.revocation_sequence = 2
        self.attest(
            revoked_state,
            revoked_evaluator,
            provider,
            stage=CIGA_COMPOSITION_REVALIDATION_STAGE,
        )
        self.assertEqual(revoked_state["ciga_composition_result"], COMPOSITION_DENY)
        self.assertEqual(
            revoked_state["ciga_composition_revocation_status"],
            COMPOSITION_REVOKED,
        )
        self.assertFalse(
            self.verify(
                revoked_state,
                revoked_evaluator,
                provider,
                require_revalidation=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
