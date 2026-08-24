from __future__ import annotations

from copy import deepcopy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.identity.sovereign_identity import (
    BIOMETRIC_ATTESTATION_EVIDENCE_ONLY,
    IDENTITY_ADMISSION_STAGE,
    IDENTITY_DENY,
    IDENTITY_REVALIDATION_STAGE,
    IDENTITY_VERIFIED,
    SOVEREIGN_IDENTITY_ISSUER_ROLE,
    evaluate_sovereign_identity,
    sovereign_identity_hash_payload,
    verify_sovereign_identity,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_signed_object,
)


class IdentityEvidenceProvider:
    token_signing_admitted = True

    def __init__(self, *, admitted: bool = True) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
            MLDSA87PrivateKey.generate(),
            Ed448PrivateKey.generate(),
            provider_id="TEST_ONLY:SOVEREIGN_IDENTITY_EVIDENCE",
            key_epoch=1,
            key_version="test-1",
        )
        self.identity_attestation_admitted = admitted

    def __getattr__(self, name):
        return getattr(self._provider, name)


class IdentityEvidenceEvaluator:
    identity_evaluator_id = "sovereign-identity-evidence-authority"
    identity_evaluator_version = "1"
    identity_issuer_role = SOVEREIGN_IDENTITY_ISSUER_ROLE
    identity_issuer_credential_id = "sovereign-identity-issuer-credential"

    def __init__(self, provider: IdentityEvidenceProvider) -> None:
        self.provider = provider
        self.identity_credential_id = "identity-credential-au-0001"
        self.revocation_status = "ACTIVE"
        self.revocation_sequence = 1
        self.binding_overrides: dict = {}
        self.source_overrides: dict = {}
        self.replay_source: dict | None = None

    def evaluate_identity(self, *, stage: str, snapshot: dict) -> dict:
        if self.replay_source is not None:
            return deepcopy(self.replay_source)
        bindings = deepcopy(snapshot["bindings"])
        bindings.update(deepcopy(self.binding_overrides))
        determination = {
            "result": (
                IDENTITY_VERIFIED
                if self.revocation_status == "ACTIVE"
                else IDENTITY_DENY
            ),
            "identity_credential_id": self.identity_credential_id,
            "bindings": bindings,
            "biometric_attestation_semantics": (
                BIOMETRIC_ATTESTATION_EVIDENCE_ONLY
            ),
            "revocation_status": self.revocation_status,
            "revocation_sequence": self.revocation_sequence,
            "evidence_references": [
                {
                    "evidence_id": "biometric-attestation-reference-1",
                    "evidence_type": "BIOMETRIC_ATTESTATION_REFERENCE",
                    "source": "admitted-external-biometric-attestation-service",
                    "digest": bindings["biometric_attestation_digest"],
                }
            ],
        }
        payload = {
            "evaluator_id": self.identity_evaluator_id,
            "evaluator_version": self.identity_evaluator_version,
            "issuer_credential": {
                "credential_id": self.identity_issuer_credential_id,
                "authority_role": self.identity_issuer_role,
            },
            "stage": stage,
            "evaluation_sequence": snapshot["evaluation_sequence"],
            "request_fingerprint": snapshot["request_fingerprint"],
            "pre_evaluation_state_hash": snapshot["state_hash"],
            "evaluation_time": snapshot["evaluation_time"],
            "prior_identity_digest": snapshot["prior_identity_digest"],
            "snapshot_digest": canonical_integrity_hash(snapshot),
            "determination": determination,
        }
        payload.update(deepcopy(self.source_overrides))
        return build_signed_object(payload, provider=self.provider)


class SovereignIdentityTests(unittest.TestCase):
    def provider(self, *, admitted: bool = True) -> IdentityEvidenceProvider:
        return IdentityEvidenceProvider(admitted=admitted)

    @staticmethod
    def trust(provider: IdentityEvidenceProvider | None) -> dict:
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
        biometric_digest = canonical_integrity_hash(
            {"external_biometric_attestation_reference": "attestation-1"}
        )
        request = {
            "identity": {"subject_id": "subject-0001"},
            "biometric_attestation_digest": biometric_digest,
            "identity_jurisdictions": ["NZ", "AU"],
            "identity_access_grants": [
                {
                    "grant_id": "grant-nz-review",
                    "jurisdiction": "NZ",
                    "actions": ["review"],
                },
                {
                    "grant_id": "grant-au-review",
                    "jurisdiction": "AU",
                    "actions": ["review", "inspect"],
                },
            ],
        }
        request_fingerprint = canonical_integrity_hash(request)
        initial_entry = build_hash_chain_entry(
            previous_hash=GENESIS_HASH,
            stage="state_construction",
            payload={"request_fingerprint": request_fingerprint},
        )
        return {
            **request,
            "request_fingerprint": request_fingerprint,
            "hash_chain": [initial_entry],
            "state_hash": initial_entry["hash"],
            "evaluation_time": 1_700_000_000,
        }

    def bind_latest_identity(self, state: dict) -> dict:
        record = state["sovereign_identity_record"]
        entry = build_hash_chain_entry(
            previous_hash=state["state_hash"],
            stage=record["stage"],
            payload=sovereign_identity_hash_payload(state),
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]
        return entry

    def admit(
        self,
        state: dict,
        evaluator: IdentityEvidenceEvaluator,
        provider: IdentityEvidenceProvider,
    ) -> None:
        evaluate_sovereign_identity(
            state,
            stage=IDENTITY_ADMISSION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.bind_latest_identity(state)

    def test_signed_admission_binds_evidence_but_grants_no_permission(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        state = self.state()

        self.admit(state, evaluator, provider)

        self.assertEqual(state["sovereign_identity_result"], IDENTITY_VERIFIED)
        record = state["sovereign_identity_record"]
        self.assertEqual(record["bindings"]["jurisdictions"], ["AU", "NZ"])
        self.assertFalse(record["biometric_proof_established"])
        for field in (
            "access_granted",
            "authority_granted",
            "licence_granted",
            "execution_authority_granted",
            "effect_authority_granted",
        ):
            self.assertFalse(record[field])
        self.assertTrue(
            verify_sovereign_identity(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

    def test_signed_revalidation_binds_prior_digest(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        state = self.state()
        self.admit(state, evaluator, provider)
        first_digest = state["sovereign_identity_digest"]
        evaluator.revocation_sequence = 2

        evaluate_sovereign_identity(
            state,
            stage=IDENTITY_REVALIDATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.bind_latest_identity(state)

        self.assertEqual(
            state["sovereign_identity_record"]["prior_identity_digest"],
            first_digest,
        )
        self.assertTrue(
            verify_sovereign_identity(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                require_revalidation=True,
                **self.trust(provider),
            )
        )

    def test_post_bind_and_later_canonical_stage_append_remain_valid(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        state = self.state()
        self.admit(state, evaluator, provider)
        self.assertTrue(
            verify_sovereign_identity(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )
        later = build_hash_chain_entry(
            previous_hash=state["state_hash"],
            stage="later_pipeline_stage",
            payload={"result": "non_identity_work"},
        )
        state["hash_chain"].append(later)
        state["state_hash"] = later["hash"]
        self.assertTrue(
            verify_sovereign_identity(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

    def test_missing_duplicate_reordered_and_wrong_previous_binding_fail(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        admitted = self.state()
        self.admit(admitted, evaluator, provider)

        missing = deepcopy(admitted)
        missing["hash_chain"] = [missing["hash_chain"][0]]
        missing["state_hash"] = missing["hash_chain"][0]["hash"]

        duplicate = deepcopy(admitted)
        duplicate_entry = build_hash_chain_entry(
            previous_hash=duplicate["state_hash"],
            stage=duplicate["sovereign_identity_record"]["stage"],
            payload=sovereign_identity_hash_payload(duplicate),
        )
        duplicate["hash_chain"].append(duplicate_entry)
        duplicate["state_hash"] = duplicate_entry["hash"]

        wrong_previous = deepcopy(admitted)
        initial = wrong_previous["hash_chain"][0]
        intervening = build_hash_chain_entry(
            previous_hash=initial["hash"],
            stage="intervening_before_identity",
            payload={"unexpected": True},
        )
        identity_entry = build_hash_chain_entry(
            previous_hash=intervening["hash"],
            stage=wrong_previous["sovereign_identity_record"]["stage"],
            payload=sovereign_identity_hash_payload(wrong_previous),
        )
        wrong_previous["hash_chain"] = [initial, intervening, identity_entry]
        wrong_previous["state_hash"] = identity_entry["hash"]

        revalidated = deepcopy(admitted)
        evaluator.revocation_sequence = 2
        evaluate_sovereign_identity(
            revalidated,
            stage=IDENTITY_REVALIDATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.bind_latest_identity(revalidated)
        first_record, second_record = revalidated["sovereign_identity_trace"]
        initial = revalidated["hash_chain"][0]
        second_payload = sovereign_identity_hash_payload(revalidated)
        first_payload = sovereign_identity_hash_payload(
            {
                "sovereign_identity_record": first_record,
                "sovereign_identity_trace": [first_record],
            }
        )
        second_entry = build_hash_chain_entry(
            previous_hash=initial["hash"],
            stage=second_record["stage"],
            payload=second_payload,
        )
        first_entry = build_hash_chain_entry(
            previous_hash=second_entry["hash"],
            stage=first_record["stage"],
            payload=first_payload,
        )
        revalidated["hash_chain"] = [initial, second_entry, first_entry]
        revalidated["state_hash"] = first_entry["hash"]

        for label, candidate in (
            ("missing", missing),
            ("duplicate", duplicate),
            ("reordered", revalidated),
            ("wrong_previous", wrong_previous),
        ):
            with self.subTest(label=label):
                self.assertFalse(
                    verify_sovereign_identity(
                        candidate,
                        evaluator=evaluator,
                        attestation_provider=provider,
                        **self.trust(provider),
                    )
                )

    def test_live_request_and_identity_binding_mutation_fail_after_binding(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)

        request_mutated = self.state()
        self.admit(request_mutated, evaluator, provider)
        request_mutated["request_fingerprint"] = canonical_integrity_hash(
            {"different": "request"}
        )
        self.assertFalse(
            verify_sovereign_identity(
                request_mutated,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

        binding_mutated = self.state()
        self.admit(binding_mutated, evaluator, provider)
        binding_mutated["identity"] = {"subject_id": "other-subject"}
        self.assertFalse(
            verify_sovereign_identity(
                binding_mutated,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

    def test_missing_or_malformed_live_bindings_fail_closed(self) -> None:
        provider = self.provider()
        mutations = {
            "identity": None,
            "biometric_attestation_digest": "not-a-digest",
            "identity_jurisdictions": [],
            "identity_access_grants": [],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                state = self.state()
                state[field] = value
                self.admit(state, IdentityEvidenceEvaluator(provider), provider)
                self.assertEqual(state["sovereign_identity_result"], IDENTITY_DENY)
                self.assertEqual(
                    state["sovereign_identity_reason"],
                    "SOVEREIGN_IDENTITY_INPUT_BINDING_INVALID",
                )

    def test_identity_role_or_label_is_not_an_admitted_identity_shape(self) -> None:
        provider = self.provider()
        for extra in ({"role": "regulator"}, {"label": "sovereign"}):
            with self.subTest(extra=extra):
                state = self.state()
                state["identity"].update(extra)
                self.admit(state, IdentityEvidenceEvaluator(provider), provider)
                self.assertEqual(state["sovereign_identity_result"], IDENTITY_DENY)

    def test_missing_unadmitted_or_wrong_provider_fails_closed(self) -> None:
        signing_provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(signing_provider)
        for verifier in (None, self.provider(admitted=False), self.provider()):
            with self.subTest(verifier=verifier):
                state = self.state()
                self.admit(state, evaluator, verifier)
                self.assertEqual(state["sovereign_identity_result"], IDENTITY_DENY)

    def test_signed_binding_tamper_is_detected_after_digest_recalculation(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        state = self.state()
        self.admit(state, evaluator, provider)
        state["sovereign_identity_trace"][0]["evaluation_source"][
            "determination"
        ]["bindings"]["subject_identity"] = {"subject_id": "attacker"}
        state["sovereign_identity_trace"][0]["evaluation_source_digest"] = (
            canonical_integrity_hash(
                state["sovereign_identity_trace"][0]["evaluation_source"]
            )
        )
        state["sovereign_identity_record"] = deepcopy(
            state["sovereign_identity_trace"][0]
        )
        state["sovereign_identity_digest"] = canonical_integrity_hash(
            state["sovereign_identity_trace"]
        )

        self.assertFalse(
            verify_sovereign_identity(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

    def test_each_live_identity_binding_mismatch_is_detected(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        mutations = {
            "identity": {"subject_id": "other"},
            "biometric_attestation_digest": canonical_integrity_hash(
                {"other": "biometric-reference"}
            ),
            "identity_jurisdictions": ["AU"],
            "identity_access_grants": [
                {
                    "grant_id": "different-grant",
                    "jurisdiction": "AU",
                    "actions": ["review"],
                }
            ],
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                state = self.state()
                self.admit(state, evaluator, provider)
                state[field] = value
                self.assertFalse(
                    verify_sovereign_identity(
                        state,
                        evaluator=evaluator,
                        attestation_provider=provider,
                        **self.trust(provider),
                    )
                )

    def test_request_state_time_and_prior_digest_are_signed_bindings(self) -> None:
        provider = self.provider()
        fields = {
            "request_fingerprint": canonical_integrity_hash({"wrong": "request"}),
            "pre_evaluation_state_hash": canonical_integrity_hash(
                {"wrong": "state"}
            ),
            "evaluation_time": 1_700_000_001,
            "prior_identity_digest": canonical_integrity_hash({"wrong": "prior"}),
        }
        for field, value in fields.items():
            with self.subTest(field=field):
                state = self.state()
                evaluator = IdentityEvidenceEvaluator(provider)
                evaluator.source_overrides = {field: value}
                self.admit(state, evaluator, provider)
                self.assertEqual(state["sovereign_identity_result"], IDENTITY_DENY)
                self.assertEqual(
                    state["sovereign_identity_reason"],
                    "SOVEREIGN_IDENTITY_EVALUATION_BINDING_MISMATCH",
                )

    def test_signed_attestation_replay_is_rejected(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        state = self.state()
        self.admit(state, evaluator, provider)
        evaluator.replay_source = deepcopy(
            state["sovereign_identity_record"]["evaluation_source"]
        )

        evaluate_sovereign_identity(
            state,
            stage=IDENTITY_REVALIDATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )

        self.assertEqual(state["sovereign_identity_result"], IDENTITY_DENY)
        self.assertEqual(
            state["sovereign_identity_reason"],
            "SOVEREIGN_IDENTITY_ATTESTATION_REPLAY",
        )

    def test_revocation_sequence_rollback_is_rejected(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        evaluator.revocation_sequence = 4
        state = self.state()
        self.admit(state, evaluator, provider)
        evaluator.revocation_sequence = 3

        evaluate_sovereign_identity(
            state,
            stage=IDENTITY_REVALIDATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )

        self.assertEqual(state["sovereign_identity_result"], IDENTITY_DENY)
        self.assertEqual(
            state["sovereign_identity_reason"],
            "SOVEREIGN_IDENTITY_REVOCATION_ROLLBACK",
        )

    def test_revocation_fails_closed_and_cannot_verify(self) -> None:
        provider = self.provider()
        evaluator = IdentityEvidenceEvaluator(provider)
        state = self.state()
        self.admit(state, evaluator, provider)
        evaluator.revocation_status = "REVOKED"
        evaluator.revocation_sequence = 2

        evaluate_sovereign_identity(
            state,
            stage=IDENTITY_REVALIDATION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )

        self.assertEqual(state["sovereign_identity_result"], IDENTITY_DENY)
        self.assertEqual(
            state["sovereign_identity_reason"],
            "SOVEREIGN_IDENTITY_REVOKED",
        )
        self.assertEqual(
            state["sovereign_identity_revocation_status"], "REVOKED"
        )
        self.assertFalse(
            verify_sovereign_identity(
                state,
                evaluator=evaluator,
                attestation_provider=provider,
                require_revalidation=True,
                **self.trust(provider),
            )
        )


if __name__ == "__main__":
    unittest.main()
