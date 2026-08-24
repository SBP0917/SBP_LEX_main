from __future__ import annotations

from copy import deepcopy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.interface.authority_boundary import (
    AUTHORITY_BOUNDARY_CONTRACT_ID,
    AUTHORITY_BOUNDARY_EVALUATOR_ROLE,
    AUTHORITY_BOUNDARY_EVIDENCE_CLASSES,
    AUTHORITY_BOUNDARY_HASH_STAGE_PREFIX,
    AUTHORITY_BOUNDARY_SCHEMA_STATUS,
    BOUNDARY_DENY,
    BOUNDARY_PASS,
    MANDATE_ACTIVE,
    MANDATE_EXPIRED,
    MANDATE_INDETERMINATE,
    MANDATE_REVOKED,
    PARTICIPANT_ACTIVE,
    PARTICIPANT_INDETERMINATE,
    PARTICIPANT_REVOKED,
    STAKEHOLDER_CLASSES,
    authority_boundary_hash_payload,
    evaluate_authority_boundary,
    verify_authority_boundary,
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


class AdmittedInterfaceProvider:
    def __init__(self) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
            MLDSA87PrivateKey.generate(),
            Ed448PrivateKey.generate(),
            provider_id="TEST_ONLY:AUTHORITY_BOUNDARY",
            key_epoch=1,
            key_version="test-1",
        )
        self.token_signing_admitted = True
        self.three_p_attestation_admitted = False
        self.framework_attestation_admitted = False
        self.licence_attestation_admitted = False
        self.interface_attestation_admitted = True

    def __getattr__(self, name):
        return getattr(self._provider, name)


class SignedBoundaryEvaluator:
    evaluator_id = "authority-bounded-participant-v2"
    evaluator_version = "1"
    authority_role = AUTHORITY_BOUNDARY_EVALUATOR_ROLE
    authority_credential_id = "authority-boundary-credential"

    def __init__(self, provider: AdmittedInterfaceProvider) -> None:
        self.provider = provider
        self.participant_status = PARTICIPANT_ACTIVE
        self.mandate_status = MANDATE_ACTIVE
        self.valid_from = 1_600_000_000
        self.valid_until = 1_800_000_000
        self.mandate_actions = ["review"]
        self.mandate_jurisdictions = ["AU"]
        self.omit_evidence_class: str | None = None
        self.force_result: str | None = None
        self.override_flags: dict = {}
        self.cached_source: dict | None = None
        self.replay = False

    def evaluate_authority_boundary(
        self,
        *,
        stage: str,
        snapshot: dict,
    ) -> dict:
        if self.replay and self.cached_source is not None:
            return deepcopy(self.cached_source)
        eligible = (
            self.participant_status == PARTICIPANT_ACTIVE
            and self.mandate_status == MANDATE_ACTIVE
            and self.valid_from
            <= snapshot["evaluation_time"]
            < self.valid_until
            and snapshot["requested_action"] in self.mandate_actions
            and snapshot["requested_jurisdiction"]
            in self.mandate_jurisdictions
        )
        determination = {
            "result": (
                self.force_result
                if self.force_result is not None
                else BOUNDARY_PASS
                if eligible
                else BOUNDARY_DENY
            ),
            "participant_id": snapshot["participant_id"],
            "stakeholder_class": snapshot["stakeholder_class"],
            "participant_status": self.participant_status,
            "mandate_id": "signed-mandate-1",
            "mandate_status": self.mandate_status,
            "mandate_valid_from": self.valid_from,
            "mandate_valid_until": self.valid_until,
            "mandate_actions": list(self.mandate_actions),
            "mandate_jurisdictions": list(self.mandate_jurisdictions),
            "requested_action": snapshot["requested_action"],
            "requested_jurisdiction": snapshot["requested_jurisdiction"],
            "evidence_references": [
                {
                    "evidence_class": evidence_class,
                    "evidence_id": f"boundary-evidence-{index}",
                    "source": "admitted-participant-authority-source",
                    "digest": canonical_integrity_hash(
                        {
                            "evidence_class": evidence_class,
                            "participant_id": snapshot["participant_id"],
                            "sequence": snapshot["evaluation_sequence"],
                        }
                    ),
                }
                for index, evidence_class in enumerate(
                    AUTHORITY_BOUNDARY_EVIDENCE_CLASSES,
                    start=1,
                )
                if evidence_class != self.omit_evidence_class
            ],
            "stakeholder_label_grants_rights": False,
            "authority_granted": False,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_authority_granted": False,
            "pipeline_bypass_permitted": False,
        }
        determination.update(deepcopy(self.override_flags))
        source = build_signed_object(
            {
                "contract_id": AUTHORITY_BOUNDARY_CONTRACT_ID,
                "schema_status": AUTHORITY_BOUNDARY_SCHEMA_STATUS,
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
                "prior_boundary_digest": snapshot[
                    "prior_boundary_digest"
                ],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": determination,
            },
            provider=self.provider,
        )
        self.cached_source = deepcopy(source)
        return source


class AuthorityBoundedInterfaceTests(unittest.TestCase):
    @staticmethod
    def trust(provider: AdmittedInterfaceProvider | None) -> dict:
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

    def state(self, stakeholder_class: str = "regulators") -> dict:
        request = {
            "participant_id": "participant-1",
            "stakeholder_class": stakeholder_class,
            "action": "review",
            "requested_jurisdiction": "AU",
        }
        return {
            **request,
            "request_fingerprint": canonical_integrity_hash(request),
            "evaluation_time": 1_700_000_000,
            "hash_chain": [],
            "state_hash": GENESIS_HASH,
        }

    def evaluate_and_bind(
        self,
        state: dict,
        *,
        stage: str,
        evaluator: SignedBoundaryEvaluator,
        provider: AdmittedInterfaceProvider,
    ) -> None:
        evaluate_authority_boundary(
            state,
            stage=stage,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )
        entry = build_hash_chain_entry(
            previous_hash=state["state_hash"],
            stage=f"{AUTHORITY_BOUNDARY_HASH_STAGE_PREFIX}{stage}",
            payload=authority_boundary_hash_payload(state),
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]

    def test_exact_stakeholder_classes_and_schema_status_are_locked(
        self,
    ) -> None:
        self.assertEqual(
            STAKEHOLDER_CLASSES,
            (
                "governments",
                "regulators",
                "corporations",
                "NGOs",
                "treaty bodies",
            ),
        )
        self.assertEqual(
            AUTHORITY_BOUNDARY_SCHEMA_STATUS,
            "IMPLEMENTATION_DEFINED_V2_MECHANICS",
        )

    def test_each_stakeholder_class_requires_signed_active_mandate(self) -> None:
        for stakeholder_class in STAKEHOLDER_CLASSES:
            with self.subTest(stakeholder_class=stakeholder_class):
                provider = AdmittedInterfaceProvider()
                evaluator = SignedBoundaryEvaluator(provider)
                state = self.state(stakeholder_class)
                self.evaluate_and_bind(
                    state,
                    stage="participant_ingress",
                    evaluator=evaluator,
                    provider=provider,
                )
                self.assertEqual(
                    state["authority_boundary_result"],
                    BOUNDARY_PASS,
                )
                self.assertFalse(state["stakeholder_label_grants_rights"])
                self.assertFalse(state["participant_authority_granted"])
                self.assertFalse(state["participant_licence_granted"])
                self.assertFalse(
                    state["participant_execution_authority_granted"]
                )
                self.assertFalse(
                    state["participant_effect_authority_granted"]
                )
                self.assertFalse(
                    state["participant_pipeline_bypass_permitted"]
                )
                self.assertNotIn("decision", state)
                self.assertTrue(
                    verify_authority_boundary(
                        state,
                        evaluator=evaluator,
                        attestation_provider=provider,
                        **self.trust(provider),
                    )
                )

    def test_label_alone_missing_or_untrusted_dependencies_fail_closed(
        self,
    ) -> None:
        provider = AdmittedInterfaceProvider()
        evaluator = SignedBoundaryEvaluator(provider)

        label_only = self.state("governments")
        evaluate_authority_boundary(
            label_only,
            stage="participant_ingress",
            evaluator=None,
            attestation_provider=None,
            **self.trust(None),
        )
        self.assertEqual(label_only["authority_boundary_result"], BOUNDARY_DENY)
        self.assertFalse(label_only["stakeholder_label_grants_rights"])

        substituted = self.state()
        substituted_provider = AdmittedInterfaceProvider()
        evaluate_authority_boundary(
            substituted,
            stage="participant_ingress",
            evaluator=evaluator,
            attestation_provider=substituted_provider,
            **self.trust(substituted_provider),
        )
        self.assertEqual(substituted["authority_boundary_result"], BOUNDARY_DENY)
        self.assertEqual(
            substituted["authority_boundary_reason"],
            "AUTHORITY_BOUNDARY_ATTESTATION_INVALID",
        )

    def test_action_jurisdiction_and_stakeholder_must_match_exact_scope(
        self,
    ) -> None:
        provider = AdmittedInterfaceProvider()
        for mutation in (
            {"action": "delete"},
            {"requested_jurisdiction": "NZ"},
            {"stakeholder_class": "Government"},
        ):
            with self.subTest(mutation=mutation):
                state = self.state()
                state.update(mutation)
                evaluator = SignedBoundaryEvaluator(provider)
                evaluate_authority_boundary(
                    state,
                    stage="participant_ingress",
                    evaluator=evaluator,
                    attestation_provider=provider,
                    **self.trust(provider),
                )
                self.assertEqual(
                    state["authority_boundary_result"],
                    BOUNDARY_DENY,
                )

    def test_revoked_expired_and_indeterminate_states_fail_closed(self) -> None:
        cases = (
            ("participant", PARTICIPANT_REVOKED),
            ("participant", PARTICIPANT_INDETERMINATE),
            ("mandate", MANDATE_REVOKED),
            ("mandate", MANDATE_EXPIRED),
            ("mandate", MANDATE_INDETERMINATE),
        )
        for target, status in cases:
            with self.subTest(target=target, status=status):
                provider = AdmittedInterfaceProvider()
                evaluator = SignedBoundaryEvaluator(provider)
                if target == "participant":
                    evaluator.participant_status = status
                else:
                    evaluator.mandate_status = status
                state = self.state()
                evaluate_authority_boundary(
                    state,
                    stage="participant_ingress",
                    evaluator=evaluator,
                    attestation_provider=provider,
                    **self.trust(provider),
                )
                self.assertEqual(
                    state["authority_boundary_result"],
                    BOUNDARY_DENY,
                )

        provider = AdmittedInterfaceProvider()
        expired_by_time = SignedBoundaryEvaluator(provider)
        expired_by_time.valid_until = 1_700_000_000
        state = self.state()
        evaluate_authority_boundary(
            state,
            stage="participant_ingress",
            evaluator=expired_by_time,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(state["authority_boundary_result"], BOUNDARY_DENY)

    def test_missing_evidence_or_independent_authority_attempt_fails(self) -> None:
        provider = AdmittedInterfaceProvider()

        missing_evidence = SignedBoundaryEvaluator(provider)
        missing_evidence.omit_evidence_class = (
            AUTHORITY_BOUNDARY_EVIDENCE_CLASSES[-1]
        )
        missing = self.state()
        evaluate_authority_boundary(
            missing,
            stage="participant_ingress",
            evaluator=missing_evidence,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(missing["authority_boundary_result"], BOUNDARY_DENY)
        self.assertEqual(
            missing["authority_boundary_reason"],
            "AUTHORITY_BOUNDARY_EVIDENCE_CONTRACT_INVALID",
        )

        authority_attempt = SignedBoundaryEvaluator(provider)
        authority_attempt.override_flags = {"authority_granted": True}
        attempted = self.state()
        evaluate_authority_boundary(
            attempted,
            stage="participant_ingress",
            evaluator=authority_attempt,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(attempted["authority_boundary_result"], BOUNDARY_DENY)
        self.assertEqual(
            attempted["authority_boundary_reason"],
            "AUTHORITY_BOUNDARY_INDEPENDENT_AUTHORITY_PROHIBITED",
        )

    def test_replay_and_current_binding_changes_fail_closed(self) -> None:
        provider = AdmittedInterfaceProvider()
        evaluator = SignedBoundaryEvaluator(provider)
        state = self.state()
        self.evaluate_and_bind(
            state,
            stage="participant_ingress",
            evaluator=evaluator,
            provider=provider,
        )

        stale = deepcopy(state)
        stale["evaluation_time"] += 1
        self.assertFalse(
            verify_authority_boundary(
                stale,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )

        evaluator.replay = True
        state["evaluation_time"] += 1
        evaluate_authority_boundary(
            state,
            stage="participant_revalidation",
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self.assertEqual(state["authority_boundary_result"], BOUNDARY_DENY)
        self.assertEqual(
            state["authority_boundary_reason"],
            "AUTHORITY_BOUNDARY_EVALUATION_BINDING_MISMATCH",
        )

    def test_signed_source_trace_and_hash_tamper_fail_closed(self) -> None:
        provider = AdmittedInterfaceProvider()
        evaluator = SignedBoundaryEvaluator(provider)
        state = self.state()
        self.evaluate_and_bind(
            state,
            stage="participant_ingress",
            evaluator=evaluator,
            provider=provider,
        )

        source_tampered = deepcopy(state)
        source_tampered["authority_boundary_trace"][0]["evaluation_source"][
            "determination"
        ]["mandate_actions"] = ["delete"]
        source_tampered["authority_boundary_record"] = deepcopy(
            source_tampered["authority_boundary_trace"][0]
        )
        source_tampered["authority_boundary_digest"] = canonical_integrity_hash(
            source_tampered["authority_boundary_record"]
        )
        source_tampered["authority_boundary_trace_digest"] = (
            canonical_integrity_hash(
                source_tampered["authority_boundary_trace"]
            )
        )
        self.assertFalse(
            verify_authority_boundary(
                source_tampered,
                evaluator=evaluator,
                attestation_provider=provider,
                require_hash_binding=False,
                **self.trust(provider),
            )
        )

        chain_tampered = deepcopy(state)
        chain_tampered["hash_chain"][0]["payload_hash"] = "0" * 128
        self.assertFalse(
            verify_authority_boundary(
                chain_tampered,
                evaluator=evaluator,
                attestation_provider=provider,
                **self.trust(provider),
            )
        )


if __name__ == "__main__":
    unittest.main()
