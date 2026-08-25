from __future__ import annotations

from copy import deepcopy
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.audit.audit_ledger import (
    verify_audit_ledger,
    verify_audit_record,
)
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.baseline.request_controls import FoundationalRequestDependencies
from sbp_lex.governance.filed_frameworks import (
    ABEGF,
    ABEGF_SUSPENSION_CONTROLS,
    AJ_SAAF,
    AJ_SAAF_RECALCULATION_TRIGGERS,
    FILED_FRAMEWORK_AUTHORITY_ROLE,
    FILED_FRAMEWORK_ATTESTATION_PURPOSE,
    FILED_FRAMEWORK_ORDER,
    FILED_FRAMEWORK_STAGES,
    FRAMEWORK_DENY,
    FRAMEWORK_PASS,
    GALA,
    PTODF,
    evaluate_filed_framework,
    filed_framework_hash_payload,
    verify_filed_frameworks,
)
from sbp_lex.governance.filed_lifecycle import (
    FILED_LIFECYCLE_ENGINE_IDS,
    FILED_LIFECYCLE_ORDER,
    FILED_LIFECYCLE_STAGES,
    LIFECYCLE_DENY,
)
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
    governance_integrity_revocation_binding,
)
from sbp_lex.governance.skg_authority import SKG_HASH_STAGE_PREFIX
from sbp_lex.governance.three_p_doctrine import THREE_P_ATTESTATION_PURPOSE
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.hybrid_signature import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_hybrid_signed_object,
)
from sbp_lex.security.signature_provider import build_signed_object
from sbp_lex.shared.state_builder import build_state
from sbp_lex.pipeline.runner import PipelineHybridTrustContexts
from sbp_lex.licensing.filed_licensing import (
    LICENCE_REVALIDATION_STAGE,
    LICENCE_ROOT_BINDING_STAGE,
    LICENCE_VALIDATION_STAGE,
)
from tests.licence_support import (
    PassingFiledLicenceEvaluator,
    append_filed_licence_evaluation,
    filed_licence_request_fields,
)
from tests.governance_support import (
    PassingFiledLifecycleEvaluator,
    PassingSKGAuthorityEvaluator,
)


class FiledEvidenceProvider:
    token_signing_admitted = True
    three_p_attestation_admitted = True
    framework_attestation_admitted = True
    licence_attestation_admitted = True
    skg_attestation_admitted = True
    lifecycle_attestation_admitted = True

    def __init__(self) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
            MLDSA87PrivateKey.generate(),
            Ed448PrivateKey.generate(),
            provider_id="TEST_ONLY:FILED_FRAMEWORK",
            key_epoch=1,
            key_version="test-1",
        )

    def __getattr__(self, name):
        return getattr(self._provider, name)


class _FiledEvidenceEvaluatorBase:
    evaluator_id = "filed-framework-evidence"
    evaluator_version = "1"
    authority_role = FILED_FRAMEWORK_AUTHORITY_ROLE
    authority_credential_id = "filed-framework-evidence-credential"

    def __init__(self, provider: FiledEvidenceProvider) -> None:
        self.provider = provider

    @staticmethod
    def evidence(framework: str, snapshot: dict) -> list[dict]:
        return [
            {
                "evidence_id": (
                    f"{framework}:{snapshot['evaluation_sequence']}"
                ),
                "source": "filed-patent-contract-evidence",
                "digest": canonical_integrity_hash(
                    {
                        "framework": framework,
                        "stage": snapshot["stage"],
                        "sequence": snapshot["evaluation_sequence"],
                    }
                ),
            }
        ]

    def signed(
        self,
        framework: str,
        stage: str,
        snapshot: dict,
        determination: dict,
    ) -> dict:
        return build_hybrid_signed_object(
            {
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "framework": framework,
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_framework_digest": snapshot[
                    "prior_framework_digest"
                ],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": determination,
            },
            provider=self.provider,
            purpose=getattr(
                self,
                "signing_purpose",
                FILED_FRAMEWORK_ATTESTATION_PURPOSE,
            ),
        )


class FiledEvidenceEvaluator(_FiledEvidenceEvaluatorBase):
    evaluator_id = "filed-framework-evidence"
    evaluator_version = "1"
    authority_role = FILED_FRAMEWORK_AUTHORITY_ROLE
    authority_credential_id = "filed-framework-evidence-credential"

    def __init__(self, provider: FiledEvidenceProvider) -> None:
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
                                    f"{primitive}:"
                                    f"{snapshot['evaluation_sequence']}"
                                ),
                                "source": "three-p-filed-framework-evidence",
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

    def evaluate_aj_saaf(self, *, stage: str, snapshot: dict) -> dict:
        return self.signed(
            AJ_SAAF,
            stage,
            snapshot,
            {
                "result": FRAMEWORK_PASS,
                "control_action": "PERMIT",
                "applicable_authorities": [snapshot["resolved_authority"]],
                "winning_authority": snapshot["resolved_authority"],
                "conflicts": [],
                "precedence_resolved": True,
                "escalation_route": None,
                "lawful_override_limits": ["no_override_outside_law"],
                "runtime_recalculation_triggers": list(
                    AJ_SAAF_RECALCULATION_TRIGGERS
                ),
                "evidence_references": self.evidence(AJ_SAAF, snapshot),
            },
        )

    def evaluate_ptodf(self, *, stage: str, snapshot: dict) -> dict:
        return self.signed(
            PTODF,
            stage,
            snapshot,
            {
                "result": FRAMEWORK_PASS,
                "required_procedural_steps": snapshot[
                    "required_procedural_steps"
                ],
                "evidentiary_sufficiency": True,
                "licence_state_action": "MAINTAIN",
                "evidence_references": self.evidence(PTODF, snapshot),
            },
        )

    def evaluate_gala(self, *, stage: str, snapshot: dict) -> dict:
        return self.signed(
            GALA,
            stage,
            snapshot,
            {
                "result": FRAMEWORK_PASS,
                "release_authorized": True,
                "certification_id": "gala-filed-certification",
                "attestation_status": "ATTESTED",
                "revocation_status": "ACTIVE",
                "audit_packet_digest": snapshot["audit_packet_digest"],
                "evidence_references": self.evidence(GALA, snapshot),
            },
        )

    def evaluate_abegf(self, *, stage: str, snapshot: dict) -> dict:
        request = snapshot["autonomy_request"]
        return self.signed(
            ABEGF,
            stage,
            snapshot,
            {
                "result": FRAMEWORK_PASS,
                "autonomy_ceiling": snapshot["autonomy_ceiling"],
                "permitted_decision_domains": [
                    request["decision_domain"]
                ],
                "prohibited_actions": [],
                "maximum_self_directed_scope": request[
                    "self_directed_scope"
                ],
                "self_modification_allowed": False,
                "goal_expansion_allowed": False,
                "escalation_triggers": ["uncertainty_threshold"],
                "suspension_controls": list(ABEGF_SUSPENSION_CONTROLS),
                "cross_system_containment": {
                    "system_chaining_limited": True,
                    "cross_model_delegation_limited": True,
                    "cross_platform_interaction_limited": True,
                    "cross_vendor_interaction_limited": True,
                    "cross_jurisdiction_interaction_limited": True,
                },
                "emergency_rollback_available": True,
                "evidence_references": self.evidence(ABEGF, snapshot),
            },
        )


class ThreePEvidenceEvaluator:
    evaluator_id = "three-p-filed-framework-evidence"
    evaluator_version = "1"
    authority_role = "CONSTITUTIONAL_3P_EVALUATOR"
    authority_credential_id = "three-p-filed-framework-credential"

    def __init__(self, provider: FiledEvidenceProvider) -> None:
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
                                    f"{primitive}:"
                                    f"{snapshot['evaluation_sequence']}"
                                ),
                                "source": "three-p-filed-framework-evidence",
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


class FiledFrameworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = FiledEvidenceProvider()
        self.attestation_trust_context = (
            self.provider.hybrid_verification_context(allow_test_only=True)
        )
        self.owner_pinned_context_digest = (
            self.attestation_trust_context.context_digest
        )
        self.evaluator = FiledEvidenceEvaluator(self.provider)
        self.three_p_evaluator = ThreePEvidenceEvaluator(self.provider)
        self.licence_evaluator = PassingFiledLicenceEvaluator(self.provider)
        self.skg_evaluator = PassingSKGAuthorityEvaluator(self.provider)
        self.lifecycle_evaluator = PassingFiledLifecycleEvaluator(
            self.provider
        )

    def framework_trust(self) -> dict:
        return {
            "attestation_trust_context": self.attestation_trust_context,
            "owner_pinned_context_digest": self.owner_pinned_context_digest,
        }

    def state(self) -> dict:
        request = {
            **filed_licence_request_fields(),
            "action": "review",
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "aj_saaf_operational_context": {
                "geographic_location": "AU",
                "deployment_context": "controlled-local",
                "data_origin": "AU",
                "subject_status": "owner",
                "regulatory_classification": "CLASS_2",
                "cross_border_data_movement": False,
            },
            "abegf_request": {
                "decision_domain": "review",
                "self_directed_scope": "local",
                "self_modification_requested": False,
                "goal_expansion_requested": False,
                "delegation_targets": [],
                "cross_platform_interactions": [],
                "cross_vendor_interactions": [],
                "cross_jurisdiction_interactions": [],
            },
            "payload": {"output": {"fact_verified_ratio": 1.0}},
            "ap_acf_class": "CLASS_2",
            "requested_autonomy_level": 20,
            "autonomy_ceiling": 30,
            "operational_scope": "local",
            "deployment_scope": "licensed-local-scope",
            "license_profile": {
                "allowed_classes": ["CLASS_2"],
                "max_autonomy_level": 30,
            },
        }
        state = build_state(request)
        state["request_fingerprint"] = canonical_integrity_hash(request)
        state.update(
            {
                "resolved_authority": "owner",
                "jurisdiction": "AU",
                "ap_acf_class": "CLASS_2",
                "ap_acf_subclass": "CLASS_2",
                "three_p_core_result": "PASS",
                "three_p_core_digest": "a" * 128,
                "authority_first_result": "ALLOW",
                "procedural_truth_result": "PASS",
                "classification_result": "ALLOW",
                "licensing_result": "ALLOW",
                "governance_result": "ALLOW",
                "domain_result": "pass",
                "aurion15_result": "pass",
                "current_candidate": {
                    "type": "direct",
                    "action": "review",
                    "payload": deepcopy(state["payload"]),
                },
            }
        )
        self.append_chain(state, "aurion_runtime", {"result": "pass"})
        return state

    @staticmethod
    def append_chain(state: dict, stage: str, payload: dict) -> None:
        previous = (
            state["hash_chain"][-1]["hash"]
            if state["hash_chain"]
            else GENESIS_HASH
        )
        entry = build_hash_chain_entry(
            previous_hash=previous,
            stage=stage,
            payload=payload,
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]

    def run_all(self, state: dict) -> dict:
        for framework in FILED_FRAMEWORK_ORDER:
            self.append_chain(
                state,
                f"three_p_core:{FILED_FRAMEWORK_STAGES[framework]}",
                {"result": "PASS"},
            )
            evaluate_filed_framework(
                state,
                framework,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.framework_trust(),
            )
            self.append_chain(
                state,
                FILED_FRAMEWORK_STAGES[framework],
                filed_framework_hash_payload(state),
            )
            self.append_chain(
                state,
                f"three_p_core:{FILED_FRAMEWORK_STAGES[framework]}:post",
                {"result": "PASS"},
            )
        return state

    def prepare_licence(self, state: dict) -> dict:
        for stage in (
            LICENCE_ROOT_BINDING_STAGE,
            LICENCE_VALIDATION_STAGE,
            LICENCE_REVALIDATION_STAGE,
        ):
            append_filed_licence_evaluation(
                state,
                stage=stage,
                evaluator=self.licence_evaluator,
                provider=self.provider,
            )
        return state

    def test_exact_order_is_signed_hash_bound_and_non_executive(self) -> None:
        state = self.run_all(self.state())

        self.assertEqual(
            [record["framework"] for record in state["filed_framework_trace"]],
            list(FILED_FRAMEWORK_ORDER),
        )
        self.assertTrue(
            verify_filed_frameworks(
                state,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.framework_trust(),
            )
        )
        self.assertTrue(
            all(
                record["execution_authority_granted"] is False
                for record in state["filed_framework_trace"]
            )
        )

    def test_stage_cannot_be_skipped_or_reordered(self) -> None:
        state = self.state()
        evaluate_filed_framework(
            state,
            AJ_SAAF,
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            **self.framework_trust(),
        )

        self.assertEqual(state["filed_framework_result"], FRAMEWORK_DENY)
        self.assertEqual(
            state["filed_framework_reason"],
            "FILED_FRAMEWORK_EXECUTION_ORDER_INVALID",
        )
        self.assertEqual(state["licensing_result"], "INVALIDATED")

    def test_aj_saaf_requires_exact_operational_context(self) -> None:
        state = self.state()
        evaluate_filed_framework(
            state,
            PTODF,
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            **self.framework_trust(),
        )
        state["aj_saaf_operational_context"].pop("data_origin")
        evaluate_filed_framework(
            state,
            AJ_SAAF,
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            **self.framework_trust(),
        )

        self.assertEqual(state["filed_framework_result"], FRAMEWORK_DENY)
        self.assertEqual(
            state["filed_framework_reason"],
            "AJ-SAAF_OPERATIONAL_CONTEXT_INVALID",
        )

    def test_ptodf_failure_invalidates_licence_state(self) -> None:
        state = self.state()
        state["procedural_truth_result"] = "FAIL"
        evaluate_filed_framework(
            state,
            PTODF,
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            **self.framework_trust(),
        )

        self.assertEqual(state["filed_framework_result"], FRAMEWORK_DENY)
        self.assertEqual(state["licensing_result"], "INVALIDATED")
        self.assertEqual(
            state["licensing_reason"],
            "ptodf_failure_invalidated_licence_state",
        )

    def test_abegf_enforces_the_lowest_autonomy_ceiling(self) -> None:
        state = self.state()
        state["requested_autonomy_level"] = 31
        self.run_all(state)

        self.assertEqual(
            state["filed_framework_results"][ABEGF],
            FRAMEWORK_DENY,
        )
        self.assertEqual(
            state["filed_framework_reason"],
            "ABEGF_AUTONOMY_CEILING_EXCEEDED",
        )

    def test_gala_attestation_tamper_invalidates_complete_traversal(self) -> None:
        state = self.run_all(self.state())
        state["gala_attestation"]["certification_id"] = "changed"

        self.assertFalse(
            verify_filed_frameworks(
                state,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.framework_trust(),
            )
        )

    def test_post_attestation_autonomy_mutation_invalidates_traversal(self) -> None:
        state = self.run_all(self.state())
        state["requested_autonomy_level"] = 31

        self.assertFalse(
            verify_filed_frameworks(
                state,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.framework_trust(),
            )
        )

    def test_owner_pin_purpose_and_legacy_provider_fail_closed(self) -> None:
        state = self.state()
        evaluate_filed_framework(
            state,
            PTODF,
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            attestation_trust_context=self.attestation_trust_context,
            owner_pinned_context_digest="0" * 128,
        )
        self.assertEqual(
            state["filed_framework_reason"],
            "FILED_FRAMEWORK_OWNER_TRUST_PIN_INVALID",
        )

        wrong_purpose = FiledEvidenceEvaluator(self.provider)
        wrong_purpose.signing_purpose = "SBP_LEX_V2_WRONG_FRAMEWORK_PURPOSE"
        state = self.state()
        evaluate_filed_framework(
            state,
            PTODF,
            evaluator=wrong_purpose,
            attestation_provider=self.provider,
            **self.framework_trust(),
        )
        self.assertEqual(
            state["filed_framework_reason"],
            "PTODF_EVALUATION_ATTESTATION_INVALID",
        )

        class LegacyAdmittedProvider:
            algorithm = "Ed25519"
            framework_attestation_admitted = True

        state = self.state()
        evaluate_filed_framework(
            state,
            PTODF,
            evaluator=self.evaluator,
            attestation_provider=LegacyAdmittedProvider(),
            **self.framework_trust(),
        )
        self.assertEqual(
            state["filed_framework_reason"],
            "FRAMEWORK_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED",
        )
        self.assertFalse(
            verify_filed_frameworks(
                self.run_all(self.state()),
                evaluator=self.evaluator,
                attestation_provider=LegacyAdmittedProvider(),
                **self.framework_trust(),
            )
        )

    def test_execution_gate_rejects_missing_filed_framework_traversal(self) -> None:
        state = self.prepare_licence(self.state())
        with patch(
            "sbp_lex.execution.execution_gate._run_foundational_execution_checks",
            return_value=None,
        ), patch(
            "sbp_lex.execution.execution_gate.verify_authority_provenance",
            return_value=True,
        ), patch(
            "sbp_lex.execution.execution_gate.verify_three_p_core",
            return_value=True,
        ), patch(
            "sbp_lex.execution.execution_gate.verify_skg_authority",
            return_value=True,
        ):
            run_execution_gate(
                state,
                filed_framework_evaluator=self.evaluator,
                filed_framework_attestation_provider=self.provider,
                filed_licence_evaluator=self.licence_evaluator,
                filed_licence_attestation_provider=self.provider,
                filed_licence_attestation_trust_context=(
                    self.attestation_trust_context
                ),
                filed_licence_owner_pinned_context_digest=(
                    self.owner_pinned_context_digest
                ),
                filed_framework_attestation_trust_context=(
                    self.attestation_trust_context
                ),
                filed_framework_owner_pinned_context_digest=(
                    self.owner_pinned_context_digest
                ),
                skg_attestation_provider=self.provider,
                skg_attestation_trust_context=(
                    self.attestation_trust_context
                ),
                skg_owner_pinned_context_digest=(
                    self.owner_pinned_context_digest
                ),
                foundational_request_dependencies=(
                    FoundationalRequestDependencies(
                        provenance_registry_snapshot=None,
                        provenance_trust_context=None,
                        sovereign_identity_evaluator=None,
                        sovereign_identity_attestation_provider=None,
                        authority_boundary_evaluator=None,
                        authority_boundary_attestation_provider=None,
                        impersonation_trust_context=None,
                    )
                ),
            )

        self.assertEqual(state["execution_result"], "HALT")
        self.assertEqual(state["decision"], "DENY")
        self.assertEqual(
            state["execution_reason"],
            "filed_framework_traversal_failure",
        )

    def test_active_pipeline_places_ptodf_early_and_other_three_in_governance(self) -> None:
        from main import run_sbp_lex
        from tests.test_foundational_public_pipeline import _public_inputs
        from tests.test_controlled_local_adapter import (
            ControlledLocalAdapterTests,
        )

        foundation = ControlledLocalAdapterTests(
            "test_real_local_effect_requires_point_of_use_receipt"
        )
        foundation.setUp()
        foundation.configure_authority_provenance_provider(
            skg_provider=self.provider,
            skg_evaluator=self.skg_evaluator,
        )
        request, signals, possession_proof = _public_inputs(foundation)
        hybrid_contexts = PipelineHybridTrustContexts(
            signature=self.attestation_trust_context,
            signature_owner_pin=self.owner_pinned_context_digest,
            three_p=self.attestation_trust_context,
            three_p_owner_pin=self.owner_pinned_context_digest,
            skg=self.attestation_trust_context,
            skg_owner_pin=self.owner_pinned_context_digest,
            filed_framework=self.attestation_trust_context,
            filed_framework_owner_pin=self.owner_pinned_context_digest,
            filed_licence=self.attestation_trust_context,
            filed_licence_owner_pin=self.owner_pinned_context_digest,
            filed_lifecycle=self.attestation_trust_context,
            filed_lifecycle_owner_pin=self.owner_pinned_context_digest,
            filed_governance_integrity=foundation.authority_context,
            filed_governance_integrity_owner_pin=(
                foundation.authority_owner_pin
            ),
        )

        def pass_aurion(state: dict) -> dict:
            state["current_candidate"] = {
                "type": "direct",
                "action": state["action"],
                "payload": deepcopy(state["payload"]),
            }
            state["candidate_attempt_count"] = 1
            state["aurion15_result"] = "pass"
            return state

        try:
            with patch(
                "sbp_lex.pipeline.runner.run_aurion15",
                side_effect=pass_aurion,
            ):
                result = run_sbp_lex(
                    request,
                    signals,
                    signature_provider=self.provider,
                    three_p_evaluator=self.three_p_evaluator,
                    three_p_attestation_provider=self.provider,
                    skg_evaluator=self.skg_evaluator,
                    skg_attestation_provider=self.provider,
                    filed_framework_evaluator=self.evaluator,
                    filed_framework_attestation_provider=self.provider,
                    filed_lifecycle_evaluator=self.lifecycle_evaluator,
                    filed_lifecycle_attestation_provider=self.provider,
                    filed_licence_evaluator=self.licence_evaluator,
                    filed_licence_attestation_provider=self.provider,
                    filed_governance_integrity_evaluator=(
                        foundation.governance_integrity_evaluator
                    ),
                    filed_governance_integrity_attestation_provider=(
                        foundation.authority
                    ),
                    filed_governance_integrity_revocation_binding=(
                        governance_integrity_revocation_binding(
                            status="ACTIVE",
                            sequence=1,
                        )
                    ),
                    application_integrity_bundle=(
                        foundation.application_bundle
                    ),
                    foundational_request_dependencies=(
                        foundation.foundational_dependencies
                    ),
                    possession_proof=possession_proof,
                    hybrid_trust_contexts=hybrid_contexts,
                )
        finally:
            foundation.tearDown()

        self.assertEqual(
            [
                record["framework"]
                for record in result["filed_framework_trace"]
            ],
            list(FILED_FRAMEWORK_ORDER),
            msg={
                "decision": result.get("decision"),
                "execution_reason": result.get("execution_reason"),
                "error": result.get("error"),
                "aurion15_result": result.get("aurion15_result"),
                "domain_result": result.get("domain_result"),
                "filed_framework_reason": result.get(
                    "filed_framework_reason"
                ),
                "three_p_core_reason": result.get("three_p_core_reason"),
                "skg_authority_reason": result.get("skg_authority_reason"),
            },
        )
        stage_indexes = {
            stage: next(
                index
                for index, entry in enumerate(result["hash_chain"])
                if entry["stage"] == stage
            )
            for stage in (
                "state_construction",
                "filed_licence:root_binding",
                f"{SKG_HASH_STAGE_PREFIX}constitutional_authority_substrate",
                "procedural_truth",
                FILED_FRAMEWORK_STAGES[PTODF],
                "classification",
                "licensing",
                FILED_FRAMEWORK_STAGES[AJ_SAAF],
                "governance:determination",
                FILED_FRAMEWORK_STAGES[GALA],
                FILED_FRAMEWORK_STAGES[ABEGF],
                *[
                    FILED_LIFECYCLE_STAGES[engine]
                    for engine in FILED_LIFECYCLE_ORDER
                ],
                *[
                    FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
                    for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
                ],
                "governance",
                "domain_wrap",
                "aurion_runtime:1",
            )
        }
        execution_prep_index = next(
            index
            for index, entry in enumerate(result["hash_chain"])
            if entry["stage"] == "three_p_core:execution_prep"
        )
        self.assertLess(
            stage_indexes["state_construction"],
            stage_indexes["filed_licence:root_binding"],
        )
        self.assertLess(
            stage_indexes["filed_licence:root_binding"],
            stage_indexes[
                f"{SKG_HASH_STAGE_PREFIX}"
                "constitutional_authority_substrate"
            ],
        )
        self.assertLess(
            stage_indexes[
                f"{SKG_HASH_STAGE_PREFIX}"
                "constitutional_authority_substrate"
            ],
            stage_indexes["procedural_truth"],
        )
        self.assertLess(
            stage_indexes["procedural_truth"],
            stage_indexes[FILED_FRAMEWORK_STAGES[PTODF]],
        )
        self.assertLess(
            stage_indexes[FILED_FRAMEWORK_STAGES[PTODF]],
            stage_indexes["classification"],
        )
        governance_path = [
            stage_indexes["licensing"],
            stage_indexes[FILED_FRAMEWORK_STAGES[AJ_SAAF]],
            stage_indexes["governance:determination"],
            stage_indexes[FILED_FRAMEWORK_STAGES[GALA]],
            stage_indexes[FILED_FRAMEWORK_STAGES[ABEGF]],
            *[
                stage_indexes[FILED_LIFECYCLE_STAGES[engine]]
                for engine in FILED_LIFECYCLE_ORDER
            ],
            *[
                stage_indexes[
                    FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
                ]
                for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
            ],
            stage_indexes["governance"],
            stage_indexes["domain_wrap"],
            stage_indexes["aurion_runtime:1"],
            execution_prep_index,
        ]
        self.assertEqual(governance_path, sorted(governance_path))

        self.lifecycle_evaluator.result = LIFECYCLE_DENY
        denied_foundation = ControlledLocalAdapterTests(
            "test_real_local_effect_requires_point_of_use_receipt"
        )
        denied_foundation.setUp()
        denied_foundation.configure_authority_provenance_provider(
            skg_provider=self.provider,
            skg_evaluator=self.skg_evaluator,
        )
        denied_request, denied_signals, denied_proof = _public_inputs(
            denied_foundation
        )
        try:
            denied = run_sbp_lex(
                denied_request,
                denied_signals,
                signature_provider=self.provider,
                three_p_evaluator=self.three_p_evaluator,
                three_p_attestation_provider=self.provider,
                skg_evaluator=self.skg_evaluator,
                skg_attestation_provider=self.provider,
                filed_framework_evaluator=self.evaluator,
                filed_framework_attestation_provider=self.provider,
                filed_lifecycle_evaluator=self.lifecycle_evaluator,
                filed_lifecycle_attestation_provider=self.provider,
                filed_licence_evaluator=self.licence_evaluator,
                filed_licence_attestation_provider=self.provider,
                application_integrity_bundle=(
                    denied_foundation.application_bundle
                ),
                foundational_request_dependencies=(
                    denied_foundation.foundational_dependencies
                ),
                possession_proof=denied_proof,
                hybrid_trust_contexts=hybrid_contexts,
            )
        finally:
            denied_foundation.tearDown()
        self.assertEqual(denied["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertEqual(denied["governance_result"], "DENY")
        self.assertEqual(denied["decision"], "DENY")
        self.assertEqual(denied["execution_result"], "HALT")
        self.assertNotIn(
            FILED_LIFECYCLE_ENGINE_IDS[
                FILED_LIFECYCLE_ORDER[0]
            ].lower(),
            denied["tokens"],
        )
        self.assertEqual(denied["audit_record"]["decision"], "DENY")
        self.assertEqual(
            denied["audit_record"]["governance_result"],
            "DENY",
        )
        self.assertTrue(
            verify_audit_record(
                denied,
                skg_evaluator=self.skg_evaluator,
                skg_attestation_provider=self.provider,
                skg_attestation_trust_context=(
                    self.attestation_trust_context
                ),
                skg_owner_pinned_context_digest=(
                    self.owner_pinned_context_digest
                ),
                filed_lifecycle_evaluator=self.lifecycle_evaluator,
                filed_lifecycle_attestation_provider=self.provider,
                filed_lifecycle_attestation_trust_context=(
                    self.attestation_trust_context
                ),
                filed_lifecycle_owner_pinned_context_digest=(
                    self.owner_pinned_context_digest
                ),
            )
        )
        self.assertTrue(verify_audit_ledger(denied))


if __name__ == "__main__":
    unittest.main()
