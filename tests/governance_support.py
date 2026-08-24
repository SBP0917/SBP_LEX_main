from __future__ import annotations

from copy import deepcopy
from typing import Any

from sbp_lex.governance.filed_lifecycle import (
    AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION,
    CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION,
    FILED_LIFECYCLE_AUTHORITY_ROLE,
    FILED_LIFECYCLE_ATTESTATION_PURPOSE,
    FILED_LIFECYCLE_ENGINE_IDS,
    FILED_LIFECYCLE_ORDER_AUTHORITY,
    FILED_LIFECYCLE_SCHEMA_STATUS,
    LIFECYCLE_PASS,
    STRUCTURED_POST_AI_ERA_CONTINUITY,
)
from sbp_lex.governance.filed_governance_integrity import (
    AUTHORITY_ANOMALY_DETECTION,
    AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE,
    BLACK_SWAN_DETECTION_ARCHITECTURE,
    CRISIS_PROPAGATION_MODELLING,
    FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE,
    FILED_GOVERNANCE_INTEGRITY_ATTESTATION_PURPOSE,
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS,
    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
    GOVERNANCE_INTEGRITY_PASS,
    STRATEGIC_INSTABILITY_EARLY_WARNING,
)
from sbp_lex.governance.skg_authority import (
    SKG_AUTHORITY_ROLE,
    SKG_AUTHORITY_ATTESTATION_PURPOSE,
    SKG_CONTENT_CLASSES,
    SKG_PASS,
    SKG_SATISFIED,
    SKG_SCHEMA_STATUS,
    SKG_V2_CONTRACT_ID,
)
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.security.signature_provider import build_signed_object


class PassingSKGAuthorityEvaluator:
    evaluator_id = "skg-v2-authority-evidence"
    evaluator_version = "1"
    authority_role = SKG_AUTHORITY_ROLE
    authority_credential_id = "skg-v2-authority-evidence-credential"

    def __init__(self, provider: Any) -> None:
        self.provider = provider

    def evaluate_skg_authority(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        return build_signed_object(
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
                "determination": {
                    "result": SKG_PASS,
                    "content_class_results": {
                        content_class: SKG_SATISFIED
                        for content_class in SKG_CONTENT_CLASSES
                    },
                    "evidence_references": [
                        {
                            "content_class": content_class,
                            "evidence_id": f"skg-authority:{index}",
                            "source": "admitted-skg-authority-evidence",
                            "digest": canonical_integrity_hash(
                                {
                                    "content_class": content_class,
                                    "stage": stage,
                                    "sequence": snapshot[
                                        "evaluation_sequence"
                                    ],
                                }
                            ),
                        }
                        for index, content_class in enumerate(
                            SKG_CONTENT_CLASSES,
                            start=1,
                        )
                    ],
                    "authority_granted": False,
                    "execution_authority_granted": False,
                    "downstream_override_permitted": False,
                },
            },
            provider=self.provider,
            purpose=SKG_AUTHORITY_ATTESTATION_PURPOSE,
        )


class PassingFiledLifecycleEvaluator:
    evaluator_id = "filed-lifecycle-evidence"
    evaluator_version = "1"
    authority_role = FILED_LIFECYCLE_AUTHORITY_ROLE
    authority_credential_id = "filed-lifecycle-evidence-credential"

    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.result = LIFECYCLE_PASS

    def _evaluate(
        self,
        lifecycle_engine: str,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        return build_signed_object(
            {
                "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "lifecycle_engine": lifecycle_engine,
                "lifecycle_engine_id": FILED_LIFECYCLE_ENGINE_IDS[
                    lifecycle_engine
                ],
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "implementation_order_authority": (
                    FILED_LIFECYCLE_ORDER_AUTHORITY
                ),
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_lifecycle_digest": snapshot[
                    "prior_lifecycle_digest"
                ],
                "three_p_core_digest": snapshot["three_p_core_digest"],
                "three_p_trace_hash": snapshot["three_p_trace_hash"],
                "skg_digest": snapshot["skg_digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": {
                    "result": self.result,
                    "transition_beyond_current_ai_paradigms_modelled": True,
                    "full_lifecycle_governance_envelope_secured": True,
                    "lawful_authority_continuity_preserved": True,
                    "violent_or_coercive_interaction_prohibited": True,
                    "bound_to_three_p": True,
                    "bound_to_skg": True,
                    "authority_granted": False,
                    "execution_authority_granted": False,
                    "licence_granted": False,
                    "governance_superseded": False,
                    "evidence_references": [
                        {
                            "evidence_id": (
                                f"{FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]}:"
                                f"{snapshot['evaluation_sequence']}"
                            ),
                            "source": "admitted-lifecycle-evidence",
                            "digest": canonical_integrity_hash(
                                {
                                    "lifecycle_engine": lifecycle_engine,
                                    "stage": stage,
                                    "sequence": snapshot[
                                        "evaluation_sequence"
                                    ],
                                }
                            ),
                        }
                    ],
                },
            },
            provider=self.provider,
            purpose=FILED_LIFECYCLE_ATTESTATION_PURPOSE,
        )

    def evaluate_ai_obsolescence_lifecycle_supersession(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        return self._evaluate(
            AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_civilisational_successor_intelligence_transition(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        return self._evaluate(
            CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_structured_post_ai_era_continuity(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        return self._evaluate(
            STRUCTURED_POST_AI_ERA_CONTINUITY,
            stage=stage,
            snapshot=snapshot,
        )


class PassingFiledGovernanceIntegrityEvaluator:
    evaluator_id = "filed-governance-integrity-evidence"
    evaluator_version = "1"
    authority_role = FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE
    authority_credential_id = "filed-governance-integrity-credential"

    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.result = GOVERNANCE_INTEGRITY_PASS

    def _evaluate(
        self,
        governance_function: str,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        function_id = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ]
        revocation = snapshot["revocation_binding"]
        return build_signed_object(
            {
                "schema_status": FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
                "result_vocabulary_authority": (
                    FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
                ),
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "governance_integrity_function": governance_function,
                "function_id": function_id,
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "implementation_order_authority": (
                    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
                ),
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_governance_integrity_digest": snapshot[
                    "prior_governance_integrity_digest"
                ],
                "three_p_core_digest": snapshot["three_p_core_digest"],
                "three_p_trace_hash": snapshot["three_p_trace_hash"],
                "skg_digest": snapshot["skg_digest"],
                "revocation_status": revocation["status"],
                "revocation_sequence": revocation["sequence"],
                "revocation_digest": revocation["digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": {
                    "result": self.result,
                    "evidence_references": [
                        {
                            "evidence_id": (
                                f"{function_id}:"
                                f"{snapshot['evaluation_sequence']}"
                            ),
                            "source": (
                                "admitted-governance-integrity-evidence"
                            ),
                            "digest": canonical_integrity_hash(
                                {
                                    "governance_function": (
                                        governance_function
                                    ),
                                    "stage": stage,
                                    "sequence": snapshot[
                                        "evaluation_sequence"
                                    ],
                                }
                            ),
                        }
                    ],
                    "authority_granted": False,
                    "licence_granted": False,
                    "execution_authority_granted": False,
                    "effect_granted": False,
                    "bypass_permitted": False,
                },
            },
            provider=self.provider,
            purpose=FILED_GOVERNANCE_INTEGRITY_ATTESTATION_PURPOSE,
        )

    def evaluate_black_swan_detection_architecture(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        return self._evaluate(
            BLACK_SWAN_DETECTION_ARCHITECTURE,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_crisis_propagation_modelling(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        return self._evaluate(
            CRISIS_PROPAGATION_MODELLING,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_authority_anomaly_detection(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        return self._evaluate(
            AUTHORITY_ANOMALY_DETECTION,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_strategic_instability_early_warning(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        return self._evaluate(
            STRATEGIC_INSTABILITY_EARLY_WARNING,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_autonomous_containment_revocation_cascade(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]:
        return self._evaluate(
            AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE,
            stage=stage,
            snapshot=snapshot,
        )
