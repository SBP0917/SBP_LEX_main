"""Claims-to-evidence index and explicit limits dossier (stage 10)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .artifact import (
    build_signed_artifact,
    validate_artifact_chain,
    validate_signed_artifact,
)
from .constants import DEPLOYMENT_LIMITS, FAIL, PASS, STAGE_ORDER
from .signing import HybridSigningContext, HybridVerificationContext

PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_CLAIMS_EVIDENCE_DOSSIER_PAYLOAD_V1"
CLAIM_ORDER = (
    "canonical_sha512_integrity",
    "required_hybrid_signature",
    "repository_provenance",
    "execution_command_evidence",
    "current_file_integrity",
    "regression_tamper_rejection",
    "constitutional_boundary",
    "toolchain_dependency_binding",
    "capstone_completion_lock",
    "offline_release_verification",
    "adversarial_negative_harness",
)


def _claims(artifacts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    evidence_stages = (
        "manifest", "execution_envelope", "evidence_chain",
        "regression_matrix", "constitutional_gates", "toolchain_guard",
        "capstone", "release_integrity", "adversarial_harness",
    )
    mapping = {
        "canonical_sha512_integrity": evidence_stages,
        "required_hybrid_signature": evidence_stages,
        "repository_provenance": ("manifest",),
        "execution_command_evidence": ("execution_envelope",),
        "current_file_integrity": ("evidence_chain", "release_integrity"),
        "regression_tamper_rejection": ("regression_matrix",),
        "constitutional_boundary": ("constitutional_gates",),
        "toolchain_dependency_binding": ("toolchain_guard",),
        "capstone_completion_lock": ("capstone",),
        "offline_release_verification": ("release_integrity",),
        "adversarial_negative_harness": ("adversarial_harness",),
    }
    by_stage = {item.get("stage"): item.get("artifact_digest") for item in artifacts}
    return [
        {
            "claim_id": claim_id,
            "status": "READY_FOR_REVIEW",
            "evidence": [
                {"stage": stage, "artifact_digest": by_stage.get(stage)}
                for stage in mapping[claim_id]
            ],
            "independent_validation": "NOT_PERFORMED",
        }
        for claim_id in CLAIM_ORDER
    ]


def build_claims_evidence_dossier(
    *,
    prior_artifacts: Sequence[Mapping[str, Any]],
    signer: HybridSigningContext,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    time_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    artifacts = [dict(item) for item in prior_artifacts]
    trust = signer.verification_context(allow_test_only=signer.signer_class == "TEST_ONLY")
    chain = validate_artifact_chain(
        artifacts,
        trust_context=trust,
        owner_pinned_context_digest=trust.context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_stages=STAGE_ORDER[:9],
    )
    all_prior_pass = all(item.get("payload", {}).get("status") == PASS for item in artifacts)
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if chain["status"] == PASS and all_prior_pass else FAIL,
        "bound_stage_order": list(STAGE_ORDER[:9]),
        "bound_stage_digests": [item.get("artifact_digest") for item in artifacts],
        "claim_order": list(CLAIM_ORDER),
        "claims": _claims(artifacts),
        "unproven_requirements": dict(DEPLOYMENT_LIMITS),
        "production_readiness_claimed": False,
        "independent_validation_claimed": False,
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="university_dossier",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(artifacts[-1].get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_claims_evidence_dossier(
    dossier: Any,
    *,
    prior_artifacts: Sequence[Mapping[str, Any]],
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
) -> dict[str, Any]:
    artifacts = [dict(item) for item in prior_artifacts]
    prior_time = artifacts[-1].get("time_evidence_digest")
    if type(prior_time) is not str:
        prior_time = ""
    chain = validate_artifact_chain(
        artifacts,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_stages=STAGE_ORDER[:9],
    )
    base = validate_signed_artifact(
        dossier,
        expected_stage="university_dossier",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=chain["head_digest"],
        expected_time_sequence=10,
        expected_prior_time_digest=prior_time,
    )
    failures = list(chain["validation_failures"]) + list(base["validation_failures"])
    try:
        payload = dossier["payload"]
        claims = payload.get("claims")
        if (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("bound_stage_order") != list(STAGE_ORDER[:9])
            or payload.get("bound_stage_digests") != [item.get("artifact_digest") for item in artifacts]
            or payload.get("claim_order") != list(CLAIM_ORDER)
            or claims != _claims(artifacts)
            or payload.get("unproven_requirements") != DEPLOYMENT_LIMITS
            or payload.get("production_readiness_claimed") is not False
            or payload.get("independent_validation_claimed") is not False
            or payload.get("runtime_attachment") != "NONE"
        ):
            failures.append("dossier_not_admissible")
    except (KeyError, TypeError, ValueError):
        failures.append("dossier_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


build_dossier = build_claims_evidence_dossier
validate_dossier = validate_claims_evidence_dossier

__all__ = [
    "CLAIM_ORDER", "build_claims_evidence_dossier", "build_dossier",
    "validate_claims_evidence_dossier", "validate_dossier",
]
