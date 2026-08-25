"""Completion lock over stages 1-6 (stage 7)."""

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

PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_CAPSTONE_PAYLOAD_V1"
PREFIX_STAGES = STAGE_ORDER[:6]


def build_capstone(
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
        expected_stages=PREFIX_STAGES,
    )
    all_prior_pass = all(item.get("payload", {}).get("status") == PASS for item in artifacts)
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if chain["status"] == PASS and all_prior_pass else FAIL,
        "completed_stage_order": list(PREFIX_STAGES),
        "bound_artifacts": [
            {
                "stage": item.get("stage"),
                "artifact_digest": item.get("artifact_digest"),
                "receipt_id": item.get("receipt_id"),
                "payload_digest": item.get("payload_digest"),
            }
            for item in artifacts
        ],
        "bound_chain_head_digest": chain["head_digest"],
        "bound_time_head_digest": chain["time_head_digest"],
        "deployment_limits": dict(DEPLOYMENT_LIMITS),
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="capstone",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(artifacts[-1].get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_capstone(
    capstone: Any,
    *,
    prior_artifacts: Sequence[Mapping[str, Any]],
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
) -> dict[str, Any]:
    artifacts = [dict(item) for item in prior_artifacts]
    chain = validate_artifact_chain(
        artifacts,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_stages=PREFIX_STAGES,
    )
    prior_time = artifacts[-1].get("time_evidence_digest") if artifacts else "GENESIS"
    if type(prior_time) is not str:
        prior_time = ""
    base = validate_signed_artifact(
        capstone,
        expected_stage="capstone",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=chain["head_digest"],
        expected_time_sequence=7,
        expected_prior_time_digest=prior_time,
    )
    failures = list(chain["validation_failures"]) + list(base["validation_failures"])
    try:
        payload = capstone["payload"]
        expected_bindings = [
            {
                "stage": item.get("stage"),
                "artifact_digest": item.get("artifact_digest"),
                "receipt_id": item.get("receipt_id"),
                "payload_digest": item.get("payload_digest"),
            }
            for item in artifacts
        ]
        if (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("completed_stage_order") != list(PREFIX_STAGES)
            or payload.get("bound_artifacts") != expected_bindings
            or payload.get("bound_chain_head_digest") != chain["head_digest"]
            or payload.get("bound_time_head_digest") != chain["time_head_digest"]
            or payload.get("deployment_limits") != DEPLOYMENT_LIMITS
            or payload.get("runtime_attachment") != "NONE"
        ):
            failures.append("capstone_not_admissible")
    except (KeyError, TypeError, ValueError):
        failures.append("capstone_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


build_local_trust_capstone = build_capstone
validate_local_trust_capstone = validate_capstone

__all__ = ["build_capstone", "build_local_trust_capstone", "validate_capstone", "validate_local_trust_capstone"]
