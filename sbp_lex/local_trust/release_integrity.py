"""Self-contained offline-verifiable release-integrity bundle (stage 8)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .artifact import (
    build_signed_artifact,
    validate_artifact_chain,
    validate_signed_artifact,
)
from .constants import FAIL, PASS, STAGE_ORDER
from .evidence_chain import compare_evidence_to_current_files
from .signing import HybridSigningContext, HybridVerificationContext

PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_RELEASE_BUNDLE_PAYLOAD_V1"
PREFIX_STAGES = STAGE_ORDER[:7]


def _index(artifacts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "stage": item.get("stage"),
            "artifact_digest": item.get("artifact_digest"),
            "payload_digest": item.get("payload_digest"),
            "receipt_id": item.get("receipt_id"),
            "replay_id": item.get("replay_id"),
        }
        for item in artifacts
    ]


def build_release_integrity_bundle(
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
        "verification_context_digest": trust.context_digest,
        "artifact_stage_order": list(PREFIX_STAGES),
        "artifact_index": _index(artifacts),
        "embedded_artifacts": artifacts,
        "chain_head_digest": chain["head_digest"],
        "time_head_digest": chain["time_head_digest"],
        "verification_instruction": "Verify with independently obtained owner-pinned public trust context.",
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="release_integrity",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(artifacts[-1].get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_release_integrity_bundle(
    release: Any,
    repository_root: str | Path,
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        payload = release["payload"]
        artifacts = payload.get("embedded_artifacts")
    except (KeyError, TypeError):
        payload = {}
        artifacts = []
        failures.append("release_bundle_malformed")
    chain = validate_artifact_chain(
        artifacts,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_stages=PREFIX_STAGES,
    )
    failures.extend(chain["validation_failures"])
    prior_time = artifacts[-1].get("time_evidence_digest") if artifacts and type(artifacts[-1]) is dict else "GENESIS"
    if type(prior_time) is not str:
        prior_time = ""
    base = validate_signed_artifact(
        release,
        expected_stage="release_integrity",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=chain["head_digest"],
        expected_time_sequence=8,
        expected_prior_time_digest=prior_time,
    )
    failures.extend(base["validation_failures"])
    try:
        manifest_snapshot = artifacts[0]["payload"]["evidence_inventory"]["files"]
        current = compare_evidence_to_current_files(repository_root, manifest_snapshot)
        if (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("verification_context_digest") != owner_pinned_context_digest
            or payload.get("artifact_stage_order") != list(PREFIX_STAGES)
            or payload.get("artifact_index") != _index(artifacts)
            or payload.get("chain_head_digest") != chain["head_digest"]
            or payload.get("time_head_digest") != chain["time_head_digest"]
            or payload.get("runtime_attachment") != "NONE"
            or current != {"missing_evidence": [], "changed_evidence": []}
        ):
            failures.append("release_bundle_not_current_or_admissible")
    except (KeyError, TypeError, ValueError, IndexError):
        failures.append("release_bundle_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


build_release_integrity = build_release_integrity_bundle
validate_release_integrity = validate_release_integrity_bundle

__all__ = [
    "build_release_integrity", "build_release_integrity_bundle",
    "validate_release_integrity", "validate_release_integrity_bundle",
]
