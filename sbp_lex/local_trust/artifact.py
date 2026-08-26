"""Exact signed artifact, trusted-time, chronology, and replay contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .constants import (
    ARTIFACT_SCHEMA,
    ARTIFACT_SIGNING_PURPOSE,
    CLOCK_SIGNING_PURPOSE,
    CONTRACT_VERSION,
    DEPLOYMENT_LIMITS,
    DETACHED_BOUNDARY,
    GENESIS,
    NO_AUTHORITY,
    STAGE_SCHEMAS,
    TEST_ONLY,
    TIME_EVIDENCE_SCHEMA,
    stage_sequence,
)
from .digests import digest, digest_equal, is_sha512
from .signing import (
    HybridSigningContext,
    HybridVerificationContext,
    sign_hybrid,
    verify_hybrid,
)


class LocalTrustArtifactError(ValueError):
    pass


_TIME_UNSIGNED_FIELDS = frozenset({
    "schema_id",
    "contract_version",
    "context_id",
    "time_sequence",
    "prior_time_digest",
    "observed_at_ms",
    "source_class",
    "status",
    "no_authority",
})
_TIME_FIELDS = _TIME_UNSIGNED_FIELDS | frozenset(
    {"signatures", "time_evidence_digest"}
)

_UNSIGNED_FIELDS = frozenset({
    "schema_id",
    "contract_version",
    "stage_schema",
    "stage",
    "stage_sequence",
    "prior_artifact_digest",
    "time_evidence",
    "time_evidence_digest",
    "payload",
    "payload_digest",
    "replay_id",
    "receipt_id",
    "no_authority",
    "detached_boundary",
    "deployment_limits",
})
_ARTIFACT_FIELDS = _UNSIGNED_FIELDS | frozenset(
    {"signatures", "artifact_digest"}
)


def build_trusted_time_evidence(
    *,
    signer: HybridSigningContext,
    observed_at_ms: int,
    time_sequence: int,
    prior_time_digest: str = GENESIS,
    source_class: str | None = None,
) -> dict[str, Any]:
    if signer.purpose != CLOCK_SIGNING_PURPOSE:
        raise LocalTrustArtifactError("trusted_time_signer_purpose_invalid")
    if type(observed_at_ms) is not int or observed_at_ms < 0:
        raise LocalTrustArtifactError("trusted_time_invalid")
    if type(time_sequence) is not int or time_sequence <= 0:
        raise LocalTrustArtifactError("trusted_time_sequence_invalid")
    if prior_time_digest != GENESIS and not is_sha512(prior_time_digest):
        raise LocalTrustArtifactError("trusted_time_prior_digest_invalid")
    if (time_sequence == 1) != (prior_time_digest == GENESIS):
        raise LocalTrustArtifactError("trusted_time_chronology_invalid")
    effective_source = source_class or (
        "TEST_ONLY_MONOTONIC_CLOCK"
        if signer.signer_class == TEST_ONLY
        else "ADMITTED_EXTERNAL_MONOTONIC_CLOCK"
    )
    unsigned = {
        "schema_id": TIME_EVIDENCE_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "context_id": signer.context_id,
        "time_sequence": time_sequence,
        "prior_time_digest": prior_time_digest,
        "observed_at_ms": observed_at_ms,
        "source_class": effective_source,
        "status": "CURRENT",
        "no_authority": dict(NO_AUTHORITY),
    }
    signatures = sign_hybrid(unsigned, signer)
    result = {**unsigned, "signatures": signatures}
    result["time_evidence_digest"] = digest(result)
    return result


def verify_trusted_time_evidence(
    value: Any,
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
    expected_time_digest: str | None = None,
) -> bool:
    try:
        if type(value) is not dict or set(value) != _TIME_FIELDS:
            return False
        unsigned = {key: value[key] for key in _TIME_UNSIGNED_FIELDS}
        if (
            value.get("schema_id") != TIME_EVIDENCE_SCHEMA
            or value.get("contract_version") != CONTRACT_VERSION
            or value.get("context_id") != trust_context.context_id
            or value.get("time_sequence") != expected_time_sequence
            or value.get("prior_time_digest") != expected_prior_time_digest
            or type(value.get("observed_at_ms")) is not int
            or value["observed_at_ms"] < 0
            or value.get("source_class") != (
                "TEST_ONLY_MONOTONIC_CLOCK"
                if trust_context.signer_class == TEST_ONLY
                else "ADMITTED_EXTERNAL_MONOTONIC_CLOCK"
            )
            or value.get("status") != "CURRENT"
            or value.get("no_authority") != NO_AUTHORITY
            or not is_sha512(value.get("time_evidence_digest"))
            or not verify_hybrid(
                unsigned,
                value.get("signatures"),
                trust_context=trust_context,
                owner_pinned_context_digest=owner_pinned_context_digest,
            )
        ):
            return False
        expected = digest({**unsigned, "signatures": value["signatures"]})
        if not digest_equal(expected, value["time_evidence_digest"]):
            return False
        return expected_time_digest is None or digest_equal(expected, expected_time_digest)
    except (KeyError, TypeError, ValueError):
        return False


def build_signed_artifact(
    *,
    stage: str,
    payload: Mapping[str, Any],
    signer: HybridSigningContext,
    prior_artifact_digest: str,
    time_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    if signer.purpose != ARTIFACT_SIGNING_PURPOSE:
        raise LocalTrustArtifactError("artifact_signer_purpose_invalid")
    if stage not in STAGE_SCHEMAS:
        raise LocalTrustArtifactError("stage_unknown")
    sequence = stage_sequence(stage)
    if prior_artifact_digest != GENESIS and not is_sha512(prior_artifact_digest):
        raise LocalTrustArtifactError("prior_artifact_digest_invalid")
    if (sequence == 1) != (prior_artifact_digest == GENESIS):
        raise LocalTrustArtifactError("artifact_chronology_invalid")
    if type(payload) is not dict or type(time_evidence) is not dict:
        raise LocalTrustArtifactError("artifact_payload_invalid")
    time_digest = time_evidence.get("time_evidence_digest")
    if not is_sha512(time_digest):
        raise LocalTrustArtifactError("artifact_time_evidence_invalid")
    payload_digest = digest(payload)
    replay_id = digest(
        {
            "contract_version": CONTRACT_VERSION,
            "context_id": signer.context_id,
            "stage": stage,
            "stage_sequence": sequence,
            "prior_artifact_digest": prior_artifact_digest,
            "time_evidence_digest": time_digest,
            "payload_digest": payload_digest,
        }
    )
    receipt_id = digest(
        {
            "contract_version": CONTRACT_VERSION,
            "stage": stage,
            "stage_sequence": sequence,
            "replay_id": replay_id,
        }
    )
    unsigned = {
        "schema_id": ARTIFACT_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "stage_schema": STAGE_SCHEMAS[stage],
        "stage": stage,
        "stage_sequence": sequence,
        "prior_artifact_digest": prior_artifact_digest,
        "time_evidence": dict(time_evidence),
        "time_evidence_digest": time_digest,
        "payload": dict(payload),
        "payload_digest": payload_digest,
        "replay_id": replay_id,
        "receipt_id": receipt_id,
        "no_authority": dict(NO_AUTHORITY),
        "detached_boundary": dict(DETACHED_BOUNDARY),
        "deployment_limits": dict(DEPLOYMENT_LIMITS),
    }
    signatures = sign_hybrid(unsigned, signer)
    result = {**unsigned, "signatures": signatures}
    result["artifact_digest"] = digest(result)
    return result


def validate_signed_artifact(
    value: Any,
    *,
    expected_stage: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_prior_artifact_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
    expected_time_digest: str | None = None,
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        if type(value) is not dict or set(value) != _ARTIFACT_FIELDS:
            raise LocalTrustArtifactError("artifact_shape_invalid")
        unsigned = {key: value[key] for key in _UNSIGNED_FIELDS}
        if expected_stage not in STAGE_SCHEMAS:
            failures.append("stage_unknown")
        elif (
            value.get("schema_id") != ARTIFACT_SCHEMA
            or value.get("contract_version") != CONTRACT_VERSION
            or value.get("stage_schema") != STAGE_SCHEMAS[expected_stage]
            or value.get("stage") != expected_stage
            or value.get("stage_sequence") != stage_sequence(expected_stage)
        ):
            failures.append("stage_contract_mismatch")
        if value.get("prior_artifact_digest") != expected_prior_artifact_digest:
            failures.append("artifact_predecessor_mismatch")
        if value.get("no_authority") != NO_AUTHORITY:
            failures.append("authority_boundary_mismatch")
        if value.get("detached_boundary") != DETACHED_BOUNDARY:
            failures.append("detached_boundary_mismatch")
        if value.get("deployment_limits") != DEPLOYMENT_LIMITS:
            failures.append("deployment_limit_mismatch")
        payload = value.get("payload")
        if type(payload) is not dict or not digest_equal(value.get("payload_digest"), digest(payload)):
            failures.append("payload_digest_mismatch")
        embedded_time = value.get("time_evidence")
        if type(embedded_time) is not dict:
            failures.append("time_evidence_shape_invalid")
        elif value.get("time_evidence_digest") != embedded_time.get("time_evidence_digest"):
            failures.append("time_evidence_binding_mismatch")
        elif not verify_trusted_time_evidence(
            value["time_evidence"],
            trust_context=clock_trust_context,
            owner_pinned_context_digest=owner_pinned_clock_context_digest,
            expected_time_sequence=expected_time_sequence,
            expected_prior_time_digest=expected_prior_time_digest,
            expected_time_digest=expected_time_digest,
        ):
            failures.append("trusted_time_evidence_invalid")
        expected_replay = digest(
            {
                "contract_version": CONTRACT_VERSION,
                "context_id": trust_context.context_id,
                "stage": expected_stage,
                "stage_sequence": stage_sequence(expected_stage),
                "prior_artifact_digest": expected_prior_artifact_digest,
                "time_evidence_digest": value.get("time_evidence_digest"),
                "payload_digest": value.get("payload_digest"),
            }
        )
        if not digest_equal(value.get("replay_id"), expected_replay):
            failures.append("replay_id_mismatch")
        expected_receipt = digest(
            {
                "contract_version": CONTRACT_VERSION,
                "stage": expected_stage,
                "stage_sequence": stage_sequence(expected_stage),
                "replay_id": expected_replay,
            }
        )
        if not digest_equal(value.get("receipt_id"), expected_receipt):
            failures.append("receipt_id_mismatch")
        if not verify_hybrid(
            unsigned,
            value.get("signatures"),
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        ):
            failures.append("hybrid_signature_invalid")
        expected_artifact_digest = digest({**unsigned, "signatures": value.get("signatures")})
        if not digest_equal(value.get("artifact_digest"), expected_artifact_digest):
            failures.append("artifact_digest_mismatch")
    except (KeyError, TypeError, ValueError, LocalTrustArtifactError):
        failures.append("artifact_malformed")
    return {
        "status": PASS if not failures else FAIL,
        "validation_failures": sorted(set(failures)),
        "artifact_digest": value.get("artifact_digest") if type(value) is dict else None,
        "no_authority": dict(NO_AUTHORITY),
    }


def validate_artifact_chain(
    artifacts: Any,
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_stages: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Verify exact order, chronology, both signatures, time chain and uniqueness."""

    stages = expected_stages or tuple(STAGE_SCHEMAS)
    failures: list[str] = []
    if type(artifacts) is not list or len(artifacts) != len(stages):
        return {
            "status": FAIL,
            "validation_failures": ["artifact_chain_shape_invalid"],
            "head_digest": None,
            "time_head_digest": None,
            "no_authority": dict(NO_AUTHORITY),
        }
    prior = GENESIS
    prior_time = GENESIS
    seen_artifacts: set[str] = set()
    seen_replays: set[str] = set()
    seen_receipts: set[str] = set()
    prior_observed_at_ms = -1
    for expected_time_sequence, (stage, artifact) in enumerate(zip(stages, artifacts), start=1):
        result = validate_signed_artifact(
            artifact,
            expected_stage=stage,
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            clock_trust_context=clock_trust_context,
            owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
            expected_prior_artifact_digest=prior,
            expected_time_sequence=expected_time_sequence,
            expected_prior_time_digest=prior_time,
        )
        failures.extend(f"{stage}:{item}" for item in result["validation_failures"])
        if type(artifact) is not dict:
            continue
        artifact_digest = artifact.get("artifact_digest")
        replay_id = artifact.get("replay_id")
        receipt_id = artifact.get("receipt_id")
        if artifact_digest in seen_artifacts:
            failures.append(f"{stage}:duplicate_artifact_digest")
        if replay_id in seen_replays:
            failures.append(f"{stage}:duplicate_replay_id")
        if receipt_id in seen_receipts:
            failures.append(f"{stage}:duplicate_receipt_id")
        if is_sha512(artifact_digest):
            seen_artifacts.add(artifact_digest)
            prior = artifact_digest
        time_digest = artifact.get("time_evidence_digest")
        observed_at_ms = artifact.get("time_evidence", {}).get("observed_at_ms")
        if type(observed_at_ms) is not int or observed_at_ms <= prior_observed_at_ms:
            failures.append(f"{stage}:trusted_time_not_monotonic")
        else:
            prior_observed_at_ms = observed_at_ms
        if is_sha512(time_digest):
            prior_time = time_digest
        if is_sha512(replay_id):
            seen_replays.add(replay_id)
        if is_sha512(receipt_id):
            seen_receipts.add(receipt_id)
    return {
        "status": PASS if not failures else FAIL,
        "validation_failures": sorted(set(failures)),
        "head_digest": prior if is_sha512(prior) else None,
        "time_head_digest": prior_time if is_sha512(prior_time) else None,
        "no_authority": dict(NO_AUTHORITY),
    }


from .constants import (  # placed after functions to keep contract constants grouped
    FAIL,
    PASS,
)

__all__ = [
    "LocalTrustArtifactError",
    "build_signed_artifact",
    "build_trusted_time_evidence",
    "validate_artifact_chain",
    "validate_signed_artifact",
    "verify_trusted_time_evidence",
]
