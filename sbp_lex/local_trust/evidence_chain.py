"""Current-file evidence chain and comparison (stage 3)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .artifact import (
    build_signed_artifact,
    validate_signed_artifact,
)
from .constants import FAIL, PASS
from .paths import LocalTrustPathError, measure_file, validated_root
from .signing import HybridSigningContext, HybridVerificationContext

PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_EVIDENCE_CHAIN_PAYLOAD_V1"
_PAYLOAD_FIELDS = frozenset({
    "schema_id", "status", "bound_manifest_digest", "bound_envelope_digest",
    "evidence_snapshot", "missing_evidence", "changed_evidence",
    "runtime_attachment",
})


def compare_evidence_to_current_files(
    repository_root: str | Path,
    evidence_snapshot: Any,
) -> dict[str, list[dict[str, Any]]]:
    root = validated_root(repository_root)
    missing: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    if type(evidence_snapshot) is not list:
        return {"missing_evidence": [{"path": "INVALID_SNAPSHOT"}], "changed_evidence": []}
    for expected in evidence_snapshot:
        if type(expected) is not dict or type(expected.get("path")) is not str:
            changed.append({"path": "INVALID_RECORD", "change": "MALFORMED"})
            continue
        try:
            observed = measure_file(root, expected["path"])
        except LocalTrustPathError:
            missing.append({"path": expected["path"], "change": "MISSING_OR_UNSAFE"})
            continue
        if observed != expected:
            changed.append(
                {
                    "path": expected["path"],
                    "change": "MEASUREMENT_MISMATCH",
                    "expected_sha512": expected.get("sha512"),
                    "observed_sha512": observed.get("sha512"),
                }
            )
    return {"missing_evidence": missing, "changed_evidence": changed}


def build_evidence_chain(
    repository_root: str | Path,
    *,
    manifest: Mapping[str, Any],
    execution_envelope: Mapping[str, Any],
    signer: HybridSigningContext,
    time_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    snapshot = manifest.get("payload", {}).get("evidence_inventory", {}).get("files", [])
    comparison = compare_evidence_to_current_files(repository_root, snapshot)
    failures = comparison["missing_evidence"] or comparison["changed_evidence"]
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if not failures else FAIL,
        "bound_manifest_digest": manifest.get("artifact_digest"),
        "bound_envelope_digest": execution_envelope.get("artifact_digest"),
        "evidence_snapshot": snapshot,
        **comparison,
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="evidence_chain",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(execution_envelope.get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_evidence_chain(
    chain: Any,
    repository_root: str | Path,
    *,
    expected_envelope_digest: str,
    expected_manifest_digest: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
) -> dict[str, Any]:
    base = validate_signed_artifact(
        chain,
        expected_stage="evidence_chain",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=expected_envelope_digest,
        expected_time_sequence=expected_time_sequence,
        expected_prior_time_digest=expected_prior_time_digest,
    )
    failures = list(base["validation_failures"])
    try:
        payload = chain["payload"]
        current = compare_evidence_to_current_files(repository_root, payload.get("evidence_snapshot"))
        if type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS:
            failures.append("evidence_chain_payload_shape_invalid")
        elif (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("bound_manifest_digest") != expected_manifest_digest
            or payload.get("bound_envelope_digest") != expected_envelope_digest
            or payload.get("missing_evidence") != []
            or payload.get("changed_evidence") != []
            or current != {"missing_evidence": [], "changed_evidence": []}
            or payload.get("runtime_attachment") != "NONE"
        ):
            failures.append("evidence_chain_not_current_or_admissible")
    except (KeyError, TypeError, ValueError):
        failures.append("evidence_chain_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


compare_evidence_chain_to_current_files = compare_evidence_to_current_files
validate_local_evidence_chain = validate_evidence_chain

__all__ = [
    "build_evidence_chain", "compare_evidence_chain_to_current_files",
    "compare_evidence_to_current_files", "validate_evidence_chain",
    "validate_local_evidence_chain",
]
