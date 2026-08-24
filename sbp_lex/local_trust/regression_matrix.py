"""Deterministic tamper/drift regression matrix (stage 4)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .artifact import build_signed_artifact, validate_signed_artifact
from .constants import FAIL, PASS
from .signing import HybridSigningContext, HybridVerificationContext


PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_REGRESSION_MATRIX_PAYLOAD_V1"
REQUIRED_CASES = (
    "artifact_digest_tamper",
    "mldsa87_signature_tamper",
    "ed448_signature_tamper",
    "payload_substitution",
    "predecessor_substitution",
    "trusted_time_tamper",
    "replay_id_tamper",
    "authority_flag_tamper",
    "legacy_sha256_width_rejection",
)


def _mutate(case_id: str, artifact: dict[str, Any]) -> None:
    if case_id == "artifact_digest_tamper":
        artifact["artifact_digest"] = "0" * 128
    elif case_id == "mldsa87_signature_tamper":
        artifact["signatures"]["mldsa87"]["signature_b64"] = "AA=="
    elif case_id == "ed448_signature_tamper":
        artifact["signatures"]["ed448"]["signature_b64"] = "AA=="
    elif case_id == "payload_substitution":
        artifact["payload"]["status"] = "SUBSTITUTED"
    elif case_id == "predecessor_substitution":
        artifact["prior_artifact_digest"] = "1" * 128
    elif case_id == "trusted_time_tamper":
        artifact["time_evidence"]["observed_at_ms"] += 1
    elif case_id == "replay_id_tamper":
        artifact["replay_id"] = "2" * 128
    elif case_id == "authority_flag_tamper":
        artifact["no_authority"]["execution_authority_granted"] = True
    elif case_id == "legacy_sha256_width_rejection":
        artifact["payload_digest"] = "3" * 64


def run_regression_cases(
    evidence_chain: Mapping[str, Any],
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
) -> list[dict[str, Any]]:
    expected_prior = evidence_chain.get("prior_artifact_digest")
    time_evidence = evidence_chain.get("time_evidence", {})
    baseline = validate_signed_artifact(
        evidence_chain,
        expected_stage="evidence_chain",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=expected_prior,
        expected_time_sequence=time_evidence.get("time_sequence"),
        expected_prior_time_digest=time_evidence.get("prior_time_digest"),
    )
    baseline_admissible = baseline["status"] == PASS
    results: list[dict[str, Any]] = []
    for case_id in REQUIRED_CASES:
        candidate = deepcopy(dict(evidence_chain))
        _mutate(case_id, candidate)
        validation = validate_signed_artifact(
            candidate,
            expected_stage="evidence_chain",
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            clock_trust_context=clock_trust_context,
            owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
            expected_prior_artifact_digest=expected_prior,
            expected_time_sequence=time_evidence.get("time_sequence"),
            expected_prior_time_digest=time_evidence.get("prior_time_digest"),
        )
        rejected = validation["status"] == FAIL
        results.append(
            {
                "case_id": case_id,
                "expected": "REJECT",
                "actual": "REJECT" if rejected else "ACCEPT",
                "status": PASS if rejected and baseline_admissible else FAIL,
                "baseline_admissible": baseline_admissible,
                "failure_digest": __import__("sbp_lex.local_trust.digests", fromlist=["digest"]).digest(
                    {"validation_failures": validation["validation_failures"]}
                ),
            }
        )
    return results


def build_regression_matrix(
    *,
    evidence_chain: Mapping[str, Any],
    signer: HybridSigningContext,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    time_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    trust = signer.verification_context(allow_test_only=signer.signer_class == "TEST_ONLY")
    cases = run_regression_cases(
        evidence_chain,
        trust_context=trust,
        owner_pinned_context_digest=trust.context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
    )
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if all(case["status"] == PASS for case in cases) else FAIL,
        "bound_evidence_chain_digest": evidence_chain.get("artifact_digest"),
        "case_order": list(REQUIRED_CASES),
        "case_results": cases,
        "baseline_validation_status": PASS if all(
            item.get("baseline_admissible") is True for item in cases
        ) else FAIL,
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="regression_matrix",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(evidence_chain.get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_regression_matrix(
    matrix: Any,
    *,
    expected_evidence_chain_digest: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
) -> dict[str, Any]:
    base = validate_signed_artifact(
        matrix,
        expected_stage="regression_matrix",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=expected_evidence_chain_digest,
        expected_time_sequence=expected_time_sequence,
        expected_prior_time_digest=expected_prior_time_digest,
    )
    failures = list(base["validation_failures"])
    try:
        payload = matrix["payload"]
        results = payload.get("case_results")
        if (
            type(payload) is not dict
            or payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("bound_evidence_chain_digest") != expected_evidence_chain_digest
            or payload.get("case_order") != list(REQUIRED_CASES)
            or type(results) is not list
            or [item.get("case_id") for item in results] != list(REQUIRED_CASES)
            or any(item.get("status") != PASS or item.get("actual") != "REJECT" for item in results)
            or any(item.get("baseline_admissible") is not True for item in results)
            or payload.get("baseline_validation_status") != PASS
            or payload.get("runtime_attachment") != "NONE"
        ):
            failures.append("regression_matrix_not_admissible")
    except (KeyError, TypeError, ValueError):
        failures.append("regression_matrix_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


validate_local_trust_regression_matrix = validate_regression_matrix

__all__ = [
    "REQUIRED_CASES", "build_regression_matrix", "run_regression_cases",
    "validate_local_trust_regression_matrix", "validate_regression_matrix",
]
