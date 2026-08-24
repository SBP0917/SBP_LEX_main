"""Negative-test harness contract over the signed release bundle (stage 9)."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .artifact import build_signed_artifact, validate_signed_artifact
from .constants import FAIL, PASS
from .release_integrity import validate_release_integrity_bundle
from .signing import HybridSigningContext, HybridVerificationContext


PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_ADVERSARIAL_HARNESS_PAYLOAD_V1"
CASE_ORDER = (
    "release_digest_tamper",
    "release_mldsa87_tamper",
    "release_ed448_tamper",
    "embedded_artifact_tamper",
    "embedded_artifact_missing",
    "embedded_artifact_reorder",
    "provider_substitution",
    "authority_grant_injection",
    "legacy_sha256_width",
    "trusted_time_rollback",
)


def _mutate(case_id: str, value: dict[str, Any]) -> None:
    if case_id == "release_digest_tamper":
        value["artifact_digest"] = "0" * 128
    elif case_id == "release_mldsa87_tamper":
        value["signatures"]["mldsa87"]["signature_b64"] = "AA=="
    elif case_id == "release_ed448_tamper":
        value["signatures"]["ed448"]["signature_b64"] = "AA=="
    elif case_id == "embedded_artifact_tamper":
        value["payload"]["embedded_artifacts"][0]["payload"]["status"] = "TAMPERED"
    elif case_id == "embedded_artifact_missing":
        value["payload"]["embedded_artifacts"].pop()
    elif case_id == "embedded_artifact_reorder":
        value["payload"]["embedded_artifacts"][0], value["payload"]["embedded_artifacts"][1] = value["payload"]["embedded_artifacts"][1], value["payload"]["embedded_artifacts"][0]
    elif case_id == "provider_substitution":
        value["signatures"]["provider_id"] = "ATTACKER"
    elif case_id == "authority_grant_injection":
        value["no_authority"]["authority_granted"] = True
    elif case_id == "legacy_sha256_width":
        value["payload_digest"] = "1" * 64
    elif case_id == "trusted_time_rollback":
        value["time_evidence"]["time_sequence"] = 1


def run_adversarial_cases(
    release: Mapping[str, Any],
    repository_root: str | Path,
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
) -> list[dict[str, Any]]:
    from .digests import digest
    baseline = validate_release_integrity_bundle(
        release,
        repository_root,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
    )
    baseline_admissible = baseline["status"] == PASS
    results: list[dict[str, Any]] = []
    for case_id in CASE_ORDER:
        candidate = deepcopy(dict(release))
        _mutate(case_id, candidate)
        validation = validate_release_integrity_bundle(
            candidate,
            repository_root,
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            clock_trust_context=clock_trust_context,
            owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        )
        rejected = validation["status"] == FAIL
        results.append(
            {
                "case_id": case_id,
                "expected": "REJECT",
                "actual": "REJECT" if rejected else "ACCEPT",
                "status": PASS if rejected and baseline_admissible else FAIL,
                "baseline_admissible": baseline_admissible,
                "failure_digest": digest({"validation_failures": validation["validation_failures"]}),
            }
        )
    return results


def build_adversarial_harness(
    repository_root: str | Path,
    *,
    release_integrity: Mapping[str, Any],
    signer: HybridSigningContext,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    time_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    trust = signer.verification_context(allow_test_only=signer.signer_class == "TEST_ONLY")
    cases = run_adversarial_cases(
        release_integrity,
        repository_root,
        trust_context=trust,
        owner_pinned_context_digest=trust.context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
    )
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if all(item["status"] == PASS for item in cases) else FAIL,
        "bound_release_integrity_digest": release_integrity.get("artifact_digest"),
        "case_order": list(CASE_ORDER),
        "case_results": cases,
        "baseline_validation_status": PASS if all(
            item.get("baseline_admissible") is True for item in cases
        ) else FAIL,
        "baseline_mutated": False,
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="adversarial_harness",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(release_integrity.get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_adversarial_harness(
    harness: Any,
    *,
    expected_release_digest: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_prior_time_digest: str,
) -> dict[str, Any]:
    base = validate_signed_artifact(
        harness,
        expected_stage="adversarial_harness",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=expected_release_digest,
        expected_time_sequence=9,
        expected_prior_time_digest=expected_prior_time_digest,
    )
    failures = list(base["validation_failures"])
    try:
        payload = harness["payload"]
        results = payload.get("case_results")
        if (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("bound_release_integrity_digest") != expected_release_digest
            or payload.get("case_order") != list(CASE_ORDER)
            or type(results) is not list
            or [item.get("case_id") for item in results] != list(CASE_ORDER)
            or any(item.get("status") != PASS or item.get("actual") != "REJECT" for item in results)
            or any(item.get("baseline_admissible") is not True for item in results)
            or payload.get("baseline_validation_status") != PASS
            or payload.get("baseline_mutated") is not False
            or payload.get("runtime_attachment") != "NONE"
        ):
            failures.append("adversarial_harness_not_admissible")
    except (KeyError, TypeError, ValueError):
        failures.append("adversarial_harness_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


build_adversarial_negative_harness = build_adversarial_harness
validate_adversarial_negative_harness = validate_adversarial_harness

__all__ = [
    "CASE_ORDER", "build_adversarial_harness", "build_adversarial_negative_harness",
    "run_adversarial_cases", "validate_adversarial_harness",
    "validate_adversarial_negative_harness",
]
