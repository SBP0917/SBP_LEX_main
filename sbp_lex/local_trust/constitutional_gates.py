"""Detached constitutional boundary gates (stage 5)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifact import build_signed_artifact, validate_artifact_chain, validate_signed_artifact
from .boundary_checker import check_runtime_detachment
from .constants import FAIL, NO_AUTHORITY, PASS
from .evidence_chain import compare_evidence_to_current_files
from .signing import HybridSigningContext, HybridVerificationContext


PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_CONSTITUTIONAL_GATES_PAYLOAD_V1"
GATE_ORDER = (
    "signed_prefix_valid",
    "all_prior_status_pass",
    "no_authority_exact",
    "required_evidence_complete",
    "current_files_unchanged",
    "required_commands_pass",
    "regression_matrix_pass",
    "runtime_detachment_pass",
    "repository_clean",
)


def _gate(gate_id: str, passed: bool, evidence: Any) -> dict[str, Any]:
    from .digests import digest
    return {
        "gate_id": gate_id,
        "required": True,
        "status": PASS if passed else FAIL,
        "evidence_digest": digest(evidence),
    }


def build_constitutional_gates(
    repository_root: str | Path,
    *,
    manifest: Mapping[str, Any],
    execution_envelope: Mapping[str, Any],
    evidence_chain: Mapping[str, Any],
    regression_matrix: Mapping[str, Any],
    signer: HybridSigningContext,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    time_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    prefix = [dict(item) for item in (manifest, execution_envelope, evidence_chain, regression_matrix)]
    trust = signer.verification_context(allow_test_only=signer.signer_class == "TEST_ONLY")
    chain_result = validate_artifact_chain(
        prefix,
        trust_context=trust,
        owner_pinned_context_digest=trust.context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_stages=("manifest", "execution_envelope", "evidence_chain", "regression_matrix"),
    )
    manifest_payload = manifest.get("payload", {})
    envelope_payload = execution_envelope.get("payload", {})
    evidence_payload = evidence_chain.get("payload", {})
    regression_payload = regression_matrix.get("payload", {})
    current_compare = compare_evidence_to_current_files(
        repository_root,
        evidence_payload.get("evidence_snapshot"),
    )
    detachment = check_runtime_detachment(repository_root)
    conditions = {
        "signed_prefix_valid": (chain_result["status"] == PASS, chain_result),
        "all_prior_status_pass": (
            all(item.get("payload", {}).get("status") == PASS for item in prefix),
            [item.get("payload", {}).get("status") for item in prefix],
        ),
        "no_authority_exact": (
            all(item.get("no_authority") == NO_AUTHORITY for item in prefix),
            [item.get("no_authority") for item in prefix],
        ),
        "required_evidence_complete": (
            manifest_payload.get("evidence_inventory", {}).get("required_missing_groups") == [],
            manifest_payload.get("evidence_inventory", {}).get("required_missing_groups"),
        ),
        "current_files_unchanged": (
            current_compare == {"missing_evidence": [], "changed_evidence": []},
            current_compare,
        ),
        "required_commands_pass": (
            envelope_payload.get("required_command_failures") == [],
            envelope_payload.get("required_command_failures"),
        ),
        "regression_matrix_pass": (regression_payload.get("status") == PASS, regression_payload.get("case_results")),
        "runtime_detachment_pass": (detachment["status"] == PASS, detachment),
        "repository_clean": (manifest_payload.get("repository", {}).get("working_tree_clean") is True, manifest_payload.get("repository")),
    }
    gates = [_gate(gate_id, *conditions[gate_id]) for gate_id in GATE_ORDER]
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if all(item["status"] == PASS for item in gates) else FAIL,
        "bound_stage_digests": [item.get("artifact_digest") for item in prefix],
        "gate_order": list(GATE_ORDER),
        "gate_results": gates,
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="constitutional_gates",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(regression_matrix.get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_constitutional_gates(
    gates: Any,
    *,
    expected_regression_digest: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
) -> dict[str, Any]:
    base = validate_signed_artifact(
        gates,
        expected_stage="constitutional_gates",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=expected_regression_digest,
        expected_time_sequence=expected_time_sequence,
        expected_prior_time_digest=expected_prior_time_digest,
    )
    failures = list(base["validation_failures"])
    try:
        payload = gates["payload"]
        results = payload.get("gate_results")
        if (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("gate_order") != list(GATE_ORDER)
            or type(results) is not list
            or [item.get("gate_id") for item in results] != list(GATE_ORDER)
            or any(item.get("status") != PASS or item.get("required") is not True for item in results)
            or payload.get("runtime_attachment") != "NONE"
        ):
            failures.append("constitutional_gates_not_admissible")
    except (KeyError, TypeError, ValueError):
        failures.append("constitutional_gates_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


validate_constitutional_gate_result = validate_constitutional_gates

__all__ = ["GATE_ORDER", "build_constitutional_gates", "validate_constitutional_gate_result", "validate_constitutional_gates"]
