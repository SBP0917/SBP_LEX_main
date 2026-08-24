"""Build and verify the complete detached V2 local-trust artifact chain."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .adversarial_harness import build_adversarial_harness, validate_adversarial_harness
from .artifact import build_trusted_time_evidence, validate_artifact_chain
from .capstone import build_capstone, validate_capstone
from .constants import (
    DETACHED_BOUNDARY,
    FAIL,
    GENESIS,
    NO_AUTHORITY,
    PASS,
    STAGE_ORDER,
)
from .constitutional_gates import build_constitutional_gates, validate_constitutional_gates
from .deployment import DeploymentTrust, DeploymentTrustError
from .digests import digest, digest_equal
from .dossier import build_claims_evidence_dossier, validate_claims_evidence_dossier
from .evidence_chain import build_evidence_chain, validate_evidence_chain
from .execution_envelope import build_execution_envelope, validate_execution_envelope
from .history import validate_accepted_package_history
from .manifest import build_manifest, validate_manifest
from .regression_matrix import build_regression_matrix, validate_regression_matrix
from .release_integrity import build_release_integrity_bundle, validate_release_integrity_bundle
from .signing import HybridSigningContext
from .toolchain_guard import (
    build_toolchain_guard,
    collect_isolated_assurance_evidence,
    validate_toolchain_guard,
)


PACKAGE_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_PACKAGE_V1"
_PACKAGE_UNSIGNED_FIELDS = {
    "package_schema",
    "composition_class",
    "repository_identity_digest",
    "artifact_context_digest",
    "clock_context_digest",
    "history_context_digest",
    "accepted_history_digest",
    "accepted_history_sequence",
    "accepted_history_live_head_digest",
    "stage_order",
    "artifacts",
    "package_status",
    "no_authority",
    "detached_boundary",
}
_PACKAGE_FIELDS = _PACKAGE_UNSIGNED_FIELDS | {"package_digest"}


def _signer_matches_deployment(
    signer: HybridSigningContext,
    expected_record: Mapping[str, Any],
) -> bool:
    try:
        context = signer.verification_context(
            allow_test_only=signer.signer_class == "TEST_ONLY"
        )
        return context.public_record() == expected_record
    except (TypeError, ValueError):
        return False


def _validate_build_inputs(
    repository_root: str | Path,
    *,
    signer: HybridSigningContext,
    clock_signer: HybridSigningContext,
    deployment: DeploymentTrust,
    accepted_history: Mapping[str, Any],
) -> None:
    deployment.validate_repository(repository_root)
    if not _signer_matches_deployment(signer, deployment.artifact_context.public_record()):
        raise DeploymentTrustError("artifact_signer_not_deployment_pinned")
    if not _signer_matches_deployment(clock_signer, deployment.clock_context.public_record()):
        raise DeploymentTrustError("clock_signer_not_deployment_pinned")
    history = validate_accepted_package_history(
        accepted_history,
        repository_identity_digest=deployment.repository_identity.identity_digest,
        trust_context=deployment.history_context,
        owner_pinned_context_digest=deployment.owner_pinned_history_context_digest,
        expected_history_digest=deployment.expected_accepted_history_digest,
        minimum_sequence=deployment.minimum_accepted_history_sequence,
    )
    if history["status"] != PASS:
        raise DeploymentTrustError("accepted_history_not_current")


def build_local_trust_package(
    repository_root: str | Path,
    *,
    signer: HybridSigningContext,
    clock_signer: HybridSigningContext,
    deployment: DeploymentTrust,
    accepted_history: Mapping[str, Any],
    observed_at_ms: int,
) -> dict[str, Any]:
    """Build evidence only; this function cannot admit its own package."""

    _validate_build_inputs(
        repository_root,
        signer=signer,
        clock_signer=clock_signer,
        deployment=deployment,
        accepted_history=accepted_history,
    )
    artifacts: list[dict[str, Any]] = []
    prior_time = GENESIS

    def time_for(sequence: int) -> dict[str, Any]:
        nonlocal prior_time
        evidence = build_trusted_time_evidence(
            signer=clock_signer,
            observed_at_ms=observed_at_ms + sequence - 1,
            time_sequence=sequence,
            prior_time_digest=prior_time,
            source_class=(
                "TEST_ONLY_MONOTONIC_CLOCK"
                if deployment.composition_class == "TEST_ONLY"
                else "ADMITTED_EXTERNAL_MONOTONIC_CLOCK"
            ),
        )
        prior_time = evidence["time_evidence_digest"]
        return evidence

    clock = deployment.clock_context
    clock_pin = deployment.owner_pinned_clock_context_digest
    repository_identity_digest = deployment.repository_identity.identity_digest
    manifest = build_manifest(
        repository_root,
        signer=signer,
        time_evidence=time_for(1),
        repository_identity_digest=repository_identity_digest,
        accepted_history=accepted_history,
    )
    artifacts.append(manifest)
    envelope = build_execution_envelope(
        repository_root,
        manifest=manifest,
        signer=signer,
        time_evidence=time_for(2),
    )
    artifacts.append(envelope)
    evidence = build_evidence_chain(
        repository_root,
        manifest=manifest,
        execution_envelope=envelope,
        signer=signer,
        time_evidence=time_for(3),
    )
    artifacts.append(evidence)
    matrix = build_regression_matrix(
        evidence_chain=evidence,
        signer=signer,
        clock_trust_context=clock,
        owner_pinned_clock_context_digest=clock_pin,
        time_evidence=time_for(4),
    )
    artifacts.append(matrix)
    gates = build_constitutional_gates(
        repository_root,
        manifest=manifest,
        execution_envelope=envelope,
        evidence_chain=evidence,
        regression_matrix=matrix,
        signer=signer,
        clock_trust_context=clock,
        owner_pinned_clock_context_digest=clock_pin,
        time_evidence=time_for(5),
    )
    artifacts.append(gates)
    toolchain = build_toolchain_guard(
        repository_root,
        constitutional_gates=gates,
        manifest=manifest,
        execution_envelope=envelope,
        signer=signer,
        time_evidence=time_for(6),
    )
    artifacts.append(toolchain)
    capstone = build_capstone(
        prior_artifacts=artifacts,
        signer=signer,
        clock_trust_context=clock,
        owner_pinned_clock_context_digest=clock_pin,
        time_evidence=time_for(7),
    )
    artifacts.append(capstone)
    release = build_release_integrity_bundle(
        prior_artifacts=artifacts,
        signer=signer,
        clock_trust_context=clock,
        owner_pinned_clock_context_digest=clock_pin,
        time_evidence=time_for(8),
    )
    artifacts.append(release)
    adversarial = build_adversarial_harness(
        repository_root,
        release_integrity=release,
        signer=signer,
        clock_trust_context=clock,
        owner_pinned_clock_context_digest=clock_pin,
        time_evidence=time_for(9),
    )
    artifacts.append(adversarial)
    dossier = build_claims_evidence_dossier(
        prior_artifacts=artifacts,
        signer=signer,
        clock_trust_context=clock,
        owner_pinned_clock_context_digest=clock_pin,
        time_evidence=time_for(10),
    )
    artifacts.append(dossier)
    unsigned = {
        "package_schema": PACKAGE_SCHEMA,
        "composition_class": deployment.composition_class,
        "repository_identity_digest": repository_identity_digest,
        "artifact_context_digest": deployment.owner_pinned_artifact_context_digest,
        "clock_context_digest": deployment.owner_pinned_clock_context_digest,
        "history_context_digest": deployment.owner_pinned_history_context_digest,
        "accepted_history_digest": accepted_history.get("history_digest"),
        "accepted_history_sequence": accepted_history.get("sequence"),
        "accepted_history_live_head_digest": accepted_history.get("live_head_digest"),
        "stage_order": list(STAGE_ORDER),
        "artifacts": artifacts,
        "package_status": (
            PASS if all(item["payload"].get("status") == PASS for item in artifacts) else FAIL
        ),
        "no_authority": dict(NO_AUTHORITY),
        "detached_boundary": dict(DETACHED_BOUNDARY),
    }
    return {**unsigned, "package_digest": digest(unsigned)}


def validate_local_trust_package(
    package: Any,
    repository_root: str | Path,
    *,
    deployment: DeploymentTrust,
    accepted_history: Mapping[str, Any],
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        deployment.validate_repository(repository_root)
    except DeploymentTrustError as exc:
        failures.append(str(exc))
    if type(package) is not dict or set(package) != _PACKAGE_FIELDS:
        return {"status": FAIL, "validation_failures": ["package_shape_invalid"]}
    unsigned = {field: package[field] for field in _PACKAGE_UNSIGNED_FIELDS}
    if not digest_equal(package.get("package_digest"), digest(unsigned)):
        failures.append("package_digest_invalid")
    history = validate_accepted_package_history(
        accepted_history,
        repository_identity_digest=deployment.repository_identity.identity_digest,
        trust_context=deployment.history_context,
        owner_pinned_context_digest=deployment.owner_pinned_history_context_digest,
        expected_history_digest=deployment.expected_accepted_history_digest,
        minimum_sequence=deployment.minimum_accepted_history_sequence,
    )
    failures.extend(history["validation_failures"])
    expected_fields = {
        "package_schema": PACKAGE_SCHEMA,
        "composition_class": deployment.composition_class,
        "repository_identity_digest": deployment.repository_identity.identity_digest,
        "artifact_context_digest": deployment.owner_pinned_artifact_context_digest,
        "clock_context_digest": deployment.owner_pinned_clock_context_digest,
        "history_context_digest": deployment.owner_pinned_history_context_digest,
        "accepted_history_digest": history.get("history_digest"),
        "accepted_history_sequence": history.get("sequence"),
        "accepted_history_live_head_digest": history.get("live_head_digest"),
        "stage_order": list(STAGE_ORDER),
        "no_authority": NO_AUTHORITY,
        "detached_boundary": DETACHED_BOUNDARY,
    }
    if any(package.get(field) != value for field, value in expected_fields.items()):
        failures.append("package_deployment_binding_invalid")
    artifacts = package.get("artifacts")
    artifact_context = deployment.artifact_context
    artifact_pin = deployment.owner_pinned_artifact_context_digest
    clock_context = deployment.clock_context
    clock_pin = deployment.owner_pinned_clock_context_digest
    chain = validate_artifact_chain(
        artifacts,
        trust_context=artifact_context,
        owner_pinned_context_digest=artifact_pin,
        clock_trust_context=clock_context,
        owner_pinned_clock_context_digest=clock_pin,
        expected_stages=STAGE_ORDER,
    )
    failures.extend(chain["validation_failures"])
    if type(artifacts) is not list or len(artifacts) != len(STAGE_ORDER):
        failures.append("package_artifacts_invalid")
        return {"status": FAIL, "validation_failures": sorted(set(failures))}
    manifest, envelope, evidence, matrix, gates, toolchain, capstone, release, adversarial, dossier = artifacts
    common = {
        "trust_context": artifact_context,
        "owner_pinned_context_digest": artifact_pin,
        "clock_trust_context": clock_context,
        "owner_pinned_clock_context_digest": clock_pin,
    }
    validators = [
        validate_manifest(
            manifest,
            repository_root,
            **common,
            expected_time_sequence=1,
            expected_prior_time_digest=GENESIS,
            expected_repository_identity_digest=deployment.repository_identity.identity_digest,
            expected_accepted_history_digest=history.get("history_digest"),
            expected_accepted_history_sequence=history.get("sequence"),
            expected_accepted_history_live_head_digest=history.get("live_head_digest"),
        ),
        validate_execution_envelope(
            envelope,
            repository_root,
            **common,
            expected_manifest_digest=manifest.get("artifact_digest"),
            expected_time_sequence=2,
            expected_prior_time_digest=manifest.get("time_evidence_digest"),
        ),
        validate_evidence_chain(
            evidence,
            repository_root,
            **common,
            expected_envelope_digest=envelope.get("artifact_digest"),
            expected_manifest_digest=manifest.get("artifact_digest"),
            expected_time_sequence=3,
            expected_prior_time_digest=envelope.get("time_evidence_digest"),
        ),
        validate_regression_matrix(
            matrix,
            **common,
            expected_evidence_chain_digest=evidence.get("artifact_digest"),
            expected_time_sequence=4,
            expected_prior_time_digest=evidence.get("time_evidence_digest"),
        ),
        validate_constitutional_gates(
            gates,
            **common,
            expected_regression_digest=matrix.get("artifact_digest"),
            expected_time_sequence=5,
            expected_prior_time_digest=matrix.get("time_evidence_digest"),
        ),
        validate_toolchain_guard(
            toolchain,
            repository_root,
            **common,
            expected_gates_digest=gates.get("artifact_digest"),
            expected_manifest_digest=manifest.get("artifact_digest"),
            expected_envelope_digest=envelope.get("artifact_digest"),
            expected_assurance_evidence=collect_isolated_assurance_evidence(manifest, envelope),
            expected_time_sequence=6,
            expected_prior_time_digest=gates.get("time_evidence_digest"),
        ),
        validate_capstone(capstone, prior_artifacts=artifacts[:6], **common),
        validate_release_integrity_bundle(
            release, repository_root, **common
        ),
        validate_adversarial_harness(
            adversarial,
            **common,
            expected_release_digest=release.get("artifact_digest"),
            expected_prior_time_digest=release.get("time_evidence_digest"),
        ),
        validate_claims_evidence_dossier(
            dossier, prior_artifacts=artifacts[:9], **common
        ),
    ]
    for stage, result in zip(STAGE_ORDER, validators):
        failures.extend(f"{stage}:{item}" for item in result["validation_failures"])
    if package.get("package_status") != PASS:
        failures.append("package_status_not_pass")
    return {
        "status": PASS if not failures else FAIL,
        "validation_failures": sorted(set(failures)),
        "package_digest": package.get("package_digest"),
        "chain_head_digest": chain.get("head_digest"),
        "time_head_digest": chain.get("time_head_digest"),
        "accepted_history_digest": history.get("history_digest"),
        "no_authority": dict(NO_AUTHORITY),
    }


__all__ = ["PACKAGE_SCHEMA", "build_local_trust_package", "validate_local_trust_package"]
