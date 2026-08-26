from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Final

from sbp_lex.compliance.australian_minor_access import (
    AUSTRALIAN_MINOR_ACCESS_STAGE,
    RESULT_DENY,
    RESULT_NOT_APPLICABLE,
    RESULT_PASS,
    bind_australian_minor_access_hash,
    evaluate_australian_minor_access,
    verify_australian_minor_access,
)
from sbp_lex.config.pipeline_config import (
    AUTHORITY_BOUNDARY_ADMISSION_STAGE,
    DIGITAL_PROVENANCE_STAGE,
    FOUNDATIONAL_BASELINE_ORDER,
)
from sbp_lex.identity.impersonation_protection import (
    AUTHORITY_BOUNDARY_COMPONENT,
    IMPERSONATION_DENY,
    IMPERSONATION_PASS,
    IMPERSONATION_PROTECTION_STAGE,
    SOVEREIGN_IDENTITY_COMPONENT,
    evaluate_impersonation_protection,
    impersonation_protection_hash_payload,
    impersonation_upstream_hash_payload,
    verify_impersonation_protection,
)
from sbp_lex.identity.sovereign_identity import (
    IDENTITY_ADMISSION_STAGE,
    IDENTITY_DENY,
    IDENTITY_VERIFIED,
    evaluate_sovereign_identity,
    sovereign_identity_hash_payload,
    verify_sovereign_identity,
)
from sbp_lex.interface.authority_boundary import (
    BOUNDARY_DENY,
    BOUNDARY_PASS,
    authority_boundary_hash_payload,
    evaluate_authority_boundary,
    verify_authority_boundary,
)
from sbp_lex.provenance.digital_provenance import (
    ADMIT,
    DENY,
    DIGITAL_PROVENANCE_CONTRACT_ID,
    NO_AUTHORIZATION_EFFECT as PROVENANCE_NO_AUTHORIZATION_EFFECT,
    ProvenanceDecision,
    ProvenanceDeploymentTrustContext,
    verify_digital_provenance,
    verify_provenance_verification_receipt,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)


_PROVENANCE_PROJECTION_KEYS: Final = (
    "digital_provenance_result",
    "digital_provenance_reason",
    "digital_provenance_digest",
    "digital_provenance_lineage_authenticated",
    "digital_provenance_verification_trace",
    "digital_provenance_verification_receipt",
    "digital_provenance_lineage_only",
)
_PROVENANCE_PAYLOAD_FIELDS: Final = frozenset({
    "contract_id",
    "stage",
    "result",
    "reason",
    "provenance_digest",
    "lineage_authenticated",
    "verification_trace_digest",
    "verification_receipt_digest",
    "lineage_only",
    *PROVENANCE_NO_AUTHORIZATION_EFFECT,
})
_CONTROL_STAGES: Final = (
    DIGITAL_PROVENANCE_STAGE,
    IDENTITY_ADMISSION_STAGE,
    AUTHORITY_BOUNDARY_ADMISSION_STAGE,
    IMPERSONATION_PROTECTION_STAGE,
    AUSTRALIAN_MINOR_ACCESS_STAGE,
)


@dataclass(frozen=True, slots=True)
class FoundationalRequestDependencies:
    provenance_registry_snapshot: dict[str, Any] | None
    provenance_trust_context: Any | None
    sovereign_identity_evaluator: Any | None
    sovereign_identity_attestation_provider: Any | None
    authority_boundary_evaluator: Any | None
    authority_boundary_attestation_provider: Any | None
    impersonation_trust_context: Any | None
    authority_provenance_dependencies: Any | None = None
    sovereign_identity_trust_context: Any | None = None
    sovereign_identity_owner_pinned_context_digest: str | None = None
    authority_boundary_trust_context: Any | None = None
    authority_boundary_owner_pinned_context_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provenance_registry_snapshot",
            deepcopy(self.provenance_registry_snapshot),
        )


def _state(state: Any) -> dict[str, Any]:
    return state if type(state) is dict else {}


def _chain_valid(state: dict[str, Any]) -> bool:
    chain = state.get("hash_chain")
    state_hash = state.get("state_hash")
    return (
        type(chain) is list
        and (
            verify_hash_chain_entries(chain, state_hash)
            if chain
            else state_hash == GENESIS_HASH
        )
    )


def _append_binding(
    state: dict[str, Any],
    *,
    stage: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if not _chain_valid(state):
        raise ValueError("FOUNDATIONAL_HASH_CHAIN_INVALID")
    chain = state["hash_chain"]
    if any(type(entry) is dict and entry.get("stage") == stage for entry in chain):
        raise ValueError("FOUNDATIONAL_HASH_BINDING_ALREADY_PRESENT")
    previous_hash = chain[-1]["hash"] if chain else GENESIS_HASH
    entry = build_hash_chain_entry(
        previous_hash=previous_hash,
        stage=stage,
        payload=payload,
    )
    chain.append(entry)
    state["state_hash"] = entry["hash"]
    if not verify_hash_chain_entries(chain, state["state_hash"]):
        raise ValueError("FOUNDATIONAL_HASH_BINDING_INVALID")
    return entry


def _unique_binding(
    state: dict[str, Any],
    *,
    stage: str,
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]] | None:
    chain = state.get("hash_chain")
    if type(chain) is not list or not verify_hash_chain_entries(
        chain, state.get("state_hash")
    ):
        return None
    expected_payload_hash = canonical_integrity_hash(payload)
    matches = [
        (index, entry)
        for index, entry in enumerate(chain)
        if type(entry) is dict
        and entry.get("stage") == stage
        and entry.get("payload_hash") == expected_payload_hash
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _provenance_projection(decision: ProvenanceDecision) -> dict[str, Any]:
    return {
        "digital_provenance_result": decision.result,
        "digital_provenance_reason": decision.reason,
        "digital_provenance_digest": decision.provenance_digest,
        "digital_provenance_lineage_authenticated": (
            decision.lineage_authenticated
        ),
        "digital_provenance_verification_trace": deepcopy(
            list(decision.verification_trace)
        ),
        "digital_provenance_verification_receipt": deepcopy(
            decision.verification_receipt
        ),
        "digital_provenance_lineage_only": decision.lineage_only,
    }


def _set_provenance_failure(
    state: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    state.update(
        {
            "digital_provenance_result": DENY,
            "digital_provenance_reason": reason,
            "digital_provenance_digest": None,
            "digital_provenance_lineage_authenticated": False,
            "digital_provenance_verification_trace": [],
            "digital_provenance_verification_receipt": {},
            "digital_provenance_lineage_only": True,
        }
    )
    return state


def run_digital_provenance_stage(
    state: dict[str, Any],
    *,
    dependencies: FoundationalRequestDependencies,
) -> dict[str, Any]:
    target = _state(state)
    try:
        if not isinstance(dependencies, FoundationalRequestDependencies):
            return _set_provenance_failure(
                target, "DIGITAL_PROVENANCE_DEPENDENCIES_MISSING"
            )
        trust_context = dependencies.provenance_trust_context
        request_fingerprint = target.get("request_fingerprint")
        release_manifest_digest = target.get("release_manifest_digest")
        runtime_measurement_digest = target.get("runtime_measurement_digest")
        if (
            not isinstance(trust_context, ProvenanceDeploymentTrustContext)
            or not isinstance(request_fingerprint, str)
            or not is_sha512(request_fingerprint)
            or not isinstance(release_manifest_digest, str)
            or not is_sha512(release_manifest_digest)
            or not isinstance(runtime_measurement_digest, str)
            or not is_sha512(runtime_measurement_digest)
        ):
            return _set_provenance_failure(
                target, "DIGITAL_PROVENANCE_DEPENDENCIES_INVALID"
            )
        decision = verify_digital_provenance(
            target.get("digital_provenance_graph"),
            registry_snapshot=deepcopy(
                dependencies.provenance_registry_snapshot
            ),
            trust_context=trust_context,
            expected_request_fingerprint=request_fingerprint,
            expected_release_manifest_digest=release_manifest_digest,
            expected_runtime_measurement_digest=runtime_measurement_digest,
        )
        target.update(_provenance_projection(decision))
        if (
            decision.result != ADMIT
            or not decision.admitted
            or not verify_provenance_verification_receipt(
                decision.verification_receipt,
                trust_context=trust_context,
            )
        ):
            return target
        bind_digital_provenance_hash(target)
        if not verify_digital_provenance_state(
            target, dependencies=dependencies
        ):
            return _set_provenance_failure(
                target, "DIGITAL_PROVENANCE_POST_BIND_VERIFICATION_FAILED"
            )
        return target
    except Exception:
        return _set_provenance_failure(
            target, "DIGITAL_PROVENANCE_DEPENDENCY_OR_EVIDENCE_FAILURE"
        )


def digital_provenance_hash_payload(
    state: dict[str, Any],
) -> dict[str, Any]:
    receipt = state.get("digital_provenance_verification_receipt")
    if type(receipt) is not dict:
        receipt = {}
    payload = {
        "contract_id": DIGITAL_PROVENANCE_CONTRACT_ID,
        "stage": DIGITAL_PROVENANCE_STAGE,
        "result": state.get("digital_provenance_result"),
        "reason": state.get("digital_provenance_reason"),
        "provenance_digest": state.get("digital_provenance_digest"),
        "lineage_authenticated": state.get(
            "digital_provenance_lineage_authenticated"
        ),
        "verification_trace_digest": canonical_integrity_hash(
            state.get("digital_provenance_verification_trace")
        ),
        "verification_receipt_digest": receipt.get("digest"),
        "lineage_only": state.get("digital_provenance_lineage_only"),
        **{
            field: receipt.get(field)
            for field in PROVENANCE_NO_AUTHORIZATION_EFFECT
        },
    }
    if set(payload) != _PROVENANCE_PAYLOAD_FIELDS:
        raise ValueError("DIGITAL_PROVENANCE_HASH_PAYLOAD_INVALID")
    return payload


def bind_digital_provenance_hash(
    state: dict[str, Any],
) -> dict[str, Any]:
    if (
        type(state) is not dict
        or state.get("digital_provenance_result") != ADMIT
        or state.get("digital_provenance_lineage_authenticated") is not True
        or state.get("digital_provenance_lineage_only") is not True
    ):
        raise ValueError("DIGITAL_PROVENANCE_NOT_ADMITTED")
    receipt = state.get("digital_provenance_verification_receipt")
    if (
        type(receipt) is not dict
        or not is_sha512(receipt.get("digest"))
        or any(
            receipt.get(field) is not expected
            for field, expected in PROVENANCE_NO_AUTHORIZATION_EFFECT.items()
        )
    ):
        raise ValueError("DIGITAL_PROVENANCE_RECEIPT_INVALID")
    return _append_binding(
        state,
        stage=DIGITAL_PROVENANCE_STAGE,
        payload=digital_provenance_hash_payload(state),
    )


def verify_digital_provenance_state(
    state: dict[str, Any],
    *,
    dependencies: FoundationalRequestDependencies,
) -> bool:
    try:
        if not isinstance(dependencies, FoundationalRequestDependencies):
            return False
        trust_context = dependencies.provenance_trust_context
        if not isinstance(trust_context, ProvenanceDeploymentTrustContext):
            return False
        if any(key not in state for key in _PROVENANCE_PROJECTION_KEYS):
            return False
        receipt = state["digital_provenance_verification_receipt"]
        trace = state["digital_provenance_verification_trace"]
        graph = state.get("digital_provenance_graph")
        snapshot = dependencies.provenance_registry_snapshot
        if (
            type(receipt) is not dict
            or type(trace) is not list
            or type(graph) is not dict
            or type(snapshot) is not dict
            or state["digital_provenance_result"] != ADMIT
            or state["digital_provenance_reason"]
            != "PROVENANCE_LINEAGE_AUTHENTICATED_ONLY"
            or state["digital_provenance_digest"] != graph.get("digest")
            or state["digital_provenance_digest"] != receipt.get("graph_digest")
            or state["digital_provenance_lineage_authenticated"] is not True
            or state["digital_provenance_lineage_only"] is not True
            or receipt.get("result") != state["digital_provenance_result"]
            or receipt.get("reason") != state["digital_provenance_reason"]
            or receipt.get("request_fingerprint")
            != state.get("request_fingerprint")
            or receipt.get("release_manifest_digest")
            != state.get("release_manifest_digest")
            or receipt.get("runtime_measurement_digest")
            != state.get("runtime_measurement_digest")
            or receipt.get("registry_snapshot_digest") != snapshot.get("digest")
            or receipt.get("trace_digest") != canonical_integrity_hash(trace)
            or not verify_provenance_verification_receipt(
                receipt,
                trust_context=trust_context,
            )
            or any(
                receipt.get(field) is not expected
                for field, expected in PROVENANCE_NO_AUTHORIZATION_EFFECT.items()
            )
        ):
            return False
        return _unique_binding(
            state,
            stage=DIGITAL_PROVENANCE_STAGE,
            payload=digital_provenance_hash_payload(state),
        ) is not None
    except Exception:
        return False


def _identity_failure(state: dict[str, Any], reason: str) -> dict[str, Any]:
    state["sovereign_identity_result"] = IDENTITY_DENY
    state["sovereign_identity_reason"] = reason
    for field in (
        "sovereign_identity_biometric_proof_established",
        "sovereign_identity_access_granted",
        "sovereign_identity_authority_granted",
        "sovereign_identity_licence_granted",
        "sovereign_identity_execution_authority_granted",
        "sovereign_identity_effect_authority_granted",
    ):
        state[field] = False
    return state


def run_sovereign_identity_stage(
    state: dict[str, Any],
    *,
    dependencies: FoundationalRequestDependencies,
) -> dict[str, Any]:
    target = _state(state)
    try:
        evaluator = (
            dependencies.sovereign_identity_evaluator
            if isinstance(dependencies, FoundationalRequestDependencies)
            else None
        )
        provider = (
            dependencies.sovereign_identity_attestation_provider
            if isinstance(dependencies, FoundationalRequestDependencies)
            else None
        )
        evaluate_sovereign_identity(
            target,
            stage=IDENTITY_ADMISSION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=(
                dependencies.sovereign_identity_trust_context
            ),
            owner_pinned_context_digest=(
                dependencies.sovereign_identity_owner_pinned_context_digest
            ),
        )
        record = target.get("sovereign_identity_record")
        if (
            type(record) is not dict
            or target.get("sovereign_identity_result") != IDENTITY_VERIFIED
        ):
            return target
        _append_binding(
            target,
            stage=IDENTITY_ADMISSION_STAGE,
            payload=sovereign_identity_hash_payload(target),
        )
        if not verify_sovereign_identity(
            target,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=(
                dependencies.sovereign_identity_trust_context
            ),
            owner_pinned_context_digest=(
                dependencies.sovereign_identity_owner_pinned_context_digest
            ),
        ):
            return _identity_failure(
                target, "SOVEREIGN_IDENTITY_POST_BIND_VERIFICATION_FAILED"
            )
        return target
    except Exception:
        return _identity_failure(
            target, "SOVEREIGN_IDENTITY_DEPENDENCY_OR_EVIDENCE_FAILURE"
        )


def _authority_failure(state: dict[str, Any], reason: str) -> dict[str, Any]:
    state["authority_boundary_result"] = BOUNDARY_DENY
    state["authority_boundary_reason"] = reason
    for field in (
        "stakeholder_label_grants_rights",
        "participant_authority_granted",
        "participant_licence_granted",
        "participant_execution_authority_granted",
        "participant_effect_authority_granted",
        "participant_pipeline_bypass_permitted",
    ):
        state[field] = False
    return state


def run_authority_boundary_stage(
    state: dict[str, Any],
    *,
    dependencies: FoundationalRequestDependencies,
) -> dict[str, Any]:
    target = _state(state)
    try:
        evaluator = (
            dependencies.authority_boundary_evaluator
            if isinstance(dependencies, FoundationalRequestDependencies)
            else None
        )
        provider = (
            dependencies.authority_boundary_attestation_provider
            if isinstance(dependencies, FoundationalRequestDependencies)
            else None
        )
        evaluate_authority_boundary(
            target,
            stage="participant_request",
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=(
                dependencies.authority_boundary_trust_context
            ),
            owner_pinned_context_digest=(
                dependencies.authority_boundary_owner_pinned_context_digest
            ),
        )
        record = target.get("authority_boundary_record")
        if (
            type(record) is not dict
            or target.get("authority_boundary_result") != BOUNDARY_PASS
        ):
            return target
        _append_binding(
            target,
            stage=AUTHORITY_BOUNDARY_ADMISSION_STAGE,
            payload=authority_boundary_hash_payload(target),
        )
        if not verify_authority_boundary(
            target,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=(
                dependencies.authority_boundary_trust_context
            ),
            owner_pinned_context_digest=(
                dependencies.authority_boundary_owner_pinned_context_digest
            ),
        ):
            return _authority_failure(
                target, "AUTHORITY_BOUNDARY_POST_BIND_VERIFICATION_FAILED"
            )
        return target
    except Exception:
        return _authority_failure(
            target, "AUTHORITY_BOUNDARY_DEPENDENCY_OR_EVIDENCE_FAILURE"
        )


def _impersonation_failure(
    state: dict[str, Any], reason: str
) -> dict[str, Any]:
    state["impersonation_protection_result"] = IMPERSONATION_DENY
    state["impersonation_protection_reason"] = reason
    for field in (
        "biometric_proof_established",
        "identity_issued",
        "identity_label_grants_access",
        "role_label_grants_authority",
        "mandate_label_grants_authority",
        "access_granted",
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_authority_granted",
        "pipeline_bypass_permitted",
    ):
        state[f"impersonation_{field}"] = False
    return state


def _verify_bound_impersonation(
    state: dict[str, Any],
    *,
    trust_context: Any,
) -> bool:
    """Verify the live component at its recorded pre-binding chain head."""

    try:
        if not verify_hash_chain_entries(
            state.get("hash_chain"), state.get("state_hash")
        ):
            return False
        match = _unique_binding(
            state,
            stage=IMPERSONATION_PROTECTION_STAGE,
            payload=impersonation_protection_hash_payload(state),
        )
        record = state.get("impersonation_protection_record")
        if match is None or type(record) is not dict:
            return False
        index, entry = match
        snapshot = record.get("evaluation_snapshot")
        if (
            type(snapshot) is not dict
            or entry.get("previous_hash")
            != snapshot.get("pre_evaluation_state_hash")
        ):
            return False
        verification_view = deepcopy(state)
        verification_view["hash_chain"] = deepcopy(
            state["hash_chain"][:index]
        )
        verification_view["state_hash"] = entry["previous_hash"]
        return verify_impersonation_protection(
            verification_view, trust_context=trust_context
        )
    except Exception:
        return False


def _append_impersonation_upstream_bindings(
    state: dict[str, Any],
    *,
    trust_context: Any,
) -> None:
    context_record = trust_context.signed_context_record
    if type(context_record) is not dict:
        raise ValueError("IMPERSONATION_CONTEXT_RECORD_INVALID")
    context_id = context_record.get("context_id")
    context_digest = context_record.get("digest")
    if (
        type(context_id) is not str
        or not isinstance(context_digest, str)
        or not is_sha512(context_digest)
    ):
        raise ValueError("IMPERSONATION_CONTEXT_BINDING_INVALID")
    identity_binding = context_record.get("sovereign_identity_verifier")
    authority_binding = context_record.get("authority_boundary_verifier")
    if type(identity_binding) is not dict or type(authority_binding) is not dict:
        raise ValueError("IMPERSONATION_UPSTREAM_BINDING_INVALID")
    identity_stage = identity_binding.get("hash_stage")
    authority_stage = authority_binding.get("hash_stage")
    if (
        type(identity_stage) is not str
        or not identity_stage
        or type(authority_stage) is not str
        or not authority_stage
        or identity_stage == authority_stage
        or identity_stage in FOUNDATIONAL_BASELINE_ORDER
        or authority_stage in FOUNDATIONAL_BASELINE_ORDER
    ):
        raise ValueError("IMPERSONATION_UPSTREAM_STAGE_INVALID")
    if not _chain_valid(state):
        raise ValueError("IMPERSONATION_UPSTREAM_HASH_CHAIN_INVALID")
    chain = state["hash_chain"]
    component_indices: list[int] = []
    for component_stage in (
        IDENTITY_ADMISSION_STAGE,
        AUTHORITY_BOUNDARY_ADMISSION_STAGE,
    ):
        matches = [
            index
            for index, entry in enumerate(chain)
            if type(entry) is dict and entry.get("stage") == component_stage
        ]
        if len(matches) != 1:
            raise ValueError("IMPERSONATION_COMPONENT_BINDING_INVALID")
        component_indices.append(matches[0])
    if component_indices[0] >= component_indices[1]:
        raise ValueError("IMPERSONATION_COMPONENT_ORDER_INVALID")
    if any(
        type(entry) is dict
        and entry.get("stage") in {identity_stage, authority_stage}
        for entry in chain
    ):
        raise ValueError("IMPERSONATION_UPSTREAM_BINDING_ALREADY_PRESENT")
    identity_payload = impersonation_upstream_hash_payload(
        state,
        component_id=SOVEREIGN_IDENTITY_COMPONENT,
        context_id=context_id,
        context_digest=context_digest,
    )
    authority_payload = impersonation_upstream_hash_payload(
        state,
        component_id=AUTHORITY_BOUNDARY_COMPONENT,
        context_id=context_id,
        context_digest=context_digest,
    )
    previous_hash = chain[-1]["hash"] if chain else GENESIS_HASH
    identity_entry = build_hash_chain_entry(
        previous_hash=previous_hash,
        stage=identity_stage,
        payload=identity_payload,
    )
    authority_entry = build_hash_chain_entry(
        previous_hash=identity_entry["hash"],
        stage=authority_stage,
        payload=authority_payload,
    )
    chain.extend((identity_entry, authority_entry))
    state["state_hash"] = authority_entry["hash"]
    if not verify_hash_chain_entries(chain, state["state_hash"]):
        raise ValueError("IMPERSONATION_UPSTREAM_HASH_BINDING_INVALID")


def run_impersonation_stage(
    state: dict[str, Any],
    *,
    dependencies: FoundationalRequestDependencies,
    possession_proof: dict[str, Any] | None,
) -> dict[str, Any]:
    target = _state(state)
    try:
        if not isinstance(dependencies, FoundationalRequestDependencies):
            return _impersonation_failure(
                target, "IMPERSONATION_DEPENDENCIES_MISSING"
            )
        context = dependencies.impersonation_trust_context
        if (
            not verify_sovereign_identity(
                target,
                evaluator=dependencies.sovereign_identity_evaluator,
                attestation_provider=(
                    dependencies.sovereign_identity_attestation_provider
                ),
                attestation_trust_context=(
                    dependencies.sovereign_identity_trust_context
                ),
                owner_pinned_context_digest=(
                    dependencies.sovereign_identity_owner_pinned_context_digest
                ),
            )
            or not verify_authority_boundary(
                target,
                evaluator=dependencies.authority_boundary_evaluator,
                attestation_provider=(
                    dependencies.authority_boundary_attestation_provider
                ),
                attestation_trust_context=(
                    dependencies.authority_boundary_trust_context
                ),
                owner_pinned_context_digest=(
                    dependencies.authority_boundary_owner_pinned_context_digest
                ),
            )
        ):
            return _impersonation_failure(
                target, "IMPERSONATION_UPSTREAM_COMPONENT_INVALID"
            )
        _append_impersonation_upstream_bindings(
            target, trust_context=context
        )
        evaluate_impersonation_protection(
            target,
            possession_proof=deepcopy(possession_proof),
            trust_context=context,
        )
        record = target.get("impersonation_protection_record")
        if (
            type(record) is not dict
            or target.get("impersonation_protection_result")
            != IMPERSONATION_PASS
        ):
            return target
        _append_binding(
            target,
            stage=IMPERSONATION_PROTECTION_STAGE,
            payload=impersonation_protection_hash_payload(target),
        )
        if not _verify_bound_impersonation(target, trust_context=context):
            return _impersonation_failure(
                target, "IMPERSONATION_POST_BIND_VERIFICATION_FAILED"
            )
        return target
    except Exception:
        return _impersonation_failure(
            target, "IMPERSONATION_DEPENDENCY_OR_EVIDENCE_FAILURE"
        )


def run_australian_minor_access_stage(
    state: dict[str, Any],
) -> dict[str, Any]:
    target = _state(state)
    try:
        record = evaluate_australian_minor_access(
            target, stage=AUSTRALIAN_MINOR_ACCESS_STAGE
        )
        if record.get("result") not in {
            RESULT_PASS,
            RESULT_DENY,
            RESULT_NOT_APPLICABLE,
        }:
            return target
        bind_australian_minor_access_hash(target)
        if not verify_australian_minor_access(target):
            raise ValueError("AUSTRALIAN_MINOR_ACCESS_VERIFICATION_FAILED")
        return target
    except Exception:
        existing_record = target.get("australian_minor_access")
        if type(existing_record) is not dict:
            target["australian_minor_access"] = {
                "stage": AUSTRALIAN_MINOR_ACCESS_STAGE,
                "result": "ESCALATE",
                "reason": "AUTHENTICATED_EVIDENCE_UNAVAILABLE",
                "access_granted": False,
                "authority_granted": False,
                "licence_granted": False,
                "execution_authority_granted": False,
                "effect_authority": False,
            }
        return target


def _verify_auxiliary_order(
    state: dict[str, Any],
    *,
    trust_context: Any,
    identity_index: int,
    authority_index: int,
    impersonation_index: int,
) -> bool:
    try:
        context_record = trust_context.signed_context_record
        identity_stage = context_record["sovereign_identity_verifier"][
            "hash_stage"
        ]
        authority_stage = context_record["authority_boundary_verifier"][
            "hash_stage"
        ]
        if (
            identity_stage == authority_stage
            or identity_stage in FOUNDATIONAL_BASELINE_ORDER
            or authority_stage in FOUNDATIONAL_BASELINE_ORDER
        ):
            return False
        chain = state["hash_chain"]
        identity_matches = [
            index
            for index, entry in enumerate(chain)
            if entry.get("stage") == identity_stage
        ]
        authority_matches = [
            index
            for index, entry in enumerate(chain)
            if entry.get("stage") == authority_stage
        ]
        return (
            len(identity_matches) == 1
            and len(authority_matches) == 1
            and identity_index < identity_matches[0] < impersonation_index
            and authority_index < authority_matches[0] < impersonation_index
            and identity_matches[0] < authority_matches[0]
        )
    except Exception:
        return False


def verify_foundational_request_controls(
    state: dict[str, Any],
    *,
    dependencies: FoundationalRequestDependencies,
) -> bool:
    try:
        if (
            type(state) is not dict
            or not isinstance(dependencies, FoundationalRequestDependencies)
            or tuple(FOUNDATIONAL_BASELINE_ORDER) != _CONTROL_STAGES
            or not verify_hash_chain_entries(
                state.get("hash_chain"), state.get("state_hash")
            )
            or not verify_digital_provenance_state(
                state, dependencies=dependencies
            )
            or not verify_sovereign_identity(
                state,
                evaluator=dependencies.sovereign_identity_evaluator,
                attestation_provider=(
                    dependencies.sovereign_identity_attestation_provider
                ),
                attestation_trust_context=(
                    dependencies.sovereign_identity_trust_context
                ),
                owner_pinned_context_digest=(
                    dependencies.sovereign_identity_owner_pinned_context_digest
                ),
            )
            or not verify_authority_boundary(
                state,
                evaluator=dependencies.authority_boundary_evaluator,
                attestation_provider=(
                    dependencies.authority_boundary_attestation_provider
                ),
                attestation_trust_context=(
                    dependencies.authority_boundary_trust_context
                ),
                owner_pinned_context_digest=(
                    dependencies.authority_boundary_owner_pinned_context_digest
                ),
            )
            or not _verify_bound_impersonation(
                state,
                trust_context=dependencies.impersonation_trust_context,
            )
            or not verify_australian_minor_access(state)
        ):
            return False
        chain = state["hash_chain"]
        indices: list[int] = []
        for stage in FOUNDATIONAL_BASELINE_ORDER:
            matches = [
                index
                for index, entry in enumerate(chain)
                if type(entry) is dict and entry.get("stage") == stage
            ]
            if len(matches) != 1:
                return False
            indices.append(matches[0])
        if indices != sorted(indices) or len(indices) != len(set(indices)):
            return False
        if not _verify_auxiliary_order(
            state,
            trust_context=dependencies.impersonation_trust_context,
            identity_index=indices[1],
            authority_index=indices[2],
            impersonation_index=indices[3],
        ):
            return False
        results = (
            state.get("digital_provenance_result"),
            state.get("sovereign_identity_result"),
            state.get("authority_boundary_result"),
            state.get("impersonation_protection_result"),
            state.get("australian_minor_access", {}).get("result"),
        )
        return (
            results[0] == ADMIT
            and results[1] == IDENTITY_VERIFIED
            and results[2] == BOUNDARY_PASS
            and results[3] == IMPERSONATION_PASS
            and results[4]
            in {RESULT_PASS, RESULT_DENY, RESULT_NOT_APPLICABLE}
            and "ALLOW" not in results
        )
    except Exception:
        return False


__all__ = [
    "FoundationalRequestDependencies",
    "bind_digital_provenance_hash",
    "digital_provenance_hash_payload",
    "run_australian_minor_access_stage",
    "run_authority_boundary_stage",
    "run_digital_provenance_stage",
    "run_impersonation_stage",
    "run_sovereign_identity_stage",
    "verify_digital_provenance_state",
    "verify_foundational_request_controls",
]
