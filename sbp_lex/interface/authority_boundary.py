from __future__ import annotations

"""Authenticated participant/request boundary for SBP-LEX V2.

This is an IMPLEMENTATION-DEFINED V2 MECHANICAL CONTRACT for filed Claim 20.
It is not a filed participant, mandate, identity, or authorization schema.
Stakeholder class is descriptive only and never grants rights or authority.
"""

from copy import deepcopy
from typing import Any, Final, Protocol

from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)
from sbp_lex.security.signature_provider import (
    HybridVerificationContext,
    SignatureProvider,
    verify_signed_object,
)


AUTHORITY_BOUNDARY_CONTRACT_ID: Final = (
    "SBP_LEX_AUTHORITY_BOUNDED_PARTICIPANT_V2"
)
AUTHORITY_BOUNDARY_SCHEMA_STATUS: Final = (
    "IMPLEMENTATION_DEFINED_V2_MECHANICS"
)
AUTHORITY_BOUNDARY_EVALUATOR_ROLE: Final = (
    "AUTHORITY_BOUNDED_PARTICIPANT_EVALUATOR"
)
AUTHORITY_BOUNDARY_HASH_STAGE_PREFIX: Final = "authority_boundary:"

STAKEHOLDER_CLASSES: Final = (
    "governments",
    "regulators",
    "corporations",
    "NGOs",
    "treaty bodies",
)
AUTHORITY_BOUNDARY_EVIDENCE_CLASSES: Final = (
    "participant_identity",
    "mandate",
    "jurisdiction",
    "request_boundary",
)

BOUNDARY_PASS: Final = "BOUNDARY_PASS"
BOUNDARY_DENY: Final = "BOUNDARY_DENY"
PARTICIPANT_ACTIVE: Final = "ACTIVE"
PARTICIPANT_REVOKED: Final = "REVOKED"
PARTICIPANT_INDETERMINATE: Final = "INDETERMINATE"
MANDATE_ACTIVE: Final = "ACTIVE"
MANDATE_REVOKED: Final = "REVOKED"
MANDATE_EXPIRED: Final = "EXPIRED"
MANDATE_INDETERMINATE: Final = "INDETERMINATE"

_SOURCE_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_boundary_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}
_SNAPSHOT_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "stakeholder_classes",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_boundary_digest",
    "participant_id",
    "stakeholder_class",
    "requested_action",
    "requested_jurisdiction",
}
_DETERMINATION_FIELDS: Final = {
    "result",
    "participant_id",
    "stakeholder_class",
    "participant_status",
    "mandate_id",
    "mandate_status",
    "mandate_valid_from",
    "mandate_valid_until",
    "mandate_actions",
    "mandate_jurisdictions",
    "requested_action",
    "requested_jurisdiction",
    "evidence_references",
    "stakeholder_label_grants_rights",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
}
_RECORD_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "stakeholder_classes",
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "evidence_references",
    "stakeholder_label_grants_rights",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
}


class AuthorityBoundaryEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate_authority_boundary(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]: ...


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _text_list(value: Any) -> bool:
    return (
        type(value) is list
        and bool(value)
        and all(_text(item) for item in value)
        and len(value) == len(set(value))
    )


def _state_hash_exact(value: Any) -> bool:
    return value == GENESIS_HASH or is_sha512(value)


def _provider_admitted(provider: SignatureProvider | None) -> bool:
    return (
        provider is not None
        and getattr(provider, "interface_attestation_admitted", None) is True
    )


def _evaluator_contract_exact(evaluator: Any) -> bool:
    metadata = (
        getattr(evaluator, "evaluator_id", None),
        getattr(evaluator, "evaluator_version", None),
        getattr(evaluator, "authority_role", None),
        getattr(evaluator, "authority_credential_id", None),
    )
    return (
        all(_text(value) for value in metadata)
        and metadata[2] == AUTHORITY_BOUNDARY_EVALUATOR_ROLE
        and callable(getattr(evaluator, "evaluate_authority_boundary", None))
    )


def _snapshot(
    state: dict[str, Any],
    *,
    stage: str,
    sequence: int,
) -> dict[str, Any]:
    return {
        "contract_id": AUTHORITY_BOUNDARY_CONTRACT_ID,
        "schema_status": AUTHORITY_BOUNDARY_SCHEMA_STATUS,
        "stakeholder_classes": list(STAKEHOLDER_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": state.get("request_fingerprint"),
        "pre_evaluation_state_hash": state.get("state_hash") or GENESIS_HASH,
        "evaluation_time": state.get("evaluation_time"),
        "prior_boundary_digest": state.get("authority_boundary_digest"),
        "participant_id": deepcopy(state.get("participant_id")),
        "stakeholder_class": deepcopy(state.get("stakeholder_class")),
        "requested_action": deepcopy(state.get("action")),
        "requested_jurisdiction": deepcopy(
            state.get("requested_jurisdiction")
        ),
    }


def _snapshot_exact(snapshot: Any) -> bool:
    return (
        type(snapshot) is dict
        and set(snapshot) == _SNAPSHOT_FIELDS
        and snapshot.get("contract_id") == AUTHORITY_BOUNDARY_CONTRACT_ID
        and snapshot.get("schema_status") == AUTHORITY_BOUNDARY_SCHEMA_STATUS
        and snapshot.get("stakeholder_classes") == list(STAKEHOLDER_CLASSES)
        and _text(snapshot.get("stage"))
        and type(snapshot.get("evaluation_sequence")) is int
        and snapshot["evaluation_sequence"] >= 1
        and is_sha512(snapshot.get("request_fingerprint"))
        and _state_hash_exact(snapshot.get("pre_evaluation_state_hash"))
        and type(snapshot.get("evaluation_time")) is int
        and snapshot["evaluation_time"] >= 0
        and (
            snapshot.get("prior_boundary_digest") is None
            or is_sha512(snapshot.get("prior_boundary_digest"))
        )
        and _text(snapshot.get("participant_id"))
        and snapshot.get("stakeholder_class") in STAKEHOLDER_CLASSES
        and _text(snapshot.get("requested_action"))
        and _text(snapshot.get("requested_jurisdiction"))
    )


def _evidence_references_exact(references: Any) -> bool:
    if type(references) is not list or len(references) != len(
        AUTHORITY_BOUNDARY_EVIDENCE_CLASSES
    ):
        return False
    observed_classes = [
        reference.get("evidence_class")
        if type(reference) is dict
        else None
        for reference in references
    ]
    if observed_classes != list(AUTHORITY_BOUNDARY_EVIDENCE_CLASSES):
        return False
    evidence_ids: set[str] = set()
    for reference in references:
        if type(reference) is not dict or set(reference) != {
            "evidence_class",
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        evidence_id = reference.get("evidence_id")
        if not _text(evidence_id) or evidence_id in evidence_ids:
            return False
        evidence_ids.add(evidence_id)
        if not _text(reference.get("source")):
            return False
        if not is_sha512(reference.get("digest")):
            return False
    return True


def _determination_error(
    determination: Any,
    snapshot: dict[str, Any],
) -> str | None:
    if type(determination) is not dict or set(determination) != (
        _DETERMINATION_FIELDS
    ):
        return "AUTHORITY_BOUNDARY_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in {BOUNDARY_PASS, BOUNDARY_DENY}:
        return "AUTHORITY_BOUNDARY_RESULT_INVALID"
    if determination.get("participant_id") != snapshot.get("participant_id"):
        return "AUTHORITY_BOUNDARY_PARTICIPANT_BINDING_MISMATCH"
    if determination.get("stakeholder_class") != snapshot.get(
        "stakeholder_class"
    ):
        return "AUTHORITY_BOUNDARY_STAKEHOLDER_BINDING_MISMATCH"
    if determination.get("requested_action") != snapshot.get(
        "requested_action"
    ):
        return "AUTHORITY_BOUNDARY_ACTION_BINDING_MISMATCH"
    if determination.get("requested_jurisdiction") != snapshot.get(
        "requested_jurisdiction"
    ):
        return "AUTHORITY_BOUNDARY_JURISDICTION_BINDING_MISMATCH"
    if determination.get("participant_status") not in {
        PARTICIPANT_ACTIVE,
        PARTICIPANT_REVOKED,
        PARTICIPANT_INDETERMINATE,
    }:
        return "AUTHORITY_BOUNDARY_PARTICIPANT_STATUS_INVALID"
    if not _text(determination.get("mandate_id")):
        return "AUTHORITY_BOUNDARY_MANDATE_ID_INVALID"
    if determination.get("mandate_status") not in {
        MANDATE_ACTIVE,
        MANDATE_REVOKED,
        MANDATE_EXPIRED,
        MANDATE_INDETERMINATE,
    }:
        return "AUTHORITY_BOUNDARY_MANDATE_STATUS_INVALID"
    valid_from = determination.get("mandate_valid_from")
    valid_until = determination.get("mandate_valid_until")
    if (
        type(valid_from) is not int
        or type(valid_until) is not int
        or valid_from < 0
        or valid_until <= valid_from
    ):
        return "AUTHORITY_BOUNDARY_MANDATE_TIME_INVALID"
    actions = determination.get("mandate_actions")
    jurisdictions = determination.get("mandate_jurisdictions")
    if not _text_list(actions):
        return "AUTHORITY_BOUNDARY_MANDATE_ACTIONS_INVALID"
    if not _text_list(jurisdictions):
        return "AUTHORITY_BOUNDARY_MANDATE_JURISDICTIONS_INVALID"
    if not _evidence_references_exact(
        determination.get("evidence_references")
    ):
        return "AUTHORITY_BOUNDARY_EVIDENCE_CONTRACT_INVALID"
    false_flags = (
        "stakeholder_label_grants_rights",
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_authority_granted",
        "pipeline_bypass_permitted",
    )
    if any(determination.get(field) is not False for field in false_flags):
        return "AUTHORITY_BOUNDARY_INDEPENDENT_AUTHORITY_PROHIBITED"

    evaluation_time = snapshot.get("evaluation_time")
    mandate_active_now = (
        determination["participant_status"] == PARTICIPANT_ACTIVE
        and determination["mandate_status"] == MANDATE_ACTIVE
        and valid_from <= evaluation_time < valid_until
        and snapshot["requested_action"] in actions
        and snapshot["requested_jurisdiction"] in jurisdictions
    )
    if determination["result"] == BOUNDARY_PASS and not mandate_active_now:
        return "AUTHORITY_BOUNDARY_PASS_WITHOUT_ACTIVE_MANDATE"
    return None


def _common_error(
    source: Any,
    *,
    snapshot: dict[str, Any],
    evaluator: AuthorityBoundaryEvaluator,
    provider: SignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    if not _provider_admitted(provider):
        return "AUTHORITY_BOUNDARY_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if not _evaluator_contract_exact(evaluator):
        return "AUTHORITY_BOUNDARY_EVALUATOR_CONTRACT_INVALID"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return "AUTHORITY_BOUNDARY_EVALUATOR_RESULT_SHAPE_INVALID"
    if not verify_signed_object(
        source,
        provider=None,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        allow_legacy_non_effect=False,
    ):
        return "AUTHORITY_BOUNDARY_ATTESTATION_INVALID"
    if source.get("contract_id") != AUTHORITY_BOUNDARY_CONTRACT_ID:
        return "AUTHORITY_BOUNDARY_CONTRACT_ID_INVALID"
    if source.get("schema_status") != AUTHORITY_BOUNDARY_SCHEMA_STATUS:
        return "AUTHORITY_BOUNDARY_SCHEMA_STATUS_INVALID"
    if source.get("evaluator_id") != getattr(evaluator, "evaluator_id", None):
        return "AUTHORITY_BOUNDARY_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != getattr(
        evaluator, "evaluator_version", None
    ):
        return "AUTHORITY_BOUNDARY_EVALUATOR_VERSION_MISMATCH"
    if source.get("authority_credential") != {
        "credential_id": getattr(
            evaluator, "authority_credential_id", None
        ),
        "authority_role": AUTHORITY_BOUNDARY_EVALUATOR_ROLE,
    }:
        return "AUTHORITY_BOUNDARY_CREDENTIAL_INVALID"
    bindings = {
        "stage": snapshot.get("stage"),
        "evaluation_sequence": snapshot.get("evaluation_sequence"),
        "request_fingerprint": snapshot.get("request_fingerprint"),
        "pre_evaluation_state_hash": snapshot.get(
            "pre_evaluation_state_hash"
        ),
        "evaluation_time": snapshot.get("evaluation_time"),
        "prior_boundary_digest": snapshot.get("prior_boundary_digest"),
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in bindings.items()):
        return "AUTHORITY_BOUNDARY_EVALUATION_BINDING_MISMATCH"
    return _determination_error(source.get("determination"), snapshot)


def _deny_state(state: dict[str, Any], reason: str) -> dict[str, Any]:
    state["authority_boundary_result"] = BOUNDARY_DENY
    state["authority_boundary_reason"] = reason
    state["stakeholder_label_grants_rights"] = False
    state["participant_authority_granted"] = False
    state["participant_licence_granted"] = False
    state["participant_execution_authority_granted"] = False
    state["participant_effect_authority_granted"] = False
    state["participant_pipeline_bypass_permitted"] = False
    return state


def evaluate_authority_boundary(
    state: dict[str, Any],
    *,
    stage: str,
    evaluator: AuthorityBoundaryEvaluator | None,
    attestation_provider: SignatureProvider | None,
    attestation_trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> dict[str, Any]:
    """Evaluate one signed participant/request boundary fail closed."""

    trace = state.setdefault("authority_boundary_trace", [])
    if type(trace) is not list:
        return _deny_state(state, "AUTHORITY_BOUNDARY_TRACE_INVALID")
    sequence = len(trace) + 1
    snapshot = _snapshot(state, stage=stage, sequence=sequence)
    source: dict[str, Any] | None = None
    error: str | None = None

    if not _snapshot_exact(snapshot):
        error = "AUTHORITY_BOUNDARY_SNAPSHOT_INVALID"
    elif trace:
        expected_prior = _safe_hash(trace[-1])
        if (
            expected_prior is None
            or state.get("authority_boundary_digest") != expected_prior
        ):
            error = "AUTHORITY_BOUNDARY_PRIOR_DIGEST_STATE_INVALID"
    elif state.get("authority_boundary_digest") is not None:
        error = "AUTHORITY_BOUNDARY_UNEXPECTED_PRIOR_DIGEST"

    if error is None and evaluator is None:
        error = "AUTHORITY_BOUNDARY_EVALUATOR_NOT_INJECTED"
    if error is None:
        method = getattr(evaluator, "evaluate_authority_boundary", None)
        if not _evaluator_contract_exact(evaluator):
            error = "AUTHORITY_BOUNDARY_EVALUATOR_CONTRACT_INVALID"
        elif not _provider_admitted(attestation_provider):
            error = "AUTHORITY_BOUNDARY_PROVIDER_NOT_INJECTED_OR_ADMITTED"
        else:
            try:
                source = method(stage=stage, snapshot=deepcopy(snapshot))
            except Exception as exc:
                error = (
                    "AUTHORITY_BOUNDARY_EVALUATOR_ERROR:"
                    f"{type(exc).__name__}:{exc}"
                )
            if error is None:
                error = _common_error(
                    source,
                    snapshot=snapshot,
                    evaluator=evaluator,
                    provider=attestation_provider,
                    trust_context=attestation_trust_context,
                    owner_pinned_context_digest=owner_pinned_context_digest,
                )

    result = (
        source["determination"]["result"]
        if error is None and source is not None
        else BOUNDARY_DENY
    )
    reason = error or "AUTHORITY_BOUNDARY_EVALUATION_COMPLETED"
    evidence_references = (
        deepcopy(source["determination"]["evidence_references"])
        if error is None and source is not None
        else []
    )
    record = {
        "contract_id": AUTHORITY_BOUNDARY_CONTRACT_ID,
        "schema_status": AUTHORITY_BOUNDARY_SCHEMA_STATUS,
        "stakeholder_classes": list(STAKEHOLDER_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "evidence_references": evidence_references,
        "stakeholder_label_grants_rights": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }
    trace.append(record)
    state["authority_boundary_record"] = deepcopy(record)
    state["authority_boundary_digest"] = canonical_integrity_hash(record)
    state["authority_boundary_trace_digest"] = canonical_integrity_hash(trace)
    state["authority_boundary_result"] = result
    state["authority_boundary_reason"] = reason
    state["stakeholder_label_grants_rights"] = False
    state["participant_authority_granted"] = False
    state["participant_licence_granted"] = False
    state["participant_execution_authority_granted"] = False
    state["participant_effect_authority_granted"] = False
    state["participant_pipeline_bypass_permitted"] = False
    return state


def _record_hash_payload(
    record: dict[str, Any],
    *,
    trace_digest: str | None,
) -> dict[str, Any]:
    return {
        "contract_id": AUTHORITY_BOUNDARY_CONTRACT_ID,
        "schema_status": AUTHORITY_BOUNDARY_SCHEMA_STATUS,
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "record_digest": _safe_hash(record),
        "trace_digest": trace_digest,
        "stakeholder_label_grants_rights": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }


def authority_boundary_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    record = state.get("authority_boundary_record")
    if type(record) is not dict:
        record = {}
    return _record_hash_payload(
        record,
        trace_digest=state.get("authority_boundary_trace_digest"),
    )


def verify_authority_boundary(
    state: dict[str, Any],
    *,
    evaluator: AuthorityBoundaryEvaluator | None,
    attestation_provider: SignatureProvider | None,
    attestation_trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
    require_hash_binding: bool = True,
) -> bool:
    """Verify the complete current boundary trace and chain fail closed."""

    try:
        trace = state.get("authority_boundary_trace")
        latest = state.get("authority_boundary_record")
        state_false_flags = (
            "stakeholder_label_grants_rights",
            "participant_authority_granted",
            "participant_licence_granted",
            "participant_execution_authority_granted",
            "participant_effect_authority_granted",
            "participant_pipeline_bypass_permitted",
        )
        if (
            evaluator is None
            or type(trace) is not list
            or not trace
            or type(latest) is not dict
            or latest != trace[-1]
            or state.get("authority_boundary_result") != BOUNDARY_PASS
            or state.get("authority_boundary_reason")
            != "AUTHORITY_BOUNDARY_EVALUATION_COMPLETED"
            or any(state.get(field) is not False for field in state_false_flags)
            or state.get("authority_boundary_digest") != _safe_hash(latest)
            or state.get("authority_boundary_trace_digest")
            != _safe_hash(trace)
        ):
            return False

        prior_digest: str | None = None
        record_false_flags = (
            "stakeholder_label_grants_rights",
            "authority_granted",
            "licence_granted",
            "execution_authority_granted",
            "effect_authority_granted",
            "pipeline_bypass_permitted",
        )
        for sequence, record in enumerate(trace, start=1):
            if type(record) is not dict or set(record) != _RECORD_FIELDS:
                return False
            snapshot = record.get("evaluation_snapshot")
            source = record.get("evaluation_source")
            if (
                record.get("contract_id") != AUTHORITY_BOUNDARY_CONTRACT_ID
                or record.get("schema_status")
                != AUTHORITY_BOUNDARY_SCHEMA_STATUS
                or record.get("stakeholder_classes")
                != list(STAKEHOLDER_CLASSES)
                or record.get("evaluation_sequence") != sequence
                or record.get("result") != BOUNDARY_PASS
                or record.get("reason")
                != "AUTHORITY_BOUNDARY_EVALUATION_COMPLETED"
                or any(
                    record.get(field) is not False
                    for field in record_false_flags
                )
                or not _snapshot_exact(snapshot)
                or snapshot.get("stage") != record.get("stage")
                or snapshot.get("evaluation_sequence") != sequence
                or snapshot.get("prior_boundary_digest") != prior_digest
                or record.get("evaluation_snapshot_digest")
                != _safe_hash(snapshot)
                or record.get("evaluation_source_digest") != _safe_hash(source)
                or _common_error(
                    source,
                    snapshot=snapshot,
                    evaluator=evaluator,
                    provider=attestation_provider,
                    trust_context=attestation_trust_context,
                    owner_pinned_context_digest=owner_pinned_context_digest,
                )
                is not None
                or record.get("evidence_references")
                != source["determination"]["evidence_references"]
            ):
                return False
            prior_digest = _safe_hash(record)
            if prior_digest is None:
                return False

        latest_snapshot = latest["evaluation_snapshot"]
        live_bindings = {
            "request_fingerprint": state.get("request_fingerprint"),
            "evaluation_time": state.get("evaluation_time"),
            "participant_id": state.get("participant_id"),
            "stakeholder_class": state.get("stakeholder_class"),
            "requested_action": state.get("action"),
            "requested_jurisdiction": state.get("requested_jurisdiction"),
        }
        if any(
            latest_snapshot.get(field) != value
            for field, value in live_bindings.items()
        ):
            return False
        if not require_hash_binding:
            return True

        chain = state.get("hash_chain")
        if not verify_hash_chain_entries(chain, state.get("state_hash")):
            return False
        previous_index = -1
        for sequence, record in enumerate(trace, start=1):
            payload = _record_hash_payload(
                record,
                trace_digest=_safe_hash(trace[:sequence]),
            )
            expected_stage = (
                f"{AUTHORITY_BOUNDARY_HASH_STAGE_PREFIX}{record['stage']}"
            )
            expected_payload_hash = _safe_hash(payload)
            matches = [
                (index, entry)
                for index, entry in enumerate(chain)
                if entry.get("stage") == expected_stage
                and entry.get("payload_hash") == expected_payload_hash
            ]
            if (
                len(matches) != 1
                or matches[0][0] <= previous_index
                or matches[0][1].get("previous_hash")
                != record["evaluation_snapshot"][
                    "pre_evaluation_state_hash"
                ]
            ):
                return False
            previous_index = matches[0][0]
        return True
    except (IntegrityContractError, KeyError, TypeError, ValueError):
        return False
