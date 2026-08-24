from __future__ import annotations

"""Non-self-admitting authority provenance for SBP-LEX V2.

This implementation-defined contract authenticates externally supplied
authority, jurisdiction, classification, and policy determinations.  It does
not define or infer any of those semantics and never grants authority.
"""

from copy import deepcopy
from typing import Any, Final

from sbp_lex.security.authority_trust import (
    AUTHORITY_TRUST_ROLE_BOUNDARY,
    AUTHORITY_TRUST_ROLE_IDENTITY,
    AUTHORITY_TRUST_ROLE_PROVENANCE,
    AuthorityProvenanceDependencies,
    authority_trust_evidence_still_current,
    current_authority_trust_evidence,
    resolve_authority_trust_boundary,
    verify_pinned_signed_object,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)


AUTHORITY_PROVENANCE_CONTRACT_ID: Final = "SBP_LEX_AUTHORITY_PROVENANCE_V2"
AUTHORITY_PROVENANCE_SCHEMA_STATUS: Final = (
    "IMPLEMENTATION_DEFINED_V2_MECHANICS"
)
AUTHORITY_PROVENANCE_STAGE: Final = "authority_provenance:admission"
AUTHORITY_PROVENANCE_HASH_STAGE_PREFIX: Final = "authority_provenance:"
AUTHORITY_PROVENANCE_PASS: Final = "PASS"
AUTHORITY_PROVENANCE_DENY: Final = "DENY"

AUTHORITY_PROVENANCE_EVIDENCE_CLASSES: Final = (
    "authority_resolution",
    "jurisdiction_resolution",
    "classification_rule_set",
    "policy_artifact",
)

_NO_AUTHORITY_FIELDS: Final = (
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
    "downstream_override_permitted",
)
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
    "prior_provenance_digest",
    "trust_context_digest",
    "clock_receipt_digest",
    "registry_head_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}
_DETERMINATION_FIELDS: Final = {
    "result",
    "participant_id",
    "mandate_id",
    "requested_action",
    "resolved_authority",
    "resolved_jurisdiction",
    "classification",
    "policy",
    "evidence_references",
    *_NO_AUTHORITY_FIELDS,
}
_AUTHORITY_FIELDS: Final = {"authority_id", "evidence_digest"}
_JURISDICTION_FIELDS: Final = {"jurisdiction_id", "evidence_digest"}
_CLASSIFICATION_FIELDS: Final = {
    "taxonomy_id",
    "rule_set_id",
    "rule_set_version",
    "rule_set_digest",
    "class_id",
    "subclass_id",
}
_POLICY_FIELDS: Final = {
    "policy_id",
    "policy_version",
    "policy_digest",
    "status",
    "effective_from",
    "effective_until",
    "permitted_actions",
    "restricted_actions",
}
_RECORD_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "trust_context_digest",
    "clock_receipt_digest",
    "registry_head_digest",
    "resolved_authority",
    "resolved_jurisdiction",
    "classification",
    "policy",
    "evidence_references",
    *_NO_AUTHORITY_FIELDS,
}


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _false_flags() -> dict[str, bool]:
    return {field: False for field in _NO_AUTHORITY_FIELDS}


def _submitted_claims(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "authority_claim": deepcopy(state.get("submitted_authority_claim")),
        "requested_jurisdiction": deepcopy(
            state.get("requested_jurisdiction")
        ),
        "classification_claim": {
            "class_id": deepcopy(state.get("submitted_ap_acf_class")),
            "subclass_id": deepcopy(
                state.get("submitted_ap_acf_subclass")
            ),
        },
        "policy_artifact": deepcopy(state.get("submitted_policy_artifact")),
    }


def _upstream_record_exact(
    state: dict[str, Any],
    *,
    record_field: str,
    trace_field: str,
    digest_field: str,
    result_field: str,
    expected_result: str,
    role: str,
    dependencies: AuthorityProvenanceDependencies,
) -> tuple[dict[str, Any], str, str] | None:
    boundary = resolve_authority_trust_boundary(dependencies)
    pin = boundary.context.role_pin(role) if boundary else None
    record = state.get(record_field)
    trace = state.get(trace_field)
    digest = state.get(digest_field)
    source = record.get("evaluation_source") if type(record) is dict else None
    if (
        pin is None
        or type(record) is not dict
        or type(trace) is not list
        or not trace
        or record != trace[-1]
        or state.get(result_field) != expected_result
        or not is_sha512(digest)
        or not verify_pinned_signed_object(source, role_pin=pin)
        or source.get("evaluator_id") != pin.evaluator_id
        or source.get("evaluator_version") != pin.evaluator_version
    ):
        return None
    credential = source.get("issuer_credential")
    if role == AUTHORITY_TRUST_ROLE_BOUNDARY:
        credential = source.get("authority_credential")
    if (
        type(credential) is not dict
        or credential.get("credential_id") != pin.authority_credential_id
        or any(record.get(field) is not False for field in _NO_AUTHORITY_FIELDS if field in record)
    ):
        return None
    trace_digest = _safe_hash(trace)
    record_digest = _safe_hash(record)
    if trace_digest is None or record_digest is None:
        return None
    expected_state_digest = (
        trace_digest
        if role == AUTHORITY_TRUST_ROLE_IDENTITY
        else record_digest
    )
    if digest != expected_state_digest:
        return None
    if (
        role == AUTHORITY_TRUST_ROLE_BOUNDARY
        and state.get("authority_boundary_trace_digest") != trace_digest
    ):
        return None
    return record, record_digest, trace_digest


def _snapshot(
    state: dict[str, Any],
    *,
    dependencies: AuthorityProvenanceDependencies,
    sequence: int,
    clock_receipt: dict[str, Any],
    registry_head: dict[str, Any],
) -> dict[str, Any] | None:
    identity = _upstream_record_exact(
        state,
        record_field="sovereign_identity_record",
        trace_field="sovereign_identity_trace",
        digest_field="sovereign_identity_digest",
        result_field="sovereign_identity_result",
        expected_result="VERIFIED",
        role=AUTHORITY_TRUST_ROLE_IDENTITY,
        dependencies=dependencies,
    )
    authority = _upstream_record_exact(
        state,
        record_field="authority_boundary_record",
        trace_field="authority_boundary_trace",
        digest_field="authority_boundary_digest",
        result_field="authority_boundary_result",
        expected_result="BOUNDARY_PASS",
        role=AUTHORITY_TRUST_ROLE_BOUNDARY,
        dependencies=dependencies,
    )
    boundary = resolve_authority_trust_boundary(dependencies)
    request_fingerprint = state.get("request_fingerprint")
    state_hash = state.get("state_hash") or GENESIS_HASH
    foundational_digest = state.get("foundational_baseline_digest")
    claims = _submitted_claims(state)
    if (
        identity is None
        or authority is None
        or boundary is None
        or not is_sha512(request_fingerprint)
        or not is_sha512(state_hash)
        or not is_sha512(foundational_digest)
        or not _text(claims.get("requested_jurisdiction"))
        or type(claims.get("policy_artifact")) is not dict
        or not claims["policy_artifact"]
        or clock_receipt.get("observed_at")
        != authority[0].get("evaluation_snapshot", {}).get("evaluation_time")
        or clock_receipt.get("observed_at")
        != identity[0].get("evaluation_time")
    ):
        return None
    prior_digest = state.get("authority_provenance_digest")
    if prior_digest is not None and not is_sha512(prior_digest):
        return None
    return {
        "contract_id": AUTHORITY_PROVENANCE_CONTRACT_ID,
        "schema_status": AUTHORITY_PROVENANCE_SCHEMA_STATUS,
        "stage": AUTHORITY_PROVENANCE_STAGE,
        "evaluation_sequence": sequence,
        "request_fingerprint": request_fingerprint,
        "pre_evaluation_state_hash": state_hash,
        "evaluation_time": clock_receipt["observed_at"],
        "prior_provenance_digest": prior_digest,
        "trust_context_digest": boundary.context.context_digest,
        "clock_receipt": deepcopy(clock_receipt),
        "clock_receipt_digest": _safe_hash(clock_receipt),
        "registry_head": deepcopy(registry_head),
        "registry_head_digest": _safe_hash(registry_head),
        "foundational_baseline_digest": foundational_digest,
        "sovereign_identity_record_digest": identity[1],
        "sovereign_identity_trace_digest": identity[2],
        "authority_boundary_record_digest": authority[1],
        "authority_boundary_trace_digest": authority[2],
        "participant_id": deepcopy(state.get("participant_id")),
        "mandate_id": deepcopy(state.get("participant_mandate_id")),
        "requested_action": deepcopy(state.get("action")),
        "submitted_claims": claims,
    }


def _text_list(value: Any) -> bool:
    return (
        type(value) is list
        and all(_text(item) for item in value)
        and len(value) == len(set(value))
    )


def _evidence_exact(value: Any) -> bool:
    if type(value) is not list or len(value) != len(
        AUTHORITY_PROVENANCE_EVIDENCE_CLASSES
    ):
        return False
    if [
        item.get("evidence_class") if type(item) is dict else None
        for item in value
    ] != list(AUTHORITY_PROVENANCE_EVIDENCE_CLASSES):
        return False
    ids: set[str] = set()
    for item in value:
        if type(item) is not dict or set(item) != {
            "evidence_class",
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        if (
            not _text(item.get("evidence_id"))
            or item["evidence_id"] in ids
            or not _text(item.get("source"))
            or not is_sha512(item.get("digest"))
        ):
            return False
        ids.add(item["evidence_id"])
    return True


def _determination_error(
    value: Any, *, snapshot: dict[str, Any]
) -> str | None:
    if type(value) is not dict or set(value) != _DETERMINATION_FIELDS:
        return "AUTHORITY_PROVENANCE_DETERMINATION_SHAPE_INVALID"
    if value.get("result") not in {
        AUTHORITY_PROVENANCE_PASS,
        AUTHORITY_PROVENANCE_DENY,
    }:
        return "AUTHORITY_PROVENANCE_RESULT_INVALID"
    if any(value.get(field) is not False for field in _NO_AUTHORITY_FIELDS):
        return "AUTHORITY_PROVENANCE_INDEPENDENT_AUTHORITY_PROHIBITED"
    if (
        value.get("participant_id") != snapshot.get("participant_id")
        or value.get("mandate_id") != snapshot.get("mandate_id")
        or value.get("requested_action") != snapshot.get("requested_action")
    ):
        return "AUTHORITY_PROVENANCE_REQUEST_SCOPE_MISMATCH"
    resolved_authority = value.get("resolved_authority")
    resolved_jurisdiction = value.get("resolved_jurisdiction")
    classification = value.get("classification")
    policy = value.get("policy")
    if (
        type(resolved_authority) is not dict
        or set(resolved_authority) != _AUTHORITY_FIELDS
        or not _text(resolved_authority.get("authority_id"))
        or not is_sha512(resolved_authority.get("evidence_digest"))
    ):
        return "AUTHORITY_PROVENANCE_AUTHORITY_INVALID"
    if (
        type(resolved_jurisdiction) is not dict
        or set(resolved_jurisdiction) != _JURISDICTION_FIELDS
        or not _text(resolved_jurisdiction.get("jurisdiction_id"))
        or not is_sha512(resolved_jurisdiction.get("evidence_digest"))
        or resolved_jurisdiction.get("jurisdiction_id")
        != snapshot["submitted_claims"]["requested_jurisdiction"]
    ):
        return "AUTHORITY_PROVENANCE_JURISDICTION_INVALID"
    if (
        type(classification) is not dict
        or set(classification) != _CLASSIFICATION_FIELDS
        or not all(
            _text(classification.get(field))
            for field in (
                "taxonomy_id",
                "rule_set_id",
                "rule_set_version",
                "class_id",
            )
        )
        or (
            classification.get("subclass_id") is not None
            and not _text(classification.get("subclass_id"))
        )
        or not is_sha512(classification.get("rule_set_digest"))
    ):
        return "AUTHORITY_PROVENANCE_CLASSIFICATION_INVALID"
    if (
        type(policy) is not dict
        or set(policy) != _POLICY_FIELDS
        or not all(
            _text(policy.get(field))
            for field in ("policy_id", "policy_version")
        )
        or not is_sha512(policy.get("policy_digest"))
        or policy.get("status") != "ACTIVE"
        or type(policy.get("effective_from")) is not int
        or type(policy.get("effective_until")) is not int
        or policy["effective_until"] <= policy["effective_from"]
        or not (
            policy["effective_from"]
            <= snapshot["evaluation_time"]
            < policy["effective_until"]
        )
        or not _text_list(policy.get("permitted_actions"))
        or not _text_list(policy.get("restricted_actions"))
        or snapshot["requested_action"] not in policy["permitted_actions"]
        or snapshot["requested_action"] in policy["restricted_actions"]
        or policy["policy_digest"]
        != _safe_hash(snapshot["submitted_claims"]["policy_artifact"])
    ):
        return "AUTHORITY_PROVENANCE_POLICY_INVALID"
    if not _evidence_exact(value.get("evidence_references")):
        return "AUTHORITY_PROVENANCE_EVIDENCE_INVALID"
    evidence = {
        item["evidence_class"]: item["digest"]
        for item in value["evidence_references"]
    }
    if (
        evidence["authority_resolution"]
        != resolved_authority["evidence_digest"]
        or evidence["jurisdiction_resolution"]
        != resolved_jurisdiction["evidence_digest"]
        or evidence["classification_rule_set"]
        != classification["rule_set_digest"]
        or evidence["policy_artifact"] != policy["policy_digest"]
    ):
        return "AUTHORITY_PROVENANCE_EVIDENCE_BINDING_INVALID"
    if value["result"] == AUTHORITY_PROVENANCE_DENY:
        return "AUTHORITY_PROVENANCE_EXTERNAL_DETERMINATION_DENIED"
    return None


def _source_error(
    source: Any,
    *,
    snapshot: dict[str, Any],
    dependencies: AuthorityProvenanceDependencies,
) -> str | None:
    boundary = resolve_authority_trust_boundary(dependencies)
    pin = boundary.context.role_pin(AUTHORITY_TRUST_ROLE_PROVENANCE) if boundary else None
    evaluator = boundary.evaluator if boundary else None
    if pin is None or evaluator is None:
        return "AUTHORITY_PROVENANCE_TRUST_CONTEXT_UNAVAILABLE"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return "AUTHORITY_PROVENANCE_SOURCE_SHAPE_INVALID"
    if not verify_pinned_signed_object(source, role_pin=pin):
        return "AUTHORITY_PROVENANCE_SIGNATURE_INVALID"
    if (
        source.get("contract_id") != AUTHORITY_PROVENANCE_CONTRACT_ID
        or source.get("schema_status") != AUTHORITY_PROVENANCE_SCHEMA_STATUS
        or source.get("evaluator_id") != pin.evaluator_id
        or source.get("evaluator_version") != pin.evaluator_version
        or source.get("evaluator_id") != getattr(evaluator, "evaluator_id", None)
        or source.get("evaluator_version")
        != getattr(evaluator, "evaluator_version", None)
        or source.get("authority_credential")
        != {
            "credential_id": pin.authority_credential_id,
            "authority_role": "AUTHORITY_PROVENANCE_EVALUATOR",
        }
    ):
        return "AUTHORITY_PROVENANCE_SOURCE_AUTHORITY_INVALID"
    expected = {
        "stage": snapshot["stage"],
        "evaluation_sequence": snapshot["evaluation_sequence"],
        "request_fingerprint": snapshot["request_fingerprint"],
        "pre_evaluation_state_hash": snapshot["pre_evaluation_state_hash"],
        "evaluation_time": snapshot["evaluation_time"],
        "prior_provenance_digest": snapshot["prior_provenance_digest"],
        "trust_context_digest": snapshot["trust_context_digest"],
        "clock_receipt_digest": snapshot["clock_receipt_digest"],
        "registry_head_digest": snapshot["registry_head_digest"],
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in expected.items()):
        return "AUTHORITY_PROVENANCE_SOURCE_BINDING_MISMATCH"
    return _determination_error(source.get("determination"), snapshot=snapshot)


def _deny(state: dict[str, Any], reason: str) -> dict[str, Any]:
    state["authority_provenance_result"] = AUTHORITY_PROVENANCE_DENY
    state["authority_provenance_reason"] = reason
    state["resolved_authority"] = ""
    state["jurisdiction"] = ""
    state["ap_acf_class"] = None
    state["ap_acf_subclass"] = None
    state["governance_policy_record"] = {}
    state["governance_policy_digest"] = None
    for field in _NO_AUTHORITY_FIELDS:
        state[f"authority_provenance_{field}"] = False
    return state


def evaluate_authority_provenance(
    state: dict[str, Any], *, dependencies: AuthorityProvenanceDependencies | None
) -> dict[str, Any]:
    trace = state.setdefault("authority_provenance_trace", [])
    if type(trace) is not list:
        return _deny(state, "AUTHORITY_PROVENANCE_TRACE_INVALID")
    request_fingerprint = state.get("request_fingerprint")
    trust = current_authority_trust_evidence(
        dependencies=dependencies,
        request_fingerprint=request_fingerprint,
    )
    if trust is None or not isinstance(dependencies, AuthorityProvenanceDependencies):
        return _deny(state, "AUTHORITY_PROVENANCE_TRUST_EVIDENCE_UNAVAILABLE")
    context, clock_receipt, registry_head = trust
    sequence = len(trace) + 1
    if sequence != 1:
        return _deny(state, "AUTHORITY_PROVENANCE_DUPLICATE_ADMISSION")
    snapshot = _snapshot(
        state,
        dependencies=dependencies,
        sequence=sequence,
        clock_receipt=clock_receipt,
        registry_head=registry_head,
    )
    if snapshot is None:
        return _deny(state, "AUTHORITY_PROVENANCE_SNAPSHOT_INVALID")
    boundary = resolve_authority_trust_boundary(dependencies)
    source: dict[str, Any] | None = None
    error: str | None = None
    try:
        candidate = boundary.evaluator.evaluate_authority_provenance(
            stage=AUTHORITY_PROVENANCE_STAGE,
            snapshot=deepcopy(snapshot),
        )
        source = candidate if type(candidate) is dict else None
    except Exception:
        error = "AUTHORITY_PROVENANCE_EVALUATOR_FAILED"
    if error is None and source is None:
        error = "AUTHORITY_PROVENANCE_SOURCE_INVALID"
    if error is None:
        error = _source_error(
            source, snapshot=snapshot, dependencies=dependencies
        )
    if error is None and not authority_trust_evidence_still_current(
        dependencies=dependencies,
        request_fingerprint=request_fingerprint,
        clock_receipt=clock_receipt,
        registry_head=registry_head,
    ):
        error = "AUTHORITY_PROVENANCE_TERMINAL_HEAD_RECHECK_FAILED"
    if error is not None:
        return _deny(state, error)
    determination = source["determination"]
    record = {
        "contract_id": AUTHORITY_PROVENANCE_CONTRACT_ID,
        "schema_status": AUTHORITY_PROVENANCE_SCHEMA_STATUS,
        "stage": AUTHORITY_PROVENANCE_STAGE,
        "evaluation_sequence": sequence,
        "result": AUTHORITY_PROVENANCE_PASS,
        "reason": "authority_provenance_evidence_verified",
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source),
        "trust_context_digest": context.context_digest,
        "clock_receipt_digest": snapshot["clock_receipt_digest"],
        "registry_head_digest": snapshot["registry_head_digest"],
        "resolved_authority": deepcopy(determination["resolved_authority"]),
        "resolved_jurisdiction": deepcopy(
            determination["resolved_jurisdiction"]
        ),
        "classification": deepcopy(determination["classification"]),
        "policy": deepcopy(determination["policy"]),
        "evidence_references": deepcopy(
            determination["evidence_references"]
        ),
        **_false_flags(),
    }
    trace.append(record)
    state["authority_provenance_record"] = deepcopy(record)
    state["authority_provenance_digest"] = canonical_integrity_hash(record)
    state["authority_provenance_trace_digest"] = canonical_integrity_hash(trace)
    state["authority_provenance_result"] = AUTHORITY_PROVENANCE_PASS
    state["authority_provenance_reason"] = record["reason"]
    state["authority_provenance_trust_context_digest"] = context.context_digest
    state["authority_provenance_clock_receipt_digest"] = record[
        "clock_receipt_digest"
    ]
    state["authority_provenance_registry_head_digest"] = record[
        "registry_head_digest"
    ]
    state["evaluation_time"] = snapshot["evaluation_time"]
    state["resolved_authority"] = record["resolved_authority"]["authority_id"]
    state["jurisdiction"] = record["resolved_jurisdiction"]["jurisdiction_id"]
    state["ap_acf_class"] = record["classification"]["class_id"]
    state["ap_acf_subclass"] = record["classification"]["subclass_id"]
    state["governance_policy_record"] = deepcopy(record["policy"])
    state["governance_policy_digest"] = record["policy"]["policy_digest"]
    for field in _NO_AUTHORITY_FIELDS:
        state[f"authority_provenance_{field}"] = False
    return state


def _hash_payload(record: dict[str, Any], trace_digest: str | None) -> dict[str, Any]:
    return {
        "contract_id": AUTHORITY_PROVENANCE_CONTRACT_ID,
        "schema_status": AUTHORITY_PROVENANCE_SCHEMA_STATUS,
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "record_digest": _safe_hash(record),
        "trace_digest": trace_digest,
        "trust_context_digest": record.get("trust_context_digest"),
        "clock_receipt_digest": record.get("clock_receipt_digest"),
        "registry_head_digest": record.get("registry_head_digest"),
        **_false_flags(),
    }


def authority_provenance_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    record = state.get("authority_provenance_record")
    if type(record) is not dict:
        record = {}
    return _hash_payload(
        record, state.get("authority_provenance_trace_digest")
    )


def verify_authority_provenance(
    state: dict[str, Any],
    *,
    dependencies: AuthorityProvenanceDependencies | None,
    require_hash_binding: bool = True,
) -> bool:
    try:
        trace = state.get("authority_provenance_trace")
        record = state.get("authority_provenance_record")
        if (
            not isinstance(dependencies, AuthorityProvenanceDependencies)
            or type(trace) is not list
            or len(trace) != 1
            or type(record) is not dict
            or record != trace[0]
            or set(record) != _RECORD_FIELDS
            or record.get("result") != AUTHORITY_PROVENANCE_PASS
            or record.get("reason") != "authority_provenance_evidence_verified"
            or state.get("authority_provenance_result")
            != AUTHORITY_PROVENANCE_PASS
            or state.get("authority_provenance_reason") != record.get("reason")
            or state.get("authority_provenance_digest") != _safe_hash(record)
            or state.get("authority_provenance_trace_digest") != _safe_hash(trace)
            or any(record.get(field) is not False for field in _NO_AUTHORITY_FIELDS)
            or any(
                state.get(f"authority_provenance_{field}") is not False
                for field in _NO_AUTHORITY_FIELDS
            )
        ):
            return False
        snapshot = record.get("evaluation_snapshot")
        source = record.get("evaluation_source")
        if (
            type(snapshot) is not dict
            or record.get("evaluation_snapshot_digest") != _safe_hash(snapshot)
            or record.get("evaluation_source_digest") != _safe_hash(source)
            or _source_error(
                source, snapshot=snapshot, dependencies=dependencies
            )
            is not None
            or record.get("trust_context_digest")
            != snapshot.get("trust_context_digest")
            or record.get("clock_receipt_digest")
            != snapshot.get("clock_receipt_digest")
            or record.get("registry_head_digest")
            != snapshot.get("registry_head_digest")
        ):
            return False
        determination = source["determination"]
        if (
            record.get("resolved_authority")
            != determination.get("resolved_authority")
            or record.get("resolved_jurisdiction")
            != determination.get("resolved_jurisdiction")
            or record.get("classification") != determination.get("classification")
            or record.get("policy") != determination.get("policy")
            or record.get("evidence_references")
            != determination.get("evidence_references")
            or state.get("resolved_authority")
            != record["resolved_authority"]["authority_id"]
            or state.get("jurisdiction")
            != record["resolved_jurisdiction"]["jurisdiction_id"]
            or state.get("ap_acf_class") != record["classification"]["class_id"]
            or state.get("ap_acf_subclass")
            != record["classification"]["subclass_id"]
            or state.get("governance_policy_record") != record["policy"]
            or state.get("governance_policy_digest")
            != record["policy"]["policy_digest"]
            or state.get("request_fingerprint")
            != snapshot.get("request_fingerprint")
            or state.get("evaluation_time") != snapshot.get("evaluation_time")
            or state.get("foundational_baseline_digest")
            != snapshot.get("foundational_baseline_digest")
        ):
            return False
        if not authority_trust_evidence_still_current(
            dependencies=dependencies,
            request_fingerprint=state["request_fingerprint"],
            clock_receipt=snapshot["clock_receipt"],
            registry_head=snapshot["registry_head"],
        ):
            return False
        if not require_hash_binding:
            return True
        chain = state.get("hash_chain")
        if not verify_hash_chain_entries(chain, state.get("state_hash")):
            return False
        expected_stage = (
            f"{AUTHORITY_PROVENANCE_HASH_STAGE_PREFIX}admission"
        )
        expected_payload_hash = _safe_hash(
            _hash_payload(record, _safe_hash(trace))
        )
        matches = [
            entry
            for entry in chain
            if type(entry) is dict
            and entry.get("stage") == expected_stage
            and entry.get("payload_hash") == expected_payload_hash
        ]
        return (
            len(matches) == 1
            and matches[0].get("previous_hash")
            == snapshot.get("pre_evaluation_state_hash")
        )
    except (IntegrityContractError, KeyError, TypeError, ValueError):
        return False


def authority_provenance_token_bindings(
    state: dict[str, Any]
) -> dict[str, Any] | None:
    fields = (
        "authority_provenance_digest",
        "authority_provenance_trace_digest",
        "authority_provenance_trust_context_digest",
        "authority_provenance_clock_receipt_digest",
        "authority_provenance_registry_head_digest",
    )
    bindings = {field: state.get(field) for field in fields}
    return bindings if all(is_sha512(value) for value in bindings.values()) else None


__all__ = [
    "AUTHORITY_PROVENANCE_CONTRACT_ID",
    "AUTHORITY_PROVENANCE_DENY",
    "AUTHORITY_PROVENANCE_EVIDENCE_CLASSES",
    "AUTHORITY_PROVENANCE_HASH_STAGE_PREFIX",
    "AUTHORITY_PROVENANCE_PASS",
    "AUTHORITY_PROVENANCE_SCHEMA_STATUS",
    "AUTHORITY_PROVENANCE_STAGE",
    "authority_provenance_hash_payload",
    "authority_provenance_token_bindings",
    "evaluate_authority_provenance",
    "verify_authority_provenance",
]
