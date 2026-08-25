from __future__ import annotations

"""Authenticated SKG authority-envelope mechanics for SBP-LEX V2.

This module is an IMPLEMENTATION-DEFINED V2 MECHANICAL CONTRACT. It is not a
filed SKG schema and does not define the substantive evidence rules for any
filed SKG content class. The injected evaluator supplies those determinations;
this module only authenticates, binds, records, and verifies them fail closed.
"""

from copy import deepcopy
import hmac
from typing import Any, Final, Protocol

from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)
from sbp_lex.security.hybrid_signature import (
    HybridSignatureProvider,
    HybridVerificationContext,
    is_hybrid_provider,
    verify_hybrid_signed_object,
)


SKG_V2_CONTRACT_ID: Final = "SBP_LEX_SKG_AUTHORITY_V2"
SKG_SCHEMA_STATUS: Final = "IMPLEMENTATION_DEFINED_V2_MECHANICS"
SKG_AUTHORITY_ROLE: Final = "SKG_CONSTITUTIONAL_AUTHORITY_EVALUATOR"
SKG_HASH_STAGE_PREFIX: Final = "skg_authority:"
SKG_AUTHORITY_ATTESTATION_PURPOSE: Final = (
    "SBP_LEX_V2_SKG_AUTHORITY_ATTESTATION"
)

SKG_CONTENT_CLASSES: Final = (
    "Authority hierarchies",
    "Jurisdictional legitimacy",
    "Statutory and constitutional precedence",
    "Procedural obligations",
    "Evidentiary sufficiency",
    "Conflict resolution precedence",
    "Treaty and delegated mandates",
)

SKG_PASS: Final = "PASS"
SKG_DENY: Final = "DENY"
SKG_SATISFIED: Final = "SATISFIED"
SKG_NOT_SATISFIED: Final = "NOT_SATISFIED"

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
    "prior_skg_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}
_SNAPSHOT_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "content_classes",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_skg_digest",
}
_DETERMINATION_FIELDS: Final = {
    "result",
    "content_class_results",
    "evidence_references",
    "authority_granted",
    "execution_authority_granted",
    "downstream_override_permitted",
}
_RECORD_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "content_classes",
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "evidence_references",
    "authority_granted",
    "execution_authority_granted",
    "downstream_override_permitted",
}


class SKGAuthorityEvaluator(Protocol):
    """Injected source of substantive SKG authority determinations."""

    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate_skg_authority(
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


def _trust_context_owner_pinned(
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> bool:
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not is_sha512(owner_pinned_context_digest)
    ):
        return False
    return hmac.compare_digest(
        trust_context.context_digest,
        owner_pinned_context_digest,
    )


def _provider_admitted(provider: HybridSignatureProvider | None) -> bool:
    return (
        is_hybrid_provider(provider)
        and getattr(provider, "skg_attestation_admitted", None) is True
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
        and metadata[2] == SKG_AUTHORITY_ROLE
        and callable(getattr(evaluator, "evaluate_skg_authority", None))
    )


def _state_hash_exact(value: Any) -> bool:
    return value == GENESIS_HASH or is_sha512(value)


def _snapshot(
    state: dict[str, Any],
    *,
    stage: str,
    sequence: int,
) -> dict[str, Any]:
    return {
        "contract_id": SKG_V2_CONTRACT_ID,
        "schema_status": SKG_SCHEMA_STATUS,
        "content_classes": list(SKG_CONTENT_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": state.get("request_fingerprint"),
        "pre_evaluation_state_hash": state.get("state_hash") or GENESIS_HASH,
        "evaluation_time": state.get("evaluation_time"),
        "prior_skg_digest": state.get("skg_authority_digest"),
    }


def _snapshot_exact(snapshot: Any) -> bool:
    return (
        type(snapshot) is dict
        and set(snapshot) == _SNAPSHOT_FIELDS
        and snapshot.get("contract_id") == SKG_V2_CONTRACT_ID
        and snapshot.get("schema_status") == SKG_SCHEMA_STATUS
        and snapshot.get("content_classes") == list(SKG_CONTENT_CLASSES)
        and _text(snapshot.get("stage"))
        and type(snapshot.get("evaluation_sequence")) is int
        and snapshot["evaluation_sequence"] >= 1
        and is_sha512(snapshot.get("request_fingerprint"))
        and _state_hash_exact(snapshot.get("pre_evaluation_state_hash"))
        and type(snapshot.get("evaluation_time")) is int
        and snapshot["evaluation_time"] >= 0
        and (
            snapshot.get("prior_skg_digest") is None
            or is_sha512(snapshot.get("prior_skg_digest"))
        )
    )


def _evidence_references_exact(references: Any) -> bool:
    if type(references) is not list or len(references) != len(
        SKG_CONTENT_CLASSES
    ):
        return False
    if [reference.get("content_class") if type(reference) is dict else None
        for reference in references] != list(SKG_CONTENT_CLASSES):
        return False
    evidence_ids: set[str] = set()
    for reference in references:
        if type(reference) is not dict or set(reference) != {
            "content_class",
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        evidence_id = reference.get("evidence_id")
        if type(evidence_id) is not str or not _text(evidence_id) or evidence_id in evidence_ids:
            return False
        evidence_ids.add(evidence_id)
        if not _text(reference.get("source")):
            return False
        if not is_sha512(reference.get("digest")):
            return False
    return True


def _determination_error(determination: Any) -> str | None:
    if type(determination) is not dict or set(determination) != (
        _DETERMINATION_FIELDS
    ):
        return "SKG_DETERMINATION_SHAPE_INVALID"
    result = determination.get("result")
    if result not in {SKG_PASS, SKG_DENY}:
        return "SKG_RESULT_INVALID"
    class_results = determination.get("content_class_results")
    if (
        type(class_results) is not dict
        or tuple(class_results) != SKG_CONTENT_CLASSES
        or any(
            value not in {SKG_SATISFIED, SKG_NOT_SATISFIED}
            for value in class_results.values()
        )
    ):
        return "SKG_CONTENT_CLASS_RESULTS_INVALID"
    expected_result = (
        SKG_PASS
        if all(value == SKG_SATISFIED for value in class_results.values())
        else SKG_DENY
    )
    if result != expected_result:
        return "SKG_RESULT_CONTENT_CLASS_MISMATCH"
    if not _evidence_references_exact(
        determination.get("evidence_references")
    ):
        return "SKG_EVIDENCE_CONTRACT_INVALID"
    if determination.get("authority_granted") is not False:
        return "SKG_AUTHORITY_GRANT_PROHIBITED"
    if determination.get("execution_authority_granted") is not False:
        return "SKG_EXECUTION_AUTHORITY_GRANT_PROHIBITED"
    if determination.get("downstream_override_permitted") is not False:
        return "SKG_DOWNSTREAM_OVERRIDE_PROHIBITED"
    return None


def _common_error(
    source: Any,
    *,
    snapshot: dict[str, Any],
    evaluator: SKGAuthorityEvaluator,
    provider: HybridSignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    if not _provider_admitted(provider):
        return "SKG_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if not _evaluator_contract_exact(evaluator):
        return "SKG_EVALUATOR_CONTRACT_INVALID"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return "SKG_EVALUATOR_RESULT_SHAPE_INVALID"
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not _trust_context_owner_pinned(
            trust_context,
            owner_pinned_context_digest,
        )
    ):
        return "SKG_OWNER_TRUST_PIN_INVALID"
    if not verify_hybrid_signed_object(
        source,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_purpose=SKG_AUTHORITY_ATTESTATION_PURPOSE,
        require_effect_authority=False,
    ):
        return "SKG_ATTESTATION_INVALID"
    if source.get("contract_id") != SKG_V2_CONTRACT_ID:
        return "SKG_CONTRACT_ID_INVALID"
    if source.get("schema_status") != SKG_SCHEMA_STATUS:
        return "SKG_SCHEMA_STATUS_INVALID"
    if source.get("evaluator_id") != getattr(evaluator, "evaluator_id", None):
        return "SKG_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != getattr(
        evaluator, "evaluator_version", None
    ):
        return "SKG_EVALUATOR_VERSION_MISMATCH"
    if source.get("authority_credential") != {
        "credential_id": getattr(
            evaluator, "authority_credential_id", None
        ),
        "authority_role": SKG_AUTHORITY_ROLE,
    }:
        return "SKG_AUTHORITY_CREDENTIAL_INVALID"
    bindings = {
        "stage": snapshot.get("stage"),
        "evaluation_sequence": snapshot.get("evaluation_sequence"),
        "request_fingerprint": snapshot.get("request_fingerprint"),
        "pre_evaluation_state_hash": snapshot.get(
            "pre_evaluation_state_hash"
        ),
        "evaluation_time": snapshot.get("evaluation_time"),
        "prior_skg_digest": snapshot.get("prior_skg_digest"),
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in bindings.items()):
        return "SKG_EVALUATION_BINDING_MISMATCH"
    return _determination_error(source.get("determination"))


def _deny_state(state: dict[str, Any], reason: str) -> dict[str, Any]:
    state["skg_authority_result"] = SKG_DENY
    state["skg_authority_reason"] = reason
    state["skg_authority_granted"] = False
    state["skg_execution_authority_granted"] = False
    state["skg_downstream_override_permitted"] = False
    return state


def evaluate_skg_authority(
    state: dict[str, Any],
    *,
    stage: str,
    evaluator: SKGAuthorityEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
) -> dict[str, Any]:
    """Evaluate and record one signed SKG authority result fail closed."""

    trace = state.setdefault("skg_authority_trace", [])
    if type(trace) is not list:
        return _deny_state(state, "SKG_TRACE_INVALID")
    sequence = len(trace) + 1
    snapshot = _snapshot(state, stage=stage, sequence=sequence)
    source: dict[str, Any] | None = None
    error: str | None = None

    if not _snapshot_exact(snapshot):
        error = "SKG_EVALUATION_SNAPSHOT_INVALID"
    elif trace:
        expected_prior = _safe_hash(trace[-1])
        if (
            expected_prior is None
            or state.get("skg_authority_digest") != expected_prior
        ):
            error = "SKG_PRIOR_DIGEST_STATE_INVALID"
    elif state.get("skg_authority_digest") is not None:
        error = "SKG_UNEXPECTED_PRIOR_DIGEST"

    if error is None and evaluator is None:
        error = "SKG_EVALUATOR_NOT_INJECTED"
    if error is None:
        method = getattr(evaluator, "evaluate_skg_authority", None)
        if not _evaluator_contract_exact(evaluator):
            error = "SKG_EVALUATOR_CONTRACT_INVALID"
        elif not _provider_admitted(attestation_provider):
            error = "SKG_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
        elif not callable(method) or evaluator is None:
            error = "SKG_EVALUATOR_CONTRACT_INVALID"
        else:
            try:
                source = method(stage=stage, snapshot=deepcopy(snapshot))
            except Exception as exc:
                error = f"SKG_EVALUATOR_ERROR:{type(exc).__name__}:{exc}"
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
        else SKG_DENY
    )
    reason = error or "SKG_AUTHORITY_EVALUATION_COMPLETED"
    evidence_references = (
        deepcopy(source["determination"]["evidence_references"])
        if error is None and source is not None
        else []
    )
    record = {
        "contract_id": SKG_V2_CONTRACT_ID,
        "schema_status": SKG_SCHEMA_STATUS,
        "content_classes": list(SKG_CONTENT_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "evidence_references": evidence_references,
        "authority_granted": False,
        "execution_authority_granted": False,
        "downstream_override_permitted": False,
    }
    trace.append(record)
    state["skg_authority_record"] = deepcopy(record)
    state["skg_authority_digest"] = canonical_integrity_hash(record)
    state["skg_authority_trace_digest"] = canonical_integrity_hash(trace)
    state["skg_authority_result"] = result
    state["skg_authority_reason"] = reason
    state["skg_authority_granted"] = False
    state["skg_execution_authority_granted"] = False
    state["skg_downstream_override_permitted"] = False
    return state


def _record_hash_payload(
    record: dict[str, Any],
    *,
    trace_digest: str | None,
) -> dict[str, Any]:
    return {
        "contract_id": SKG_V2_CONTRACT_ID,
        "schema_status": SKG_SCHEMA_STATUS,
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "record_digest": _safe_hash(record),
        "trace_digest": trace_digest,
        "authority_granted": False,
        "execution_authority_granted": False,
        "downstream_override_permitted": False,
    }


def skg_authority_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    """Canonical hash-chain payload for the latest SKG authority record."""

    record = state.get("skg_authority_record")
    if type(record) is not dict:
        record = {}
    return _record_hash_payload(
        record,
        trace_digest=state.get("skg_authority_trace_digest"),
    )


def verify_skg_authority(
    state: dict[str, Any],
    *,
    evaluator: SKGAuthorityEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    require_hash_binding: bool = True,
) -> bool:
    """Verify the complete current SKG trace, source, bindings, and chain."""

    try:
        trace = state.get("skg_authority_trace")
        latest = state.get("skg_authority_record")
        if (
            evaluator is None
            or type(trace) is not list
            or not trace
            or type(latest) is not dict
            or latest != trace[-1]
            or state.get("skg_authority_result") != SKG_PASS
            or state.get("skg_authority_reason")
            != "SKG_AUTHORITY_EVALUATION_COMPLETED"
            or state.get("skg_authority_granted") is not False
            or state.get("skg_execution_authority_granted") is not False
            or state.get("skg_downstream_override_permitted") is not False
            or state.get("skg_authority_digest") != _safe_hash(latest)
            or state.get("skg_authority_trace_digest") != _safe_hash(trace)
        ):
            return False

        prior_digest: str | None = None
        for sequence, record in enumerate(trace, start=1):
            if type(record) is not dict or set(record) != _RECORD_FIELDS:
                return False
            snapshot = record.get("evaluation_snapshot")
            source = record.get("evaluation_source")
            if type(snapshot) is not dict or type(source) is not dict:
                return False
            if (
                record.get("contract_id") != SKG_V2_CONTRACT_ID
                or record.get("schema_status") != SKG_SCHEMA_STATUS
                or record.get("content_classes") != list(SKG_CONTENT_CLASSES)
                or record.get("evaluation_sequence") != sequence
                or record.get("result") != SKG_PASS
                or record.get("reason")
                != "SKG_AUTHORITY_EVALUATION_COMPLETED"
                or record.get("authority_granted") is not False
                or record.get("execution_authority_granted") is not False
                or record.get("downstream_override_permitted") is not False
                or not _snapshot_exact(snapshot)
                or snapshot.get("stage") != record.get("stage")
                or snapshot.get("evaluation_sequence") != sequence
                or snapshot.get("prior_skg_digest") != prior_digest
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
        if type(latest_snapshot) is not dict:
            return False
        if (
            latest_snapshot.get("request_fingerprint")
            != state.get("request_fingerprint")
            or latest_snapshot.get("evaluation_time")
            != state.get("evaluation_time")
        ):
            return False
        if not require_hash_binding:
            return True

        chain = state.get("hash_chain")
        if type(chain) is not list or not verify_hash_chain_entries(
            chain, state.get("state_hash")
        ):
            return False
        previous_index = -1
        for sequence, record in enumerate(trace, start=1):
            payload = _record_hash_payload(
                record,
                trace_digest=_safe_hash(trace[:sequence]),
            )
            expected_stage = f"{SKG_HASH_STAGE_PREFIX}{record['stage']}"
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
