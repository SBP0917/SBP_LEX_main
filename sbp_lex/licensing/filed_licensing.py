from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol

from sbp_lex.security.integrity import (
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)
from sbp_lex.security.signature_provider import (
    SignatureProvider,
    verify_signed_object,
)
from sbp_lex.security.hybrid_signature import HybridVerificationContext


TIER_1_PERSONAL = "TIER_1_PERSONAL"
TIER_2_COMMERCIAL = "TIER_2_COMMERCIAL"
TIER_3_INSTITUTIONAL = "TIER_3_INSTITUTIONAL"
TIER_4_EXTRA_TERRITORIAL = "TIER_4_EXTRA_TERRITORIAL"

FILED_LICENCE_TIERS = (
    TIER_1_PERSONAL,
    TIER_2_COMMERCIAL,
    TIER_3_INSTITUTIONAL,
    TIER_4_EXTRA_TERRITORIAL,
)
FILED_LICENCE_BINDINGS = (
    "identity",
    "jurisdiction",
    "authority_state",
    "execution_rights",
    "autonomy_level",
)
FILED_LICENCE_AUTHORITY_ROLE = "FILED_LICENCE_AUTHORITY"
LICENCE_ROOT_BINDING_STAGE = "filed_licence:root_binding"
LICENCE_VALIDATION_STAGE = "filed_licence:validation"
LICENCE_REVALIDATION_STAGE = "filed_licence:revalidation"
LICENCE_POINT_OF_USE_STAGE = "filed_licence:point_of_use"

LICENCE_ALLOW = "ALLOW"
LICENCE_DENY = "DENY"
LICENCE_ESCALATE = "ESCALATE"

_SOURCE_FIELDS = {
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_licence_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}


class FiledLicenceEvaluator(Protocol):
    licence_evaluator_id: str
    licence_evaluator_version: str
    licence_authority_role: str
    licence_authority_credential_id: str

    def evaluate_licence(
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


def _present(value: Any) -> bool:
    return value is not None and value not in ("", {}, [])


def _evidence_references_exact(value: Any) -> bool:
    if type(value) is not list or not value:
        return False
    identifiers: set[str] = set()
    for reference in value:
        if type(reference) is not dict or set(reference) != {
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        identifier = reference.get("evidence_id")
        if type(identifier) is not str or not _text(identifier) or identifier in identifiers:
            return False
        identifiers.add(identifier)
        if not _text(reference.get("source")):
            return False
        if not is_sha512(reference.get("digest")):
            return False
    return True


def _licence_bindings(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "identity": deepcopy(state.get("identity")),
        "jurisdiction": deepcopy(state.get("jurisdiction")),
        "authority_state": deepcopy(state.get("resolved_authority")),
        "execution_rights": deepcopy(state.get("execution_rights")),
        "autonomy_level": deepcopy(state.get("requested_autonomy_level")),
    }


def _snapshot(
    state: dict[str, Any],
    *,
    stage: str,
    sequence: int,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash"),
        "evaluation_time": state.get("evaluation_time"),
        "tier": deepcopy(state.get("license_tier")),
        "bindings": _licence_bindings(state),
        "action": deepcopy(state.get("action")),
        "ap_acf_class": deepcopy(state.get("ap_acf_class")),
        "prior_licence_digest": state.get("filed_licence_digest"),
    }


def _common_error(
    source: Any,
    *,
    snapshot: dict[str, Any],
    evaluator: FiledLicenceEvaluator,
    provider: SignatureProvider | None,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> str | None:
    if getattr(provider, "licence_attestation_admitted", None) is not True:
        return "LICENCE_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return "FILED_LICENCE_EVALUATOR_RESULT_SHAPE_INVALID"
    if not verify_signed_object(
        source,
        provider=provider,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        allow_legacy_non_effect=False,
    ):
        return "FILED_LICENCE_ATTESTATION_INVALID"
    if source.get("evaluator_id") != getattr(
        evaluator, "licence_evaluator_id", None
    ):
        return "FILED_LICENCE_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != getattr(
        evaluator, "licence_evaluator_version", None
    ):
        return "FILED_LICENCE_EVALUATOR_VERSION_MISMATCH"
    if source.get("authority_credential") != {
        "credential_id": getattr(
            evaluator, "licence_authority_credential_id", None
        ),
        "authority_role": FILED_LICENCE_AUTHORITY_ROLE,
    }:
        return "FILED_LICENCE_AUTHORITY_CREDENTIAL_INVALID"
    bindings = {
        "stage": snapshot.get("stage"),
        "evaluation_sequence": snapshot.get("evaluation_sequence"),
        "request_fingerprint": snapshot.get("request_fingerprint"),
        "pre_evaluation_state_hash": snapshot.get("state_hash"),
        "evaluation_time": snapshot.get("evaluation_time"),
        "prior_licence_digest": snapshot.get("prior_licence_digest"),
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in bindings.items()):
        return "FILED_LICENCE_EVALUATION_BINDING_MISMATCH"
    return None


def _determination_error(
    determination: Any,
    snapshot: dict[str, Any],
) -> str | None:
    fields = {
        "result",
        "licence_id",
        "tier",
        "bindings",
        "invalidation_status",
        "revocation_status",
        "revocation_sequence",
        "evidence_references",
    }
    if type(determination) is not dict or set(determination) != fields:
        return "FILED_LICENCE_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in {
        LICENCE_ALLOW,
        LICENCE_DENY,
        LICENCE_ESCALATE,
    }:
        return "FILED_LICENCE_RESULT_INVALID"
    if not _text(determination.get("licence_id")):
        return "FILED_LICENCE_ID_INVALID"
    if determination.get("tier") not in FILED_LICENCE_TIERS:
        return "FILED_LICENCE_TIER_INVALID"
    if determination.get("tier") != snapshot.get("tier"):
        return "FILED_LICENCE_TIER_BINDING_MISMATCH"
    bindings = determination.get("bindings")
    if (
        type(bindings) is not dict
        or tuple(bindings) != FILED_LICENCE_BINDINGS
        or bindings != snapshot.get("bindings")
    ):
        return "FILED_LICENCE_FIVE_BINDING_MISMATCH"
    if not all(_present(bindings.get(field)) for field in FILED_LICENCE_BINDINGS):
        return "FILED_LICENCE_REQUIRED_BINDING_MISSING"
    autonomy = bindings.get("autonomy_level")
    if type(autonomy) is not int or autonomy < 0:
        return "FILED_LICENCE_AUTONOMY_BINDING_INVALID"
    execution_rights = bindings.get("execution_rights")
    if (
        type(execution_rights) is not dict
        or set(execution_rights) != {"allowed_actions"}
        or type(execution_rights.get("allowed_actions")) is not list
        or not execution_rights["allowed_actions"]
        or any(
            not _text(action)
            for action in execution_rights["allowed_actions"]
        )
        or len(set(execution_rights["allowed_actions"]))
        != len(execution_rights["allowed_actions"])
    ):
        return "FILED_LICENCE_EXECUTION_RIGHTS_BINDING_INVALID"
    if snapshot.get("action") not in execution_rights["allowed_actions"]:
        return "FILED_LICENCE_ACTION_NOT_IN_SIGNED_EXECUTION_RIGHTS"
    if determination.get("invalidation_status") not in {
        "VALID",
        "INVALIDATED",
    }:
        return "FILED_LICENCE_INVALIDATION_STATUS_INVALID"
    if determination.get("revocation_status") not in {"ACTIVE", "REVOKED"}:
        return "FILED_LICENCE_REVOCATION_STATUS_INVALID"
    if (
        type(determination.get("revocation_sequence")) is not int
        or determination["revocation_sequence"] < 0
    ):
        return "FILED_LICENCE_REVOCATION_SEQUENCE_INVALID"
    if not _evidence_references_exact(determination.get("evidence_references")):
        return "FILED_LICENCE_EVIDENCE_CONTRACT_INVALID"
    if determination["result"] == LICENCE_ALLOW:
        if (
            determination["invalidation_status"] != "VALID"
            or determination["revocation_status"] != "ACTIVE"
        ):
            return "FILED_LICENCE_ALLOW_STATUS_INVALID"
    elif (
        determination["invalidation_status"] == "VALID"
        and determination["revocation_status"] == "ACTIVE"
    ):
        return "FILED_LICENCE_NON_ALLOW_STATUS_INVALID"
    return None


def evaluate_filed_licence(
    state: dict[str, Any],
    *,
    stage: str,
    evaluator: FiledLicenceEvaluator | None,
    attestation_provider: SignatureProvider | None,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> dict[str, Any]:
    trace = state.setdefault("filed_licence_trace", [])
    if type(trace) is not list:
        raise ValueError("FILED_LICENCE_TRACE_INVALID")
    sequence = len(trace) + 1
    snapshot = _snapshot(state, stage=stage, sequence=sequence)
    source: dict[str, Any] | None = None
    error: str | None = None
    if stage not in {
        LICENCE_ROOT_BINDING_STAGE,
        LICENCE_VALIDATION_STAGE,
        LICENCE_REVALIDATION_STAGE,
    }:
        error = "FILED_LICENCE_STAGE_NOT_ADMITTED"
    elif sequence == 1 and stage != LICENCE_ROOT_BINDING_STAGE:
        error = "FILED_LICENCE_ROOT_BINDING_REQUIRED"
    elif sequence == 2 and stage != LICENCE_VALIDATION_STAGE:
        error = "FILED_LICENCE_VALIDATION_STAGE_REQUIRED"
    elif sequence > 2 and stage != LICENCE_REVALIDATION_STAGE:
        error = "FILED_LICENCE_REVALIDATION_STAGE_REQUIRED"
    elif evaluator is None:
        error = "FILED_LICENCE_EVALUATOR_NOT_INJECTED"
    else:
        metadata = (
            getattr(evaluator, "licence_evaluator_id", None),
            getattr(evaluator, "licence_evaluator_version", None),
            getattr(evaluator, "licence_authority_role", None),
            getattr(evaluator, "licence_authority_credential_id", None),
        )
        method = getattr(evaluator, "evaluate_licence", None)
        if (
            not all(_text(value) for value in metadata)
            or metadata[2] != FILED_LICENCE_AUTHORITY_ROLE
            or not callable(method)
        ):
            error = "FILED_LICENCE_EVALUATOR_CONTRACT_INVALID"
        elif getattr(
            attestation_provider,
            "licence_attestation_admitted",
            None,
        ) is not True:
            error = "LICENCE_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
        else:
            try:
                source = method(stage=stage, snapshot=deepcopy(snapshot))
            except Exception as exc:
                error = (
                    "FILED_LICENCE_EVALUATOR_ERROR:"
                    f"{type(exc).__name__}:{exc}"
                )
            if error is None:
                error = _common_error(
                    source,
                    snapshot=snapshot,
                    evaluator=evaluator,
                    provider=attestation_provider,
                    trust_context=trust_context,
                    owner_pinned_context_digest=owner_pinned_context_digest,
                )
            if error is None:
                if type(source) is not dict:
                    error = "FILED_LICENCE_SOURCE_INVALID"
                else:
                    error = _determination_error(
                        source.get("determination"),
                        snapshot,
                    )
            if error is None and trace and type(source) is dict:
                previous_source = trace[-1].get("evaluation_source")
                previous_determination = (
                    previous_source.get("determination")
                    if type(previous_source) is dict
                    else None
                )
                current_determination = source["determination"]
                if type(previous_determination) is not dict:
                    error = "FILED_LICENCE_PRIOR_RECORD_INVALID"
                elif current_determination["licence_id"] != (
                    previous_determination.get("licence_id")
                ):
                    error = "FILED_LICENCE_ID_CONTINUITY_FAILURE"
                elif current_determination["revocation_sequence"] < (
                    previous_determination.get("revocation_sequence", -1)
                ):
                    error = "FILED_LICENCE_REVOCATION_SEQUENCE_ROLLBACK"
    result = (
        source["determination"]["result"]
        if error is None and source is not None
        else LICENCE_DENY
    )
    reason = error or "FILED_LICENCE_EVALUATION_COMPLETED"
    record = {
        "stage": stage,
        "evaluation_sequence": sequence,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "authority_granted": False,
        "execution_authority_granted": False,
    }
    trace.append(record)
    state["filed_licence_digest"] = canonical_integrity_hash(trace)
    state["filed_licence_record"] = deepcopy(record)
    state["filed_licence_result"] = result
    state["filed_licence_reason"] = reason
    if source is not None and error is None:
        determination = source["determination"]
        state["licence_id"] = determination["licence_id"]
        state["licence_invalidation_status"] = determination[
            "invalidation_status"
        ]
        state["licence_revocation_status"] = determination[
            "revocation_status"
        ]
        state["licence_revocation_sequence"] = determination[
            "revocation_sequence"
        ]
    return state


def filed_licence_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    record = state.get("filed_licence_record", {})
    return {
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "reason": record.get("reason"),
        "record_digest": _safe_hash(record),
        "trace_digest": state.get("filed_licence_digest"),
        "authority_granted": False,
        "execution_authority_granted": False,
    }


def probe_filed_licence_current(
    state: dict[str, Any],
    *,
    evaluator: FiledLicenceEvaluator | None,
    attestation_provider: SignatureProvider | None,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    if (
        evaluator is None
        or state.get("licence_invalidation_status") != "VALID"
        or state.get("licence_revocation_status") != "ACTIVE"
    ):
        return None, "FILED_LICENCE_POINT_OF_USE_STATE_INVALID"
    metadata = (
        getattr(evaluator, "licence_evaluator_id", None),
        getattr(evaluator, "licence_evaluator_version", None),
        getattr(evaluator, "licence_authority_role", None),
        getattr(evaluator, "licence_authority_credential_id", None),
    )
    method = getattr(evaluator, "evaluate_licence", None)
    if (
        not all(_text(value) for value in metadata)
        or metadata[2] != FILED_LICENCE_AUTHORITY_ROLE
        or not callable(method)
    ):
        return None, "FILED_LICENCE_EVALUATOR_CONTRACT_INVALID"
    trace = state.get("filed_licence_trace")
    if type(trace) is not list or not trace:
        return None, "FILED_LICENCE_TRACE_INVALID"
    snapshot = _snapshot(
        state,
        stage=LICENCE_POINT_OF_USE_STAGE,
        sequence=len(trace) + 1,
    )
    try:
        source = method(
            stage=LICENCE_POINT_OF_USE_STAGE,
            snapshot=deepcopy(snapshot),
        )
    except Exception as exc:
        return None, (
            "FILED_LICENCE_EVALUATOR_ERROR:"
            f"{type(exc).__name__}:{exc}"
        )
    error = _common_error(
        source,
        snapshot=snapshot,
        evaluator=evaluator,
        provider=attestation_provider,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    if error is None:
        error = _determination_error(source.get("determination"), snapshot)
    if error is not None:
        return None, error
    determination = source["determination"]
    if (
        determination["result"] != LICENCE_ALLOW
        or determination["licence_id"] != state.get("licence_id")
        or determination["tier"] != state.get("license_tier")
        or determination["bindings"] != _licence_bindings(state)
        or determination["invalidation_status"] != "VALID"
        or determination["revocation_status"] != "ACTIVE"
        or determination["revocation_sequence"]
        < state.get("licence_revocation_sequence", -1)
    ):
        return None, "FILED_LICENCE_POINT_OF_USE_NOT_ACTIVE"
    return source, None


def invalidate_filed_licence(
    state: dict[str, Any],
    *,
    stage: str,
    reason: str,
) -> dict[str, Any]:
    if state.get("licence_invalidation_status") == "INVALIDATED":
        return state
    record = {
        "stage": stage,
        "reason": reason,
        "licence_id": state.get("licence_id"),
        "prior_licence_digest": state.get("filed_licence_digest"),
        "revocation_status": state.get("licence_revocation_status"),
    }
    state.setdefault("licence_invalidation_trace", []).append(record)
    state["licence_invalidation_digest"] = canonical_integrity_hash(
        state["licence_invalidation_trace"]
    )
    state["licence_invalidation_status"] = "INVALIDATED"
    state["licence_execution_disabled"] = True
    state["licensing_result"] = "INVALIDATED"
    state["licensing_reason"] = reason
    state["token_stack_valid"] = False
    return state


def verify_filed_licence(
    state: dict[str, Any],
    *,
    evaluator: FiledLicenceEvaluator | None,
    attestation_provider: SignatureProvider | None,
    require_validation: bool = True,
    require_revalidation: bool = False,
    require_hash_binding: bool = True,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> bool:
    trace = state.get("filed_licence_trace")
    if (
        evaluator is None
        or type(trace) is not list
        or not trace
        or state.get("filed_licence_digest") != _safe_hash(trace)
        or state.get("licence_invalidation_status") != "VALID"
        or state.get("licence_revocation_status") != "ACTIVE"
    ):
        return False
    expected_stages = [LICENCE_ROOT_BINDING_STAGE]
    if require_validation:
        expected_stages.append(LICENCE_VALIDATION_STAGE)
    if require_revalidation:
        if not require_validation:
            return False
        expected_stages.append(LICENCE_REVALIDATION_STAGE)
    if [record.get("stage") for record in trace] != expected_stages:
        return False
    licence_id: str | None = None
    prior_revocation_sequence = -1
    for index, record in enumerate(trace, start=1):
        if type(record) is not dict or set(record) != {
            "stage",
            "evaluation_sequence",
            "result",
            "reason",
            "evaluation_snapshot",
            "evaluation_snapshot_digest",
            "evaluation_source",
            "evaluation_source_digest",
            "authority_granted",
            "execution_authority_granted",
        }:
            return False
        snapshot = record.get("evaluation_snapshot")
        source = record.get("evaluation_source")
        if type(snapshot) is not dict or type(source) is not dict:
            return False
        if (
            record.get("evaluation_sequence") != index
            or record.get("result") != LICENCE_ALLOW
            or record.get("authority_granted") is not False
            or record.get("execution_authority_granted") is not False
            or record.get("evaluation_snapshot_digest") != _safe_hash(snapshot)
            or record.get("evaluation_source_digest") != _safe_hash(source)
            or _common_error(
                source,
                snapshot=snapshot,
                evaluator=evaluator,
                provider=attestation_provider,
                trust_context=trust_context,
                owner_pinned_context_digest=owner_pinned_context_digest,
            )
            is not None
            or _determination_error(source.get("determination"), snapshot)
            is not None
        ):
            return False
        observed_id = source["determination"]["licence_id"]
        if licence_id is None:
            licence_id = observed_id
        elif observed_id != licence_id:
            return False
        observed_sequence = source["determination"]["revocation_sequence"]
        if observed_sequence < prior_revocation_sequence:
            return False
        prior_revocation_sequence = observed_sequence
    latest_snapshot = trace[-1]["evaluation_snapshot"]
    if type(latest_snapshot) is not dict:
        return False
    if (
        latest_snapshot.get("tier") != state.get("license_tier")
        or latest_snapshot.get("bindings") != _licence_bindings(state)
        or state.get("licence_id") != licence_id
        or state.get("filed_licence_record") != trace[-1]
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
    for record in trace:
        payload = {
            "stage": record["stage"],
            "evaluation_sequence": record["evaluation_sequence"],
            "result": record["result"],
            "reason": record["reason"],
            "record_digest": _safe_hash(record),
            "trace_digest": _safe_hash(
                trace[: record["evaluation_sequence"]]
            ),
            "authority_granted": False,
            "execution_authority_granted": False,
        }
        matches = [
            index
            for index, entry in enumerate(chain)
            if entry.get("stage") == record["stage"]
            and entry.get("payload_hash") == _safe_hash(payload)
        ]
        if len(matches) != 1 or matches[0] <= previous_index:
            return False
        previous_index = matches[0]
    return True
