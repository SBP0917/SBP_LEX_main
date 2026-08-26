"""Implementation-defined V2 mechanical contract for filed Claim 2.

This module authenticates a deterministic register of source-artifact digests
for the four rule classes named in the filed claim.  It does not interpret a
rule, declare a universal legal precedence, resolve a legal conflict, or grant
authority.  Conflicts admitted by this contract remain unresolved and require
external escalation.
"""

from __future__ import annotations

from copy import deepcopy
import hmac
from typing import Any, Final, Protocol

from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
)
from sbp_lex.security.hybrid_signature import (
    HybridSignatureProvider,
    HybridVerificationContext,
    is_hybrid_provider,
    verify_hybrid_signed_object,
)


RULE_REGISTER_CONTRACT_ID: Final = "SBP_LEX_RULE_ARTIFACT_REGISTER_V2"
RULE_REGISTER_SCHEMA_STATUS: Final = "IMPLEMENTATION_DEFINED_V2_MECHANICS"
RULE_REGISTER_EVALUATOR_ROLE: Final = "RULE_ARTIFACT_REGISTER_EVALUATOR"
RULE_ARTIFACT_SOURCE_ROLE: Final = "RULE_ARTIFACT_SOURCE_AUTHORITY"
RULE_ARTIFACT_SIGNING_PURPOSE: Final = (
    "SBP_LEX_V2_RULE_ARTIFACT_REGISTER_ATTESTATION"
)

RULE_ARTIFACT_CLASSES: Final = (
    "constitutional",
    "statutory",
    "regulatory",
    "treaty",
)

RULE_REGISTER_ADMISSION_STAGE: Final = "rule_artifact_register:admission"
RULE_REGISTER_REVALIDATION_STAGE: Final = "rule_artifact_register:revalidation"

RULE_ARTIFACT_PASS: Final = "PASS"
RULE_ARTIFACT_ESCALATE: Final = "ESCALATE"
RULE_ARTIFACT_DENY: Final = "DENY"
ARTIFACT_ACTIVE: Final = "ACTIVE"

_SOURCE_FIELDS: Final = frozenset({
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
    "register_version",
    "prior_register_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
})

_SNAPSHOT_FIELDS: Final = frozenset({
    "contract_id",
    "schema_status",
    "rule_classes",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "register_version",
    "prior_register_digest",
})

_DETERMINATION_FIELDS: Final = frozenset({
    "result",
    "register_version",
    "artifacts",
    "conflicts",
    "universal_precedence_declared",
    "legal_interpretation_performed",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
})

_ARTIFACT_FIELDS: Final = frozenset({
    "rule_class",
    "artifact_id",
    "artifact_version",
    "jurisdiction",
    "authority_credential",
    "provenance",
    "effective_from",
    "effective_until",
    "status",
    "revocation_sequence",
    "artifact_digest",
})

_ARTIFACT_CREDENTIAL_FIELDS: Final = frozenset({
    "credential_id",
    "authority_role",
    "credential_digest",
})

_PROVENANCE_FIELDS: Final = frozenset({
    "source_id",
    "source_locator",
    "source_version",
    "source_digest",
    "issuing_authority_id",
})

_CONFLICT_FIELDS: Final = frozenset({
    "conflict_id",
    "artifact_references",
    "status",
    "escalation_required",
    "resolution_authority_credential",
    "resolution_digest",
})

_ARTIFACT_REFERENCE_FIELDS: Final = frozenset({
    "rule_class",
    "artifact_id",
    "artifact_version",
})

_RECORD_FIELDS: Final = frozenset({
    "contract_id",
    "schema_status",
    "rule_classes",
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "artifacts",
    "conflicts",
    "universal_precedence_declared",
    "legal_interpretation_performed",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
})


class RuleArtifactAttestationProvider(HybridSignatureProvider, Protocol):
    rule_artifact_attestation_admitted: bool


class RuleArtifactEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate_rule_artifacts(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]: ...


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _state_hash_exact(value: Any) -> bool:
    return value == GENESIS_HASH or is_sha512(value)


def _provider_admitted(provider: RuleArtifactAttestationProvider | None) -> bool:
    return (
        is_hybrid_provider(provider)
        and getattr(provider, "rule_artifact_attestation_admitted", None) is True
    )


def _trust_context_owner_pinned(
    context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> bool:
    if (
        not isinstance(context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not is_sha512(owner_pinned_context_digest)
    ):
        return False
    return hmac.compare_digest(context.context_digest, owner_pinned_context_digest)


def _evaluator_exact(evaluator: Any) -> bool:
    metadata = (
        getattr(evaluator, "evaluator_id", None),
        getattr(evaluator, "evaluator_version", None),
        getattr(evaluator, "authority_role", None),
        getattr(evaluator, "authority_credential_id", None),
    )
    return (
        all(_text(value) for value in metadata)
        and metadata[2] == RULE_REGISTER_EVALUATOR_ROLE
        and callable(getattr(evaluator, "evaluate_rule_artifacts", None))
    )


def _snapshot(state: dict[str, Any], *, stage: str, sequence: int) -> dict[str, Any]:
    return {
        "contract_id": RULE_REGISTER_CONTRACT_ID,
        "schema_status": RULE_REGISTER_SCHEMA_STATUS,
        "rule_classes": list(RULE_ARTIFACT_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": state.get("request_fingerprint"),
        "pre_evaluation_state_hash": state.get("state_hash"),
        "evaluation_time": state.get("evaluation_time"),
        "register_version": state.get("rule_artifact_register_version"),
        "prior_register_digest": state.get("rule_artifact_register_digest"),
    }


def _snapshot_exact(snapshot: Any) -> bool:
    return (
        type(snapshot) is dict
        and set(snapshot) == _SNAPSHOT_FIELDS
        and snapshot.get("contract_id") == RULE_REGISTER_CONTRACT_ID
        and snapshot.get("schema_status") == RULE_REGISTER_SCHEMA_STATUS
        and snapshot.get("rule_classes") == list(RULE_ARTIFACT_CLASSES)
        and _text(snapshot.get("stage"))
        and type(snapshot.get("evaluation_sequence")) is int
        and snapshot["evaluation_sequence"] >= 1
        and is_sha512(snapshot.get("request_fingerprint"))
        and _state_hash_exact(snapshot.get("pre_evaluation_state_hash"))
        and type(snapshot.get("evaluation_time")) is int
        and snapshot["evaluation_time"] >= 0
        and _text(snapshot.get("register_version"))
        and (
            snapshot.get("prior_register_digest") is None
            or is_sha512(snapshot.get("prior_register_digest"))
        )
    )


def _artifact_key(artifact: dict[str, Any]) -> tuple[int, str, str]:
    return (
        RULE_ARTIFACT_CLASSES.index(artifact["rule_class"]),
        artifact["artifact_id"],
        artifact["artifact_version"],
    )


def _artifact_identity(artifact: dict[str, Any]) -> tuple[str, str, str]:
    return (
        artifact["rule_class"],
        artifact["artifact_id"],
        artifact["artifact_version"],
    )


def _artifact_error(artifact: Any, *, evaluation_time: int) -> str | None:
    if type(artifact) is not dict or set(artifact) != _ARTIFACT_FIELDS:
        return "RULE_ARTIFACT_SHAPE_INVALID"
    if artifact.get("rule_class") not in RULE_ARTIFACT_CLASSES:
        return "RULE_ARTIFACT_CLASS_INVALID"
    if not all(
        _text(artifact.get(field))
        for field in ("artifact_id", "artifact_version", "jurisdiction")
    ):
        return "RULE_ARTIFACT_IDENTITY_INVALID"
    credential = artifact.get("authority_credential")
    if (
        type(credential) is not dict
        or set(credential) != _ARTIFACT_CREDENTIAL_FIELDS
        or not _text(credential.get("credential_id"))
        or credential.get("authority_role") != RULE_ARTIFACT_SOURCE_ROLE
        or not is_sha512(credential.get("credential_digest"))
    ):
        return "RULE_ARTIFACT_AUTHORITY_CREDENTIAL_INVALID"
    provenance = artifact.get("provenance")
    if (
        type(provenance) is not dict
        or set(provenance) != _PROVENANCE_FIELDS
        or not all(
            _text(provenance.get(field))
            for field in (
                "source_id",
                "source_locator",
                "source_version",
                "issuing_authority_id",
            )
        )
        or not is_sha512(provenance.get("source_digest"))
        or provenance.get("issuing_authority_id")
        != credential.get("credential_id")
    ):
        return "RULE_ARTIFACT_PROVENANCE_INVALID"
    effective_from = artifact.get("effective_from")
    effective_until = artifact.get("effective_until")
    if (
        type(effective_from) is not int
        or effective_from < 0
        or (
            effective_until is not None
            and (
                type(effective_until) is not int
                or effective_until <= effective_from
            )
        )
    ):
        return "RULE_ARTIFACT_EFFECTIVE_WINDOW_INVALID"
    if (
        artifact.get("status") != ARTIFACT_ACTIVE
        or evaluation_time < effective_from
        or (effective_until is not None and evaluation_time >= effective_until)
    ):
        return "RULE_ARTIFACT_STALE_OR_REVOKED"
    if (
        type(artifact.get("revocation_sequence")) is not int
        or artifact["revocation_sequence"] < 0
        or not is_sha512(artifact.get("artifact_digest"))
    ):
        return "RULE_ARTIFACT_REVOCATION_OR_DIGEST_INVALID"
    return None


def _artifacts_error(
    artifacts: Any,
    *,
    evaluation_time: int,
) -> str | None:
    if type(artifacts) is not list or len(artifacts) < len(RULE_ARTIFACT_CLASSES):
        return "RULE_ARTIFACT_CLASSES_INCOMPLETE"
    identities: set[tuple[str, str, str]] = set()
    id_versions: set[tuple[str, str]] = set()
    class_counts = {rule_class: 0 for rule_class in RULE_ARTIFACT_CLASSES}
    for artifact in artifacts:
        error = _artifact_error(artifact, evaluation_time=evaluation_time)
        if error is not None:
            return error
        identity = _artifact_identity(artifact)
        id_version = (artifact["artifact_id"], artifact["artifact_version"])
        if identity in identities or id_version in id_versions:
            return "RULE_ARTIFACT_ID_VERSION_DUPLICATE"
        identities.add(identity)
        id_versions.add(id_version)
        class_counts[artifact["rule_class"]] += 1
    if any(count < 1 for count in class_counts.values()):
        return "RULE_ARTIFACT_CLASSES_INCOMPLETE"
    if artifacts != sorted(artifacts, key=_artifact_key):
        return "RULE_ARTIFACT_ORDER_NOT_CANONICAL"
    return None


def _conflicts_error(conflicts: Any, *, artifacts: list[dict[str, Any]]) -> str | None:
    if type(conflicts) is not list:
        return "RULE_ARTIFACT_CONFLICTS_INVALID"
    valid_references = {_artifact_identity(artifact) for artifact in artifacts}
    conflict_ids: set[str] = set()
    for conflict in conflicts:
        if type(conflict) is not dict or set(conflict) != _CONFLICT_FIELDS:
            return "RULE_ARTIFACT_CONFLICT_SHAPE_INVALID"
        conflict_id = conflict.get("conflict_id")
        if type(conflict_id) is not str or not _text(conflict_id) or conflict_id in conflict_ids:
            return "RULE_ARTIFACT_CONFLICT_ID_INVALID"
        conflict_ids.add(conflict_id)
        references = conflict.get("artifact_references")
        if type(references) is not list or len(references) < 2:
            return "RULE_ARTIFACT_CONFLICT_REFERENCES_INVALID"
        observed: list[tuple[str, str, str]] = []
        for reference in references:
            if type(reference) is not dict or set(reference) != _ARTIFACT_REFERENCE_FIELDS:
                return "RULE_ARTIFACT_CONFLICT_REFERENCES_INVALID"
            identity = (
                reference.get("rule_class"),
                reference.get("artifact_id"),
                reference.get("artifact_version"),
            )
            if identity not in valid_references or identity in observed:
                return "RULE_ARTIFACT_CONFLICT_REFERENCES_INVALID"
            observed.append(identity)
        if observed != sorted(
            observed,
            key=lambda identity: (
                RULE_ARTIFACT_CLASSES.index(identity[0]), identity[1], identity[2]
            ),
        ):
            return "RULE_ARTIFACT_CONFLICT_ORDER_NOT_CANONICAL"
        if (
            conflict.get("status") != "UNRESOLVED"
            or conflict.get("escalation_required") is not True
            or conflict.get("resolution_authority_credential") is not None
            or conflict.get("resolution_digest") is not None
        ):
            return "RULE_ARTIFACT_CONFLICT_RESOLUTION_NOT_ADMITTED"
    if conflicts != sorted(conflicts, key=lambda conflict: conflict["conflict_id"]):
        return "RULE_ARTIFACT_CONFLICT_ORDER_NOT_CANONICAL"
    return None


def _determination_error(
    determination: Any,
    *,
    snapshot: dict[str, Any],
) -> str | None:
    if type(determination) is not dict or set(determination) != _DETERMINATION_FIELDS:
        return "RULE_ARTIFACT_DETERMINATION_SHAPE_INVALID"
    if determination.get("register_version") != snapshot.get("register_version"):
        return "RULE_ARTIFACT_REGISTER_VERSION_MISMATCH"
    artifacts = determination.get("artifacts")
    error = _artifacts_error(
        artifacts,
        evaluation_time=snapshot["evaluation_time"],
    )
    if error is not None:
        return error
    if type(artifacts) is not list:
        return "RULE_ARTIFACTS_INVALID"
    conflicts = determination.get("conflicts")
    error = _conflicts_error(conflicts, artifacts=artifacts)
    if error is not None:
        return error
    expected_result = RULE_ARTIFACT_ESCALATE if conflicts else RULE_ARTIFACT_PASS
    if determination.get("result") != expected_result:
        return "RULE_ARTIFACT_RESULT_CONFLICT_MISMATCH"
    false_fields = (
        "universal_precedence_declared",
        "legal_interpretation_performed",
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_authority_granted",
        "pipeline_bypass_permitted",
    )
    if any(determination.get(field) is not False for field in false_fields):
        return "RULE_ARTIFACT_PROHIBITED_AUTHORITY_OR_INTERPRETATION"
    return None


def _source_error(
    source: Any,
    *,
    snapshot: dict[str, Any],
    evaluator: RuleArtifactEvaluator,
    provider: RuleArtifactAttestationProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    if not _provider_admitted(provider):
        return "RULE_ARTIFACT_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if not _evaluator_exact(evaluator):
        return "RULE_ARTIFACT_EVALUATOR_INVALID"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return "RULE_ARTIFACT_SOURCE_SHAPE_INVALID"
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not _trust_context_owner_pinned(
            trust_context, owner_pinned_context_digest
        )
    ):
        return "RULE_ARTIFACT_OWNER_PIN_NOT_INJECTED_OR_INVALID"
    if not verify_hybrid_signed_object(
        source,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_purpose=RULE_ARTIFACT_SIGNING_PURPOSE,
        require_effect_authority=False,
    ):
        return "RULE_ARTIFACT_SIGNATURE_INVALID"
    if (
        source.get("contract_id") != RULE_REGISTER_CONTRACT_ID
        or source.get("schema_status") != RULE_REGISTER_SCHEMA_STATUS
        or source.get("evaluator_id") != getattr(evaluator, "evaluator_id", None)
        or source.get("evaluator_version")
        != getattr(evaluator, "evaluator_version", None)
        or source.get("authority_credential")
        != {
            "credential_id": getattr(evaluator, "authority_credential_id", None),
            "authority_role": RULE_REGISTER_EVALUATOR_ROLE,
        }
    ):
        return "RULE_ARTIFACT_SOURCE_AUTHORITY_INVALID"
    expected = {
        "stage": snapshot["stage"],
        "evaluation_sequence": snapshot["evaluation_sequence"],
        "request_fingerprint": snapshot["request_fingerprint"],
        "pre_evaluation_state_hash": snapshot["pre_evaluation_state_hash"],
        "evaluation_time": snapshot["evaluation_time"],
        "register_version": snapshot["register_version"],
        "prior_register_digest": snapshot["prior_register_digest"],
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in expected.items()):
        return "RULE_ARTIFACT_EVALUATION_BINDING_MISMATCH"
    return _determination_error(source.get("determination"), snapshot=snapshot)


def _false_fields() -> dict[str, bool]:
    return {
        "universal_precedence_declared": False,
        "legal_interpretation_performed": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }


def _apply_record(state: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    trace = state["rule_artifact_register_trace"]
    trace.append(record)
    state["rule_artifact_register_record"] = deepcopy(record)
    state["rule_artifact_register_digest"] = canonical_integrity_hash(trace)
    state["rule_artifact_register_result"] = record["result"]
    state["rule_artifact_register_reason"] = record["reason"]
    for field, value in _false_fields().items():
        state[f"rule_artifact_register_{field}"] = value
    return state


def evaluate_rule_artifact_register(
    state: dict[str, Any],
    *,
    stage: str,
    evaluator: RuleArtifactEvaluator | None,
    attestation_provider: RuleArtifactAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> dict[str, Any]:
    """Admit one signed register evaluation fail closed."""

    trace = state.setdefault("rule_artifact_register_trace", [])
    if type(trace) is not list:
        raise ValueError("RULE_ARTIFACT_TRACE_INVALID")
    sequence = len(trace) + 1
    snapshot = _snapshot(state, stage=stage, sequence=sequence)
    source: dict[str, Any] | None = None
    error: str | None = None

    if not _snapshot_exact(snapshot):
        error = "RULE_ARTIFACT_SNAPSHOT_INVALID"
    elif sequence == 1 and stage != RULE_REGISTER_ADMISSION_STAGE:
        error = "RULE_ARTIFACT_ADMISSION_STAGE_REQUIRED"
    elif sequence > 1 and stage != RULE_REGISTER_REVALIDATION_STAGE:
        error = "RULE_ARTIFACT_REVALIDATION_STAGE_REQUIRED"
    elif sequence == 1 and snapshot["prior_register_digest"] is not None:
        error = "RULE_ARTIFACT_UNEXPECTED_PRIOR_DIGEST"
    elif sequence > 1 and snapshot["prior_register_digest"] != _safe_hash(trace):
        error = "RULE_ARTIFACT_PRIOR_DIGEST_MISMATCH"
    elif sequence > 1 and (
        type(trace[-1]) is not dict
        or trace[-1].get("result")
        not in {RULE_ARTIFACT_PASS, RULE_ARTIFACT_ESCALATE}
    ):
        error = "RULE_ARTIFACT_PRIOR_RESULT_INVALID"
    elif evaluator is None or not _evaluator_exact(evaluator):
        error = "RULE_ARTIFACT_EVALUATOR_NOT_INJECTED_OR_INVALID"
    elif not _provider_admitted(attestation_provider):
        error = "RULE_ARTIFACT_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    elif not _trust_context_owner_pinned(
        attestation_trust_context, owner_pinned_context_digest
    ):
        error = "RULE_ARTIFACT_OWNER_PIN_NOT_INJECTED_OR_INVALID"
    else:
        try:
            candidate = evaluator.evaluate_rule_artifacts(
                stage=stage,
                snapshot=deepcopy(snapshot),
            )
            source = candidate if type(candidate) is dict else None
        except Exception:
            error = "RULE_ARTIFACT_EVALUATOR_FAILED"
    if error is None and source is None:
        error = "RULE_ARTIFACT_SOURCE_INVALID"
    if error is None and source is not None and evaluator is not None:
        source_digest = _safe_hash(source)
        if source_digest is None:
            error = "RULE_ARTIFACT_SOURCE_INVALID"
        elif any(
            type(record) is dict
            and record.get("evaluation_source_digest") == source_digest
            for record in trace
        ):
            error = "RULE_ARTIFACT_ATTESTATION_REPLAY"
        else:
            error = _source_error(
                source,
                snapshot=snapshot,
                evaluator=evaluator,
                provider=attestation_provider,
                trust_context=attestation_trust_context,
                owner_pinned_context_digest=owner_pinned_context_digest,
            )
    determination = source.get("determination") if error is None and source is not None else None
    if error is None and type(determination) is not dict:
        error = "RULE_ARTIFACT_DETERMINATION_SHAPE_INVALID"
    if error is None and trace and type(determination) is dict:
        prior_artifacts = {
            _artifact_identity(artifact): artifact
            for artifact in trace[-1].get("artifacts", [])
        }
        current_artifacts = {
            _artifact_identity(artifact): artifact
            for artifact in determination["artifacts"]
        }
        if set(prior_artifacts) != set(current_artifacts):
            error = "RULE_ARTIFACT_REVALIDATION_SET_CHANGED"
        elif any(
            current_artifacts[key]["revocation_sequence"]
            < prior_artifacts[key]["revocation_sequence"]
            for key in prior_artifacts
        ):
            error = "RULE_ARTIFACT_REVOCATION_ROLLBACK"

    result = (
        determination["result"]
        if error is None and type(determination) is dict
        else RULE_ARTIFACT_DENY
    )
    reason = (
        error
        or (
            "rule_artifact_conflict_escalation_required"
            if result == RULE_ARTIFACT_ESCALATE
            else "rule_artifact_register_admitted"
        )
    )
    record = {
        "contract_id": RULE_REGISTER_CONTRACT_ID,
        "schema_status": RULE_REGISTER_SCHEMA_STATUS,
        "rule_classes": list(RULE_ARTIFACT_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "artifacts": (
            deepcopy(determination["artifacts"])
            if error is None and type(determination) is dict
            else []
        ),
        "conflicts": (
            deepcopy(determination["conflicts"])
            if error is None and type(determination) is dict
            else []
        ),
        **_false_fields(),
    }
    return _apply_record(state, record)


def verify_rule_artifact_register(
    state: dict[str, Any],
    *,
    evaluator: RuleArtifactEvaluator | None,
    attestation_provider: RuleArtifactAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    require_revalidation: bool = False,
) -> bool:
    """Verify an admitted or escalation-required register trace."""

    trace = state.get("rule_artifact_register_trace")
    if (
        evaluator is None
        or not _evaluator_exact(evaluator)
        or not _provider_admitted(attestation_provider)
        or not _trust_context_owner_pinned(
            attestation_trust_context, owner_pinned_context_digest
        )
        or type(trace) is not list
        or not trace
        or (require_revalidation and len(trace) < 2)
    ):
        return False
    prefix: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    previous_artifacts: dict[tuple[str, str, str], dict[str, Any]] | None = None
    for index, record in enumerate(trace):
        if type(record) is not dict or set(record) != _RECORD_FIELDS:
            return False
        expected_stage = (
            RULE_REGISTER_ADMISSION_STAGE
            if index == 0
            else RULE_REGISTER_REVALIDATION_STAGE
        )
        expected_prior = None if index == 0 else _safe_hash(prefix)
        if (
            record.get("contract_id") != RULE_REGISTER_CONTRACT_ID
            or record.get("schema_status") != RULE_REGISTER_SCHEMA_STATUS
            or record.get("rule_classes") != list(RULE_ARTIFACT_CLASSES)
            or record.get("stage") != expected_stage
            or record.get("evaluation_sequence") != index + 1
            or record.get("result")
            not in {RULE_ARTIFACT_PASS, RULE_ARTIFACT_ESCALATE}
            or any(record.get(field) is not False for field in _false_fields())
        ):
            return False
        snapshot = record.get("evaluation_snapshot")
        if type(snapshot) is not dict:
            return False
        if (
            not _snapshot_exact(snapshot)
            or snapshot.get("prior_register_digest") != expected_prior
            or record.get("evaluation_snapshot_digest") != _safe_hash(snapshot)
        ):
            return False
        source = record.get("evaluation_source")
        if type(source) is not dict:
            return False
        source_digest = _safe_hash(source)
        if (
            source_digest is None
            or source_digest in seen_sources
            or source_digest != record.get("evaluation_source_digest")
            or _source_error(
                source,
                snapshot=snapshot,
                evaluator=evaluator,
                provider=attestation_provider,
                trust_context=attestation_trust_context,
                owner_pinned_context_digest=owner_pinned_context_digest,
            )
            is not None
            or record.get("artifacts") != source["determination"]["artifacts"]
            or record.get("conflicts") != source["determination"]["conflicts"]
        ):
            return False
        seen_sources.add(source_digest)
        current_artifacts = {
            _artifact_identity(artifact): artifact
            for artifact in record["artifacts"]
        }
        if previous_artifacts is not None and (
            set(previous_artifacts) != set(current_artifacts)
            or any(
                current_artifacts[key]["revocation_sequence"]
                < previous_artifacts[key]["revocation_sequence"]
                for key in previous_artifacts
            )
        ):
            return False
        previous_artifacts = current_artifacts
        prefix.append(record)
    latest = trace[-1]
    if require_revalidation and latest.get("stage") != RULE_REGISTER_REVALIDATION_STAGE:
        return False
    latest_snapshot = latest["evaluation_snapshot"]
    live = {
        "request_fingerprint": state.get("request_fingerprint"),
        "pre_evaluation_state_hash": state.get("state_hash"),
        "evaluation_time": state.get("evaluation_time"),
        "register_version": state.get("rule_artifact_register_version"),
    }
    if any(latest_snapshot.get(field) != value for field, value in live.items()):
        return False
    expected_reason = (
        "rule_artifact_conflict_escalation_required"
        if latest["result"] == RULE_ARTIFACT_ESCALATE
        else "rule_artifact_register_admitted"
    )
    if (
        latest.get("reason") != expected_reason
        or state.get("rule_artifact_register_record") != latest
        or state.get("rule_artifact_register_digest") != _safe_hash(trace)
        or state.get("rule_artifact_register_result") != latest["result"]
        or state.get("rule_artifact_register_reason") != expected_reason
        or any(
            state.get(f"rule_artifact_register_{field}") is not value
            for field, value in _false_fields().items()
        )
    ):
        return False
    return True
