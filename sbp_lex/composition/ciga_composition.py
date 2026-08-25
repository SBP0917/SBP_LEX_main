"""Implementation-defined V2 mechanical contract for filed Claim 1.

The contract authenticates a composition manifest containing one digest for
each of the four capability classes named in the filed claim.  A valid record
proves only that those four identified component artifacts were composed into
one signed manifest.  It does not prove the substantive correctness, national
or sovereign scale, legal validity, simulation validity, identity assurance or
decision quality of any component, and it does not prove complete CIGA.

No composition record grants authority, licence, execution, effect permission
or pipeline bypass.
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


CIGA_COMPOSITION_CONTRACT_ID: Final = "SBP_LEX_CIGA_COMPOSITION_V2"
CIGA_COMPOSITION_SCHEMA_STATUS: Final = "IMPLEMENTATION_DEFINED_V2_MECHANICS"
CIGA_COMPOSITION_PROOF_SCOPE: Final = (
    "COMPOSITION_ONLY_NOT_SUBSTANTIVE_CIGA_PROOF"
)
CIGA_COMPOSITION_ROLE: Final = "CIGA_COMPOSITION_ATTESTATION_EVALUATOR"
CIGA_COMPOSITION_SIGNING_PURPOSE: Final = (
    "SBP_LEX_V2_CIGA_COMPOSITION_ATTESTATION"
)

CIGA_CAPABILITY_CLASSES: Final = (
    "legal computation",
    "simulation engines",
    "identity security",
    "sovereign-scale decision systems",
)

CIGA_COMPOSITION_ATTESTATION_STAGE: Final = "ciga_composition:attestation"
CIGA_COMPOSITION_REVALIDATION_STAGE: Final = "ciga_composition:revalidation"

COMPOSITION_PASS: Final = "PASS"
COMPOSITION_DENY: Final = "DENY"
COMPOSITION_ACTIVE: Final = "ACTIVE"
COMPOSITION_REVOKED: Final = "REVOKED"

_SOURCE_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "proof_scope",
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "composition_version",
    "prior_composition_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}

_SNAPSHOT_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "proof_scope",
    "capability_classes",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "composition_version",
    "prior_composition_digest",
}

_DETERMINATION_FIELDS: Final = {
    "result",
    "composition_version",
    "capability_attestations",
    "revocation_status",
    "revocation_sequence",
    "composition_only",
    "substantive_ciga_proven",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
}

_CAPABILITY_ATTESTATION_FIELDS: Final = {
    "capability_class",
    "component_id",
    "component_version",
    "component_digest",
}

_RECORD_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "proof_scope",
    "capability_classes",
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "capability_attestations",
    "revocation_status",
    "revocation_sequence",
    "composition_only",
    "substantive_ciga_proven",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
}


class CompositionAttestationRejected(ValueError):
    """Raised only for a structurally unusable trace container."""


class CompositionAttestationProvider(HybridSignatureProvider, Protocol):
    composition_attestation_admitted: bool


class CIGACompositionEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate_ciga_composition(
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


def _provider_admitted(provider: CompositionAttestationProvider | None) -> bool:
    return (
        is_hybrid_provider(provider)
        and getattr(provider, "composition_attestation_admitted", None) is True
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
        and metadata[2] == CIGA_COMPOSITION_ROLE
        and callable(getattr(evaluator, "evaluate_ciga_composition", None))
    )


def _snapshot(
    state: dict[str, Any],
    *,
    stage: str,
    sequence: int,
) -> dict[str, Any]:
    return {
        "contract_id": CIGA_COMPOSITION_CONTRACT_ID,
        "schema_status": CIGA_COMPOSITION_SCHEMA_STATUS,
        "proof_scope": CIGA_COMPOSITION_PROOF_SCOPE,
        "capability_classes": list(CIGA_CAPABILITY_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": state.get("request_fingerprint"),
        "pre_evaluation_state_hash": state.get("state_hash"),
        "evaluation_time": state.get("evaluation_time"),
        "composition_version": state.get("ciga_composition_version"),
        "prior_composition_digest": state.get("ciga_composition_digest"),
    }


def _snapshot_exact(snapshot: Any) -> bool:
    return (
        type(snapshot) is dict
        and set(snapshot) == _SNAPSHOT_FIELDS
        and snapshot.get("contract_id") == CIGA_COMPOSITION_CONTRACT_ID
        and snapshot.get("schema_status") == CIGA_COMPOSITION_SCHEMA_STATUS
        and snapshot.get("proof_scope") == CIGA_COMPOSITION_PROOF_SCOPE
        and snapshot.get("capability_classes") == list(CIGA_CAPABILITY_CLASSES)
        and _text(snapshot.get("stage"))
        and type(snapshot.get("evaluation_sequence")) is int
        and snapshot["evaluation_sequence"] >= 1
        and is_sha512(snapshot.get("request_fingerprint"))
        and _state_hash_exact(snapshot.get("pre_evaluation_state_hash"))
        and type(snapshot.get("evaluation_time")) is int
        and snapshot["evaluation_time"] >= 0
        and _text(snapshot.get("composition_version"))
        and (
            snapshot.get("prior_composition_digest") is None
            or is_sha512(snapshot.get("prior_composition_digest"))
        )
    )


def _capability_attestations_error(value: Any) -> str | None:
    if type(value) is not list:
        return "CIGA_COMPOSITION_CAPABILITIES_INVALID"
    observed_classes: list[Any] = []
    component_ids: set[str] = set()
    for attestation in value:
        if (
            type(attestation) is not dict
            or set(attestation) != _CAPABILITY_ATTESTATION_FIELDS
        ):
            return "CIGA_COMPOSITION_CAPABILITY_SHAPE_INVALID"
        capability_class = attestation.get("capability_class")
        component_id = attestation.get("component_id")
        observed_classes.append(capability_class)
        if (
            type(component_id) is not str
            or not _text(component_id)
            or component_id in component_ids
            or not _text(attestation.get("component_version"))
            or not is_sha512(attestation.get("component_digest"))
        ):
            return "CIGA_COMPOSITION_CAPABILITY_ATTESTATION_INVALID"
        component_ids.add(component_id)
    if observed_classes != list(CIGA_CAPABILITY_CLASSES):
        return "CIGA_COMPOSITION_CAPABILITY_SET_INVALID"
    return None


def _determination_error(
    determination: Any,
    *,
    snapshot: dict[str, Any],
) -> str | None:
    if (
        type(determination) is not dict
        or set(determination) != _DETERMINATION_FIELDS
    ):
        return "CIGA_COMPOSITION_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in {COMPOSITION_PASS, COMPOSITION_DENY}:
        return "CIGA_COMPOSITION_RESULT_INVALID"
    if determination.get("composition_version") != snapshot.get(
        "composition_version"
    ):
        return "CIGA_COMPOSITION_VERSION_BINDING_MISMATCH"
    capability_error = _capability_attestations_error(
        determination.get("capability_attestations")
    )
    if capability_error is not None:
        return capability_error
    if determination.get("revocation_status") not in {
        COMPOSITION_ACTIVE,
        COMPOSITION_REVOKED,
    }:
        return "CIGA_COMPOSITION_REVOCATION_STATUS_INVALID"
    sequence = determination.get("revocation_sequence")
    if type(sequence) is not int or sequence < 0:
        return "CIGA_COMPOSITION_REVOCATION_SEQUENCE_INVALID"
    if (
        determination["result"] == COMPOSITION_PASS
        and determination["revocation_status"] != COMPOSITION_ACTIVE
    ):
        return "CIGA_COMPOSITION_PASS_STATUS_INVALID"
    if (
        determination["revocation_status"] == COMPOSITION_REVOKED
        and determination["result"] != COMPOSITION_DENY
    ):
        return "CIGA_COMPOSITION_REVOKED_RESULT_INVALID"
    false_fields = (
        "substantive_ciga_proven",
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_authority_granted",
        "pipeline_bypass_permitted",
    )
    if (
        determination.get("composition_only") is not True
        or any(determination.get(field) is not False for field in false_fields)
    ):
        return "CIGA_COMPOSITION_AUTHORITY_OR_SCOPE_INVALID"
    return None


def _source_error(
    source: Any,
    *,
    snapshot: dict[str, Any],
    evaluator: CIGACompositionEvaluator,
    provider: CompositionAttestationProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    if not _provider_admitted(provider):
        return "CIGA_COMPOSITION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if not _evaluator_exact(evaluator):
        return "CIGA_COMPOSITION_EVALUATOR_CONTRACT_INVALID"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return "CIGA_COMPOSITION_SOURCE_SHAPE_INVALID"
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not _trust_context_owner_pinned(
            trust_context, owner_pinned_context_digest
        )
    ):
        return "CIGA_COMPOSITION_OWNER_PIN_NOT_INJECTED_OR_INVALID"
    if not verify_hybrid_signed_object(
        source,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_purpose=CIGA_COMPOSITION_SIGNING_PURPOSE,
        require_effect_authority=False,
    ):
        return "CIGA_COMPOSITION_ATTESTATION_INVALID"
    if (
        source.get("contract_id") != CIGA_COMPOSITION_CONTRACT_ID
        or source.get("schema_status") != CIGA_COMPOSITION_SCHEMA_STATUS
        or source.get("proof_scope") != CIGA_COMPOSITION_PROOF_SCOPE
    ):
        return "CIGA_COMPOSITION_CONTRACT_IDENTITY_INVALID"
    if source.get("evaluator_id") != getattr(evaluator, "evaluator_id", None):
        return "CIGA_COMPOSITION_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != getattr(
        evaluator, "evaluator_version", None
    ):
        return "CIGA_COMPOSITION_EVALUATOR_VERSION_MISMATCH"
    if source.get("authority_credential") != {
        "credential_id": getattr(evaluator, "authority_credential_id", None),
        "authority_role": CIGA_COMPOSITION_ROLE,
    }:
        return "CIGA_COMPOSITION_AUTHORITY_CREDENTIAL_INVALID"
    expected = {
        "stage": snapshot["stage"],
        "evaluation_sequence": snapshot["evaluation_sequence"],
        "request_fingerprint": snapshot["request_fingerprint"],
        "pre_evaluation_state_hash": snapshot["pre_evaluation_state_hash"],
        "evaluation_time": snapshot["evaluation_time"],
        "composition_version": snapshot["composition_version"],
        "prior_composition_digest": snapshot["prior_composition_digest"],
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in expected.items()):
        return "CIGA_COMPOSITION_EVALUATION_BINDING_MISMATCH"
    return _determination_error(source.get("determination"), snapshot=snapshot)


def _non_authorizing_fields() -> dict[str, bool]:
    return {
        "composition_only": True,
        "substantive_ciga_proven": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }


def _non_authorizing_state_fields() -> dict[str, bool]:
    return {
        "ciga_composition_scope_only": True,
        "ciga_composition_substantive_ciga_proven": False,
        "ciga_composition_authority_granted": False,
        "ciga_composition_licence_granted": False,
        "ciga_composition_execution_authority_granted": False,
        "ciga_composition_effect_authority_granted": False,
        "ciga_composition_pipeline_bypass_permitted": False,
    }


def _apply_record(state: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    trace = state["ciga_composition_trace"]
    trace.append(record)
    state["ciga_composition_record"] = deepcopy(record)
    state["ciga_composition_digest"] = canonical_integrity_hash(trace)
    state["ciga_composition_result"] = record["result"]
    state["ciga_composition_reason"] = record["reason"]
    state["ciga_composition_revocation_status"] = record["revocation_status"]
    state["ciga_composition_revocation_sequence"] = record[
        "revocation_sequence"
    ]
    state.update(_non_authorizing_state_fields())
    return state


def evaluate_ciga_composition(
    state: dict[str, Any],
    *,
    stage: str,
    evaluator: CIGACompositionEvaluator | None,
    attestation_provider: CompositionAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> dict[str, Any]:
    """Evaluate one signed composition attestation or revalidation."""

    trace = state.setdefault("ciga_composition_trace", [])
    if type(trace) is not list:
        raise CompositionAttestationRejected("CIGA_COMPOSITION_TRACE_INVALID")
    sequence = len(trace) + 1
    snapshot = _snapshot(state, stage=stage, sequence=sequence)
    source: dict[str, Any] | None = None
    error: str | None = None

    if not _snapshot_exact(snapshot):
        error = "CIGA_COMPOSITION_SNAPSHOT_INVALID"
    elif sequence == 1 and stage != CIGA_COMPOSITION_ATTESTATION_STAGE:
        error = "CIGA_COMPOSITION_ATTESTATION_STAGE_REQUIRED"
    elif sequence > 1 and stage != CIGA_COMPOSITION_REVALIDATION_STAGE:
        error = "CIGA_COMPOSITION_REVALIDATION_STAGE_REQUIRED"
    elif sequence == 1 and snapshot["prior_composition_digest"] is not None:
        error = "CIGA_COMPOSITION_UNEXPECTED_PRIOR_DIGEST"
    elif sequence > 1 and (
        snapshot["prior_composition_digest"] != _safe_hash(trace)
    ):
        error = "CIGA_COMPOSITION_PRIOR_DIGEST_MISMATCH"
    elif sequence > 1 and (
        type(trace[-1]) is not dict
        or trace[-1].get("result") != COMPOSITION_PASS
    ):
        error = "CIGA_COMPOSITION_PRIOR_RESULT_NOT_PASS"
    elif evaluator is None or not _evaluator_exact(evaluator):
        error = "CIGA_COMPOSITION_EVALUATOR_NOT_INJECTED_OR_INVALID"
    elif not _provider_admitted(attestation_provider):
        error = "CIGA_COMPOSITION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    elif not _trust_context_owner_pinned(
        attestation_trust_context, owner_pinned_context_digest
    ):
        error = "CIGA_COMPOSITION_OWNER_PIN_NOT_INJECTED_OR_INVALID"
    else:
        try:
            candidate = evaluator.evaluate_ciga_composition(
                stage=stage,
                snapshot=deepcopy(snapshot),
            )
            source = candidate if type(candidate) is dict else None
        except Exception:
            error = "CIGA_COMPOSITION_EVALUATOR_FAILED"

    if error is None and source is None:
        error = "CIGA_COMPOSITION_SOURCE_INVALID"
    if error is None and source is not None and evaluator is not None:
        source_digest = _safe_hash(source)
        if source_digest is None:
            error = "CIGA_COMPOSITION_SOURCE_INVALID"
        elif any(
            type(record) is dict
            and record.get("evaluation_source_digest") == source_digest
            for record in trace
        ):
            error = "CIGA_COMPOSITION_ATTESTATION_REPLAY"
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
        error = "CIGA_COMPOSITION_DETERMINATION_INVALID"
    if error is None and trace and type(determination) is dict:
        previous_sequence = trace[-1].get("revocation_sequence")
        current_sequence = determination.get("revocation_sequence")
        if (
            type(previous_sequence) is not int
            or type(current_sequence) is not int
            or current_sequence < previous_sequence
        ):
            error = "CIGA_COMPOSITION_REVOCATION_ROLLBACK"
        elif trace[-1].get("revocation_status") == COMPOSITION_REVOKED:
            error = "CIGA_COMPOSITION_REVOCATION_IRREVERSIBLE"

    result = (
        determination["result"]
        if error is None and type(determination) is dict
        else COMPOSITION_DENY
    )
    reason = (
        error
        or (
            "ciga_composition_attested"
            if result == COMPOSITION_PASS
            else "CIGA_COMPOSITION_DENIED"
        )
    )
    record = {
        "contract_id": CIGA_COMPOSITION_CONTRACT_ID,
        "schema_status": CIGA_COMPOSITION_SCHEMA_STATUS,
        "proof_scope": CIGA_COMPOSITION_PROOF_SCOPE,
        "capability_classes": list(CIGA_CAPABILITY_CLASSES),
        "stage": stage,
        "evaluation_sequence": sequence,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "capability_attestations": (
            deepcopy(determination["capability_attestations"])
            if error is None and type(determination) is dict
            else []
        ),
        "revocation_status": (
            determination["revocation_status"]
            if error is None and type(determination) is dict
            else None
        ),
        "revocation_sequence": (
            determination["revocation_sequence"]
            if error is None and type(determination) is dict
            else None
        ),
        **_non_authorizing_fields(),
    }
    return _apply_record(state, record)


def verify_ciga_composition(
    state: dict[str, Any],
    *,
    evaluator: CIGACompositionEvaluator | None,
    attestation_provider: CompositionAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    require_revalidation: bool = False,
) -> bool:
    """Verify the signed trace, composition digests and current live bindings."""

    trace = state.get("ciga_composition_trace")
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
    source_digests: set[str] = set()
    previous_revocation_sequence: int | None = None

    for index, record in enumerate(trace):
        if type(record) is not dict or set(record) != _RECORD_FIELDS:
            return False
        expected_stage = (
            CIGA_COMPOSITION_ATTESTATION_STAGE
            if index == 0
            else CIGA_COMPOSITION_REVALIDATION_STAGE
        )
        expected_prior = None if index == 0 else _safe_hash(prefix)
        if (
            record.get("contract_id") != CIGA_COMPOSITION_CONTRACT_ID
            or record.get("schema_status") != CIGA_COMPOSITION_SCHEMA_STATUS
            or record.get("proof_scope") != CIGA_COMPOSITION_PROOF_SCOPE
            or record.get("capability_classes") != list(CIGA_CAPABILITY_CLASSES)
            or record.get("stage") != expected_stage
            or record.get("evaluation_sequence") != index + 1
            or record.get("result") != COMPOSITION_PASS
            or record.get("reason") != "ciga_composition_attested"
            or record.get("revocation_status") != COMPOSITION_ACTIVE
            or record.get("composition_only") is not True
            or record.get("substantive_ciga_proven") is not False
            or record.get("authority_granted") is not False
            or record.get("licence_granted") is not False
            or record.get("execution_authority_granted") is not False
            or record.get("effect_authority_granted") is not False
            or record.get("pipeline_bypass_permitted") is not False
        ):
            return False
        snapshot = record.get("evaluation_snapshot")
        if type(snapshot) is not dict:
            return False
        if (
            not _snapshot_exact(snapshot)
            or snapshot.get("prior_composition_digest") != expected_prior
            or record.get("evaluation_snapshot_digest") != _safe_hash(snapshot)
        ):
            return False
        source = record.get("evaluation_source")
        if type(source) is not dict:
            return False
        source_digest = _safe_hash(source)
        if (
            source_digest is None
            or source_digest in source_digests
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
            or record.get("capability_attestations")
            != source["determination"]["capability_attestations"]
        ):
            return False
        source_digests.add(source_digest)
        revocation_sequence = record.get("revocation_sequence")
        if (
            type(revocation_sequence) is not int
            or (
                previous_revocation_sequence is not None
                and revocation_sequence < previous_revocation_sequence
            )
        ):
            return False
        previous_revocation_sequence = revocation_sequence
        prefix.append(record)

    latest = trace[-1]
    latest_snapshot = latest["evaluation_snapshot"]
    if (
        require_revalidation
        and latest.get("stage") != CIGA_COMPOSITION_REVALIDATION_STAGE
    ):
        return False
    live_bindings = {
        "request_fingerprint": state.get("request_fingerprint"),
        "pre_evaluation_state_hash": state.get("state_hash"),
        "evaluation_time": state.get("evaluation_time"),
        "composition_version": state.get("ciga_composition_version"),
    }
    if any(
        latest_snapshot.get(field) != value
        for field, value in live_bindings.items()
    ):
        return False
    expected_state_flags = _non_authorizing_state_fields()
    if (
        state.get("ciga_composition_record") != latest
        or state.get("ciga_composition_digest") != _safe_hash(trace)
        or state.get("ciga_composition_result") != COMPOSITION_PASS
        or state.get("ciga_composition_reason") != "ciga_composition_attested"
        or state.get("ciga_composition_revocation_status") != COMPOSITION_ACTIVE
        or state.get("ciga_composition_revocation_sequence")
        != latest.get("revocation_sequence")
        or any(state.get(field) is not value for field, value in expected_state_flags.items())
    ):
        return False
    return True
