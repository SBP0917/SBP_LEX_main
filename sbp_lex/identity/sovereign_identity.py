"""Implementation-defined V2 mechanical contract for filed Claim 5.

This module admits signed sovereign-identity evidence.  Its schema is a V2
implementation contract, not wording supplied by the filed claim.  In
particular, ``biometric_attestation_digest`` is only a cryptographic reference
to evidence evaluated by an external issuer.  It is never biometric data or
proof that a biometric comparison occurred.

An admitted identity record grants no access, authority, licence, execution,
or effect permission.  Those decisions remain the responsibility of separate
downstream authority and execution boundaries.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol, TypeGuard

from sbp_lex.security.integrity import (
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


SOVEREIGN_IDENTITY_ISSUER_ROLE = "V2_SOVEREIGN_IDENTITY_EVIDENCE_ISSUER"
SOVEREIGN_IDENTITY_HASH_STAGE_PREFIX = "sovereign_identity:"
BIOMETRIC_ATTESTATION_EVIDENCE_ONLY = (
    "EVIDENCE_REFERENCE_ONLY_NOT_BIOMETRIC_PROOF"
)

IDENTITY_ADMISSION_STAGE = "sovereign_identity:admission"
IDENTITY_REVALIDATION_STAGE = "sovereign_identity:revalidation"

IDENTITY_VERIFIED = "VERIFIED"
IDENTITY_DENY = "DENY"

_SOURCE_FIELDS = {
    "evaluator_id",
    "evaluator_version",
    "issuer_credential",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_identity_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}

_DETERMINATION_FIELDS = {
    "result",
    "identity_credential_id",
    "bindings",
    "biometric_attestation_semantics",
    "revocation_status",
    "revocation_sequence",
    "evidence_references",
}

_BINDING_FIELDS = (
    "subject_identity",
    "biometric_attestation_digest",
    "jurisdictions",
    "access_grants",
)

_RECORD_FIELDS = {
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_identity_digest",
    "bindings",
    "result",
    "reason",
    "revocation_status",
    "revocation_sequence",
    "evaluation_source",
    "evaluation_source_digest",
    "biometric_proof_established",
    "access_granted",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
}


class SovereignIdentityAttestationProvider(SignatureProvider, Protocol):
    """A signing provider explicitly admitted for identity attestations."""

    identity_attestation_admitted: bool


class SovereignIdentityEvaluator(Protocol):
    """Injected issuer/evaluator.  No local issuer fallback is permitted."""

    identity_evaluator_id: str
    identity_evaluator_version: str
    identity_issuer_role: str
    identity_issuer_credential_id: str

    def evaluate_identity(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]: ...


def _text(value: Any) -> TypeGuard[str]:
    return type(value) is str and bool(value)


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _evaluator_metadata_valid(
    evaluator: Any,
) -> TypeGuard[SovereignIdentityEvaluator]:
    return (
        evaluator is not None
        and _text(getattr(evaluator, "identity_evaluator_id", None))
        and _text(getattr(evaluator, "identity_evaluator_version", None))
        and getattr(evaluator, "identity_issuer_role", None)
        == SOVEREIGN_IDENTITY_ISSUER_ROLE
        and _text(getattr(evaluator, "identity_issuer_credential_id", None))
        and callable(getattr(evaluator, "evaluate_identity", None))
    )


def _canonical_jurisdictions(value: Any) -> list[str] | None:
    if (
        type(value) is not list
        or not value
        or any(not _text(jurisdiction) for jurisdiction in value)
        or len(set(value)) != len(value)
    ):
        return None
    return sorted(value)


def _canonical_access_grants(
    value: Any,
    *,
    jurisdictions: list[str] | None,
) -> list[dict[str, Any]] | None:
    if type(value) is not list or not value or jurisdictions is None:
        return None
    grants: list[dict[str, Any]] = []
    grant_ids: set[str] = set()
    for grant in value:
        if type(grant) is not dict or set(grant) != {
            "grant_id",
            "jurisdiction",
            "actions",
        }:
            return None
        grant_id = grant.get("grant_id")
        jurisdiction = grant.get("jurisdiction")
        actions = grant.get("actions")
        if (
            not _text(grant_id)
            or grant_id in grant_ids
            or jurisdiction not in jurisdictions
            or type(actions) is not list
            or not actions
            or any(not _text(action) for action in actions)
            or len(set(actions)) != len(actions)
        ):
            return None
        grant_ids.add(grant_id)
        grants.append(
            {
                "grant_id": grant_id,
                "jurisdiction": jurisdiction,
                "actions": sorted(actions),
            }
        )
    return sorted(grants, key=lambda grant: grant["grant_id"])


def _identity_bindings(state: dict[str, Any]) -> dict[str, Any] | None:
    subject_identity = state.get("identity")
    if (
        type(subject_identity) is not dict
        or set(subject_identity) != {"subject_id"}
        or not _text(subject_identity.get("subject_id"))
    ):
        return None
    biometric_digest = state.get("biometric_attestation_digest")
    if not is_sha512(biometric_digest):
        return None
    jurisdictions = _canonical_jurisdictions(
        state.get("identity_jurisdictions")
    )
    access_grants = _canonical_access_grants(
        state.get("identity_access_grants"),
        jurisdictions=jurisdictions,
    )
    if jurisdictions is None or access_grants is None:
        return None
    return {
        "subject_identity": deepcopy(subject_identity),
        "biometric_attestation_digest": biometric_digest,
        "jurisdictions": jurisdictions,
        "access_grants": access_grants,
    }


def _snapshot(
    state: dict[str, Any],
    *,
    stage: str,
    sequence: int,
) -> dict[str, Any] | None:
    bindings = _identity_bindings(state)
    request_fingerprint = state.get("request_fingerprint")
    state_hash = state.get("state_hash")
    evaluation_time = state.get("evaluation_time")
    prior_digest = state.get("sovereign_identity_digest")
    if (
        bindings is None
        or not is_sha512(request_fingerprint)
        or not is_sha512(state_hash)
        or type(evaluation_time) is not int
        or evaluation_time < 0
        or (prior_digest is not None and not is_sha512(prior_digest))
    ):
        return None
    return {
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": request_fingerprint,
        "state_hash": state_hash,
        "evaluation_time": evaluation_time,
        "prior_identity_digest": prior_digest,
        "bindings": bindings,
    }


def _evidence_references_exact(
    value: Any,
    *,
    biometric_digest: str,
) -> bool:
    if type(value) is not list or not value:
        return False
    identifiers: set[str] = set()
    biometric_reference_found = False
    for reference in value:
        if type(reference) is not dict or set(reference) != {
            "evidence_id",
            "evidence_type",
            "source",
            "digest",
        }:
            return False
        evidence_id = reference.get("evidence_id")
        if not _text(evidence_id) or evidence_id in identifiers:
            return False
        identifiers.add(evidence_id)
        if not _text(reference.get("source")) or not is_sha512(
            reference.get("digest")
        ):
            return False
        if reference.get("evidence_type") == "BIOMETRIC_ATTESTATION_REFERENCE":
            if reference.get("digest") != biometric_digest:
                return False
            biometric_reference_found = True
        elif not _text(reference.get("evidence_type")):
            return False
    return biometric_reference_found


def _source_error(
    source: Any,
    *,
    snapshot: dict[str, Any],
    evaluator: SovereignIdentityEvaluator,
    provider: SovereignIdentityAttestationProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    if getattr(provider, "identity_attestation_admitted", None) is not True:
        return "SOVEREIGN_IDENTITY_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return "SOVEREIGN_IDENTITY_SOURCE_SHAPE_INVALID"
    if not verify_signed_object(
        source,
        provider=None,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        allow_legacy_non_effect=False,
    ):
        return "SOVEREIGN_IDENTITY_ATTESTATION_INVALID"
    if source.get("evaluator_id") != getattr(
        evaluator, "identity_evaluator_id", None
    ):
        return "SOVEREIGN_IDENTITY_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != getattr(
        evaluator, "identity_evaluator_version", None
    ):
        return "SOVEREIGN_IDENTITY_EVALUATOR_VERSION_MISMATCH"
    if source.get("issuer_credential") != {
        "credential_id": getattr(
            evaluator, "identity_issuer_credential_id", None
        ),
        "authority_role": SOVEREIGN_IDENTITY_ISSUER_ROLE,
    }:
        return "SOVEREIGN_IDENTITY_ISSUER_CREDENTIAL_INVALID"
    expected = {
        "stage": snapshot["stage"],
        "evaluation_sequence": snapshot["evaluation_sequence"],
        "request_fingerprint": snapshot["request_fingerprint"],
        "pre_evaluation_state_hash": snapshot["state_hash"],
        "evaluation_time": snapshot["evaluation_time"],
        "prior_identity_digest": snapshot["prior_identity_digest"],
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in expected.items()):
        return "SOVEREIGN_IDENTITY_EVALUATION_BINDING_MISMATCH"
    return None


def _determination_error(
    determination: Any,
    *,
    snapshot: dict[str, Any],
) -> str | None:
    if type(determination) is not dict or set(determination) != _DETERMINATION_FIELDS:
        return "SOVEREIGN_IDENTITY_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in {IDENTITY_VERIFIED, IDENTITY_DENY}:
        return "SOVEREIGN_IDENTITY_RESULT_INVALID"
    if not _text(determination.get("identity_credential_id")):
        return "SOVEREIGN_IDENTITY_CREDENTIAL_ID_INVALID"
    bindings = determination.get("bindings")
    if (
        type(bindings) is not dict
        or tuple(bindings) != _BINDING_FIELDS
        or bindings != snapshot.get("bindings")
    ):
        return "SOVEREIGN_IDENTITY_LIVE_BINDING_MISMATCH"
    if (
        determination.get("biometric_attestation_semantics")
        != BIOMETRIC_ATTESTATION_EVIDENCE_ONLY
    ):
        return "SOVEREIGN_IDENTITY_BIOMETRIC_SEMANTICS_INVALID"
    if determination.get("revocation_status") not in {"ACTIVE", "REVOKED"}:
        return "SOVEREIGN_IDENTITY_REVOCATION_STATUS_INVALID"
    revocation_sequence = determination.get("revocation_sequence")
    if type(revocation_sequence) is not int or revocation_sequence < 0:
        return "SOVEREIGN_IDENTITY_REVOCATION_SEQUENCE_INVALID"
    if determination["result"] == IDENTITY_VERIFIED:
        if determination["revocation_status"] != "ACTIVE":
            return "SOVEREIGN_IDENTITY_REVOKED_RESULT_INVALID"
    elif determination["revocation_status"] != "REVOKED":
        return "SOVEREIGN_IDENTITY_DENIAL_STATUS_INVALID"
    if not _evidence_references_exact(
        determination.get("evidence_references"),
        biometric_digest=bindings["biometric_attestation_digest"],
    ):
        return "SOVEREIGN_IDENTITY_EVIDENCE_CONTRACT_INVALID"
    return None


def _denial_record(
    *,
    stage: str,
    sequence: int,
    snapshot: dict[str, Any] | None,
    reason: str,
    source: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": (
            snapshot.get("request_fingerprint") if snapshot else None
        ),
        "pre_evaluation_state_hash": (
            snapshot.get("state_hash") if snapshot else None
        ),
        "evaluation_time": snapshot.get("evaluation_time") if snapshot else None,
        "prior_identity_digest": (
            snapshot.get("prior_identity_digest") if snapshot else None
        ),
        "bindings": deepcopy(snapshot.get("bindings")) if snapshot else None,
        "result": IDENTITY_DENY,
        "reason": reason,
        "revocation_status": None,
        "revocation_sequence": None,
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "biometric_proof_established": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
    }


def _apply_record(
    state: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    trace = state.setdefault("sovereign_identity_trace", [])
    trace.append(record)
    state["sovereign_identity_record"] = deepcopy(record)
    state["sovereign_identity_digest"] = canonical_integrity_hash(trace)
    state["sovereign_identity_result"] = record["result"]
    state["sovereign_identity_reason"] = record["reason"]
    state["sovereign_identity_revocation_status"] = record[
        "revocation_status"
    ]
    state["sovereign_identity_revocation_sequence"] = record[
        "revocation_sequence"
    ]
    return state


def _record_hash_payload(
    record: dict[str, Any],
    *,
    trace_digest: str | None,
) -> dict[str, Any]:
    return {
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "record_digest": _safe_hash(record),
        "trace_digest": trace_digest,
        "biometric_proof_established": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
    }


def sovereign_identity_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    """Return the canonical hash payload for the current identity trace prefix."""

    record = state.get("sovereign_identity_record")
    trace = state.get("sovereign_identity_trace")
    if type(record) is not dict:
        record = {}
    return _record_hash_payload(
        record,
        trace_digest=_safe_hash(trace),
    )


def evaluate_sovereign_identity(
    state: dict[str, Any],
    *,
    stage: str,
    evaluator: SovereignIdentityEvaluator | None,
    attestation_provider: SovereignIdentityAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> dict[str, Any]:
    """Evaluate one signed identity-admission or revalidation record."""

    trace = state.setdefault("sovereign_identity_trace", [])
    if type(trace) is not list:
        raise ValueError("SOVEREIGN_IDENTITY_TRACE_INVALID")
    sequence = len(trace) + 1
    snapshot = _snapshot(state, stage=stage, sequence=sequence)
    source: dict[str, Any] | None = None
    reason: str | None = None

    if snapshot is None:
        reason = "SOVEREIGN_IDENTITY_INPUT_BINDING_INVALID"
    elif sequence == 1 and stage != IDENTITY_ADMISSION_STAGE:
        reason = "SOVEREIGN_IDENTITY_ADMISSION_STAGE_REQUIRED"
    elif sequence > 1 and stage != IDENTITY_REVALIDATION_STAGE:
        reason = "SOVEREIGN_IDENTITY_REVALIDATION_STAGE_REQUIRED"
    elif sequence > 1 and (
        type(trace[-1]) is not dict
        or trace[-1].get("result") != IDENTITY_VERIFIED
    ):
        reason = "SOVEREIGN_IDENTITY_PRIOR_EVALUATION_NOT_VERIFIED"
    elif evaluator is None or not callable(
        getattr(evaluator, "evaluate_identity", None)
    ):
        reason = "SOVEREIGN_IDENTITY_EVALUATOR_NOT_INJECTED"
    elif not _evaluator_metadata_valid(evaluator):
        reason = "SOVEREIGN_IDENTITY_EVALUATOR_METADATA_INVALID"
    elif sequence == 1 and snapshot["prior_identity_digest"] is not None:
        reason = "SOVEREIGN_IDENTITY_PRIOR_DIGEST_INVALID"
    elif sequence > 1 and snapshot["prior_identity_digest"] != _safe_hash(trace):
        reason = "SOVEREIGN_IDENTITY_PRIOR_DIGEST_MISMATCH"
    else:
        try:
            candidate = evaluator.evaluate_identity(
                stage=stage,
                snapshot=deepcopy(snapshot),
            )
            source = candidate if type(candidate) is dict else None
        except Exception:
            source = None
            reason = "SOVEREIGN_IDENTITY_EVALUATOR_FAILED"

    if (
        reason is None
        and source is not None
        and snapshot is not None
        and _evaluator_metadata_valid(evaluator)
    ):
        source_digest = _safe_hash(source)
        if source_digest is None:
            reason = "SOVEREIGN_IDENTITY_SOURCE_NOT_HASHABLE"
        elif any(
            type(record) is dict
            and record.get("evaluation_source_digest") == source_digest
            for record in trace
        ):
            reason = "SOVEREIGN_IDENTITY_ATTESTATION_REPLAY"
        else:
            reason = _source_error(
                source,
                snapshot=snapshot,
                evaluator=evaluator,
                provider=attestation_provider,
                trust_context=attestation_trust_context,
                owner_pinned_context_digest=owner_pinned_context_digest,
            )
    elif reason is None:
        reason = "SOVEREIGN_IDENTITY_EVALUATOR_RESULT_INVALID"

    determination: dict[str, Any] | None = None
    if reason is None and source is not None and snapshot is not None:
        determination = source.get("determination")
        reason = _determination_error(determination, snapshot=snapshot)
    elif reason is None:
        reason = "SOVEREIGN_IDENTITY_INTERNAL_VALIDATION_FAILED"

    if reason is None and determination is not None and trace:
        previous_sequence = trace[-1].get("revocation_sequence")
        current_sequence = determination.get("revocation_sequence")
        if (
            type(previous_sequence) is not int
            or type(current_sequence) is not int
            or current_sequence < previous_sequence
        ):
            reason = "SOVEREIGN_IDENTITY_REVOCATION_ROLLBACK"
        elif trace[-1].get("revocation_status") == "REVOKED":
            reason = "SOVEREIGN_IDENTITY_REVOCATION_IRREVERSIBLE"

    if reason is not None:
        return _apply_record(
            state,
            _denial_record(
                stage=stage,
                sequence=sequence,
                snapshot=snapshot,
                reason=reason,
                source=source,
            ),
        )

    if snapshot is None or source is None or determination is None:
        return _apply_record(
            state,
            _denial_record(
                stage=stage,
                sequence=sequence,
                snapshot=snapshot,
                reason="SOVEREIGN_IDENTITY_INTERNAL_VALIDATION_FAILED",
                source=source,
            ),
        )

    result = determination["result"]
    record = {
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": snapshot["request_fingerprint"],
        "pre_evaluation_state_hash": snapshot["state_hash"],
        "evaluation_time": snapshot["evaluation_time"],
        "prior_identity_digest": snapshot["prior_identity_digest"],
        "bindings": deepcopy(determination["bindings"]),
        "result": result,
        "reason": (
            "sovereign_identity_evidence_verified"
            if result == IDENTITY_VERIFIED
            else "SOVEREIGN_IDENTITY_REVOKED"
        ),
        "revocation_status": determination["revocation_status"],
        "revocation_sequence": determination["revocation_sequence"],
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": canonical_integrity_hash(source),
        "biometric_proof_established": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
    }
    return _apply_record(state, record)


def _verify_sovereign_identity_exact(
    state: dict[str, Any],
    *,
    evaluator: SovereignIdentityEvaluator | None,
    attestation_provider: SovereignIdentityAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    require_revalidation: bool = False,
    require_hash_binding: bool = True,
) -> bool:
    """Verify the complete signed trace and its current live bindings."""

    trace = state.get("sovereign_identity_trace")
    if (
        not _evaluator_metadata_valid(evaluator)
        or type(trace) is not list
        or not trace
        or (require_revalidation and len(trace) < 2)
    ):
        return False

    live_bindings = _identity_bindings(state)
    if live_bindings is None:
        return False
    seen_sources: set[str] = set()
    prefix: list[dict[str, Any]] = []
    previous_revocation_sequence: int | None = None
    revoked_seen = False

    for index, record in enumerate(trace):
        if type(record) is not dict or set(record) != _RECORD_FIELDS:
            return False
        expected_stage = (
            IDENTITY_ADMISSION_STAGE
            if index == 0
            else IDENTITY_REVALIDATION_STAGE
        )
        expected_prior = (
            None if index == 0 else _safe_hash(prefix)
        )
        if (
            record.get("stage") != expected_stage
            or record.get("evaluation_sequence") != index + 1
            or record.get("prior_identity_digest") != expected_prior
            or record.get("bindings") != live_bindings
            or record.get("result") != IDENTITY_VERIFIED
            or record.get("reason") != "sovereign_identity_evidence_verified"
            or record.get("revocation_status") != "ACTIVE"
            or record.get("biometric_proof_established") is not False
            or record.get("access_granted") is not False
            or record.get("authority_granted") is not False
            or record.get("licence_granted") is not False
            or record.get("execution_authority_granted") is not False
            or record.get("effect_authority_granted") is not False
        ):
            return False
        source = record.get("evaluation_source")
        source_digest = _safe_hash(source)
        if (
            type(source) is not dict
            or source_digest is None
            or source_digest != record.get("evaluation_source_digest")
            or source_digest in seen_sources
        ):
            return False
        seen_sources.add(source_digest)
        snapshot = {
            "stage": record["stage"],
            "evaluation_sequence": record["evaluation_sequence"],
            "request_fingerprint": record["request_fingerprint"],
            "state_hash": record["pre_evaluation_state_hash"],
            "evaluation_time": record["evaluation_time"],
            "prior_identity_digest": record["prior_identity_digest"],
            "bindings": deepcopy(record["bindings"]),
        }
        if _source_error(
            source,
            snapshot=snapshot,
            evaluator=evaluator,
            provider=attestation_provider,
            trust_context=attestation_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        ) is not None:
            return False
        determination = source.get("determination")
        if _determination_error(determination, snapshot=snapshot) is not None:
            return False
        revocation_sequence = record.get("revocation_sequence")
        if (
            type(revocation_sequence) is not int
            or (
                previous_revocation_sequence is not None
                and revocation_sequence < previous_revocation_sequence
            )
            or revoked_seen
        ):
            return False
        previous_revocation_sequence = revocation_sequence
        revoked_seen = record.get("revocation_status") == "REVOKED"
        prefix.append(record)

    latest = trace[-1]
    if require_revalidation and latest.get("stage") != IDENTITY_REVALIDATION_STAGE:
        return False
    if (
        latest.get("request_fingerprint") != state.get("request_fingerprint")
        or latest.get("evaluation_time") != state.get("evaluation_time")
        or state.get("sovereign_identity_record") != latest
        or state.get("sovereign_identity_digest") != _safe_hash(trace)
        or state.get("sovereign_identity_result") != IDENTITY_VERIFIED
        or state.get("sovereign_identity_reason")
        != "sovereign_identity_evidence_verified"
        or state.get("sovereign_identity_revocation_status") != "ACTIVE"
        or state.get("sovereign_identity_revocation_sequence")
        != latest.get("revocation_sequence")
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
        expected_stage = record["stage"]
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
            != record["pre_evaluation_state_hash"]
        ):
            return False
        previous_index = matches[0][0]
    return True


def verify_sovereign_identity(
    state: dict[str, Any],
    *,
    evaluator: SovereignIdentityEvaluator | None,
    attestation_provider: SovereignIdentityAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
    require_revalidation: bool = False,
    require_hash_binding: bool = True,
) -> bool:
    """Verify the signed live trace and its chronological canonical bindings."""

    try:
        return _verify_sovereign_identity_exact(
            state,
            evaluator=evaluator,
            attestation_provider=attestation_provider,
            attestation_trust_context=attestation_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            require_revalidation=require_revalidation,
            require_hash_binding=require_hash_binding,
        )
    except Exception:
        return False


__all__ = [
    "BIOMETRIC_ATTESTATION_EVIDENCE_ONLY",
    "IDENTITY_ADMISSION_STAGE",
    "IDENTITY_DENY",
    "IDENTITY_REVALIDATION_STAGE",
    "IDENTITY_VERIFIED",
    "SOVEREIGN_IDENTITY_HASH_STAGE_PREFIX",
    "SOVEREIGN_IDENTITY_ISSUER_ROLE",
    "SovereignIdentityAttestationProvider",
    "SovereignIdentityEvaluator",
    "evaluate_sovereign_identity",
    "sovereign_identity_hash_payload",
    "verify_sovereign_identity",
]
