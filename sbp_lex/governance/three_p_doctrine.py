from __future__ import annotations

from copy import deepcopy
from types import MappingProxyType
from typing import Any, Final, Protocol

from sbp_lex.security.integrity import (
    GENESIS_HASH,
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


THREE_P_DOCTRINE_ID: Final = "SBP_LEX_3P_CORE_FINAL_MASTER_SPEC_4_3_26"
THREE_P_AUTHORITY_ROLE: Final = "CONSTITUTIONAL_3P_EVALUATOR"
THREE_P_ATTESTATION_PURPOSE: Final = "SBP_LEX_V2_THREE_P_ATTESTATION"
THREE_P_PRIMITIVES: Final = ("P1", "P2", "P3")
THREE_P_DEFINITIONS: Final = MappingProxyType({
    "P1": MappingProxyType({
        "name": "Planetary Stability Engine (PSE)",
        "definition": (
            "Non-negotiable ecological and planetary constraint enforcement."
        ),
    }),
    "P2": MappingProxyType({
        "name": "Population Integrity Engine (PIE)",
        "definition": (
            "Human continuity, dignity, cohesion, and socio-economic stability "
            "preservation."
        ),
    }),
    "P3": MappingProxyType({
        "name": "Permanent Sovereign Governance Cycle (PSGC)",
        "definition": (
            "Continuous rule validation, lawful recalibration, and authority "
            "continuity loop."
        ),
    }),
})
MECHANICALLY_CONSTRAINED_PROCESSES: Final = (
    "optimisation",
    "modelling",
    "routing",
    "attestation",
    "licensing",
    "escalation",
    "execution",
    "lifecycle_governance",
    "obsolescence_modelling",
    "supersession",
)

_SATISFIED: Final = "SATISFIED"
_NOT_SATISFIED: Final = "NOT_SATISFIED"
_EVALUATION_FIELDS: Final = frozenset({
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_three_p_digest",
    "snapshot_digest",
    "determinations",
    "digest",
    "signature",
    "verified",
})


class ThreePCoreEvaluator(Protocol):
    """External evaluator for the exact constitutional 3P primitives.

    The evaluator supplies evidence-bearing determinations. The pipeline validates
    and constrains those determinations; it does not define substantive PSE, PIE,
    or PSGC evidence rules.
    """

    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate(
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


def _deny_evaluation(reason: str) -> dict[str, Any]:
    return {
        "values": {primitive: False for primitive in THREE_P_PRIMITIVES},
        "source": None,
        "reason": reason,
    }


def _token_digests(state: dict[str, Any]) -> dict[str, Any]:
    tokens = state.get("tokens")
    if type(tokens) is not dict:
        return {}
    return {
        token_name: token.get("digest") if type(token) is dict else None
        for token_name, token in sorted(tokens.items())
    }


def _evaluation_snapshot(
    state: dict[str, Any],
    *,
    stage: str,
    sequence: int,
) -> dict[str, Any]:
    return {
        "evaluation_stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": state.get("request_fingerprint"),
        "action": deepcopy(state.get("action")),
        "payload": deepcopy(state.get("payload")),
        "context": deepcopy(state.get("context")),
        "resolved_authority": deepcopy(state.get("resolved_authority")),
        "jurisdiction": deepcopy(state.get("jurisdiction")),
        "ap_acf_class": deepcopy(state.get("ap_acf_class")),
        "ap_acf_subclass": deepcopy(state.get("ap_acf_subclass")),
        "requested_autonomy_level": deepcopy(
            state.get("requested_autonomy_level")
        ),
        "requested_system_mode": deepcopy(state.get("requested_system_mode")),
        "autonomy_ceiling": deepcopy(state.get("autonomy_ceiling")),
        "operational_environment": deepcopy(
            state.get("operational_environment")
        ),
        "public_exposure": deepcopy(state.get("public_exposure")),
        "operational_scope": deepcopy(state.get("operational_scope")),
        "environment_modifiers": deepcopy(state.get("environment_modifiers")),
        "deployment_restrictions": deepcopy(
            state.get("deployment_restrictions")
        ),
        "deployment_scope": deepcopy(state.get("deployment_scope")),
        "license_profile": deepcopy(state.get("license_profile")),
        "evaluation_time": state.get("evaluation_time"),
        "state_hash": state.get("state_hash") or GENESIS_HASH,
        "active_results": {
            key: deepcopy(state.get(key))
            for key in (
                "authority_first_result",
                "procedural_truth_result",
                "classification_result",
                "licensing_result",
                "governance_result",
                "domain_result",
                "aurion15_result",
                "execution_result",
                "decision",
            )
        },
        "current_candidate": deepcopy(state.get("current_candidate")),
        "candidate_attempt_count": state.get("candidate_attempt_count"),
        "token_digests": _token_digests(state),
        "prior_three_p_digest": state.get("three_p_core_digest"),
        "three_p_history": deepcopy(state.get("three_p_trace", [])),
    }


def _provider_admitted(provider: SignatureProvider | None) -> bool:
    return (
        provider is not None
        and getattr(provider, "three_p_attestation_admitted", None) is True
    )


def _evidence_references_exact(references: Any) -> bool:
    if type(references) is not list or not references:
        return False
    evidence_ids: set[str] = set()
    for reference in references:
        if type(reference) is not dict or set(reference) != {
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        evidence_id = reference.get("evidence_id")
        source = reference.get("source")
        if type(evidence_id) is not str or not evidence_id:
            return False
        if evidence_id in evidence_ids:
            return False
        evidence_ids.add(evidence_id)
        if type(source) is not str or not source:
            return False
        if not is_sha512(reference.get("digest")):
            return False
    return True


def _determinations_exact(determinations: Any) -> bool:
    if type(determinations) is not dict or set(determinations) != set(
        THREE_P_PRIMITIVES
    ):
        return False
    for primitive in THREE_P_PRIMITIVES:
        determination = determinations[primitive]
        if type(determination) is not dict or set(determination) != {
            "result",
            "evidence_references",
        }:
            return False
        if determination.get("result") not in {_SATISFIED, _NOT_SATISFIED}:
            return False
        if not _evidence_references_exact(
            determination.get("evidence_references")
        ):
            return False
    return True


def _evaluation_attestation_error(
    source: Any,
    *,
    evaluator_id: str,
    evaluator_version: str,
    authority_credential_id: str,
    stage: str,
    sequence: int,
    snapshot: dict[str, Any],
    snapshot_digest: str,
    provider: SignatureProvider | None,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> str | None:
    if not _provider_admitted(provider):
        return "3P_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if type(source) is not dict or set(source) != _EVALUATION_FIELDS:
        return "3P_EVALUATOR_RESULT_SHAPE_INVALID"
    if not verify_signed_object(
        source,
        provider=provider,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        purpose=THREE_P_ATTESTATION_PURPOSE,
        allow_legacy_non_effect=False,
    ):
        return "3P_EVALUATION_ATTESTATION_INVALID"
    if source.get("evaluator_id") != evaluator_id:
        return "3P_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != evaluator_version:
        return "3P_EVALUATOR_VERSION_MISMATCH"
    credential = source.get("authority_credential")
    if credential != {
        "credential_id": authority_credential_id,
        "authority_role": THREE_P_AUTHORITY_ROLE,
    }:
        return "3P_AUTHORITY_CREDENTIAL_INVALID"
    expected = {
        "stage": stage,
        "evaluation_sequence": sequence,
        "request_fingerprint": snapshot.get("request_fingerprint"),
        "pre_evaluation_state_hash": snapshot.get("state_hash"),
        "evaluation_time": snapshot.get("evaluation_time"),
        "prior_three_p_digest": snapshot.get("prior_three_p_digest"),
        "snapshot_digest": snapshot_digest,
    }
    for field, expected_value in expected.items():
        if source.get(field) != expected_value:
            return f"3P_EVALUATION_BINDING_MISMATCH:{field}"
    if not _determinations_exact(source.get("determinations")):
        return "3P_EVIDENCE_CONTRACT_INVALID"
    return None


def _evaluate_source(
    state: dict[str, Any],
    evaluator: ThreePCoreEvaluator | None,
    attestation_provider: SignatureProvider | None,
    stage: str,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    trace = state.get("three_p_trace", [])
    if type(trace) is not list:
        return _deny_evaluation("3P_TRACE_INVALID"), {}
    sequence = len(trace) + 1
    snapshot = _evaluation_snapshot(state, stage=stage, sequence=sequence)
    snapshot_digest = _safe_hash(snapshot)
    if snapshot_digest is None:
        return _deny_evaluation("3P_SNAPSHOT_NOT_CANONICAL"), snapshot
    if evaluator is None:
        return _deny_evaluation("3P_EVALUATOR_NOT_INJECTED"), snapshot
    evaluator_id = getattr(evaluator, "evaluator_id", None)
    evaluator_version = getattr(evaluator, "evaluator_version", None)
    authority_role = getattr(evaluator, "authority_role", None)
    authority_credential_id = getattr(
        evaluator, "authority_credential_id", None
    )
    method = getattr(evaluator, "evaluate", None)
    if (
        not isinstance(evaluator_id, str)
        or not evaluator_id
        or not isinstance(evaluator_version, str)
        or not evaluator_version
        or not isinstance(authority_credential_id, str)
        or not authority_credential_id
        or type(authority_role) is not str
        or authority_role != THREE_P_AUTHORITY_ROLE
        or not callable(method)
    ):
        return _deny_evaluation("3P_EVALUATOR_CONTRACT_INVALID"), snapshot
    if not _provider_admitted(attestation_provider):
        return _deny_evaluation(
            "3P_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
        ), snapshot
    try:
        source = method(stage=stage, snapshot=deepcopy(snapshot))
    except Exception as exc:
        return _deny_evaluation(
            f"3P_EVALUATOR_ERROR:{type(exc).__name__}:{exc}"
        ), snapshot
    error = _evaluation_attestation_error(
        source,
        evaluator_id=evaluator_id,
        evaluator_version=evaluator_version,
        authority_credential_id=authority_credential_id,
        stage=stage,
        sequence=sequence,
        snapshot=snapshot,
        snapshot_digest=snapshot_digest,
        provider=attestation_provider,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    if error is not None:
        return _deny_evaluation(error), snapshot
    determinations = source["determinations"]
    values = {
        primitive: determinations[primitive]["result"] == _SATISFIED
        for primitive in THREE_P_PRIMITIVES
    }
    return {
        "values": values,
        "source": deepcopy(source),
        "reason": "3P_EVALUATOR_COMPLETED",
    }, snapshot


def _build_trace_entry(
    state: dict[str, Any],
    *,
    stage: str,
    record: dict[str, Any],
    record_digest: str,
) -> dict[str, Any]:
    trace = state.setdefault("three_p_trace", [])
    previous_trace_hash = trace[-1]["trace_hash"] if trace else GENESIS_HASH
    prior_three_p_digest = (
        trace[-1]["three_p_core_digest"] if trace else None
    )
    entry = {
        "stage": stage,
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "reason": record.get("reason"),
        "three_p_core_digest": record_digest,
        "evaluation_source_digest": record.get("evaluation_source_digest"),
        "prior_three_p_digest": prior_three_p_digest,
        "previous_trace_hash": previous_trace_hash,
        "authority_granted": False,
    }
    entry["trace_hash"] = canonical_integrity_hash(entry)
    return entry


def evaluate_three_p_core(
    state: dict[str, Any],
    *,
    evaluator: ThreePCoreEvaluator | None,
    attestation_provider: SignatureProvider | None = None,
    stage: str,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> dict[str, Any]:
    """Re-evaluate all three primitives; the result can only constrain authority."""

    evaluation, snapshot = _evaluate_source(
        state,
        evaluator,
        attestation_provider,
        stage,
        trust_context,
        owner_pinned_context_digest,
    )
    values = evaluation["values"]
    source = evaluation["source"]
    determinations = (
        source.get("determinations", {}) if type(source) is dict else {}
    )
    primitive_records = []
    for primitive in THREE_P_PRIMITIVES:
        passed = values.get(primitive) is True
        evidence_references = deepcopy(
            determinations.get(primitive, {}).get("evidence_references", [])
        )
        primitive_records.append(
            {
                "primitive": primitive,
                "name": THREE_P_DEFINITIONS[primitive]["name"],
                "definition": THREE_P_DEFINITIONS[primitive]["definition"],
                "result": "PASS" if passed else "DENY",
                "reason": (
                    f"{primitive}_EVALUATOR_PASS"
                    if passed
                    else f"{primitive}_EVALUATOR_DENY"
                ),
                "evidence_references": evidence_references,
                "evidence_digest": _safe_hash(evidence_references),
                "authority_granted": False,
            }
        )
    passed = all(record["result"] == "PASS" for record in primitive_records)
    source_digest = _safe_hash(source) if type(source) is dict else None
    snapshot_digest = _safe_hash(snapshot)
    record = {
        "doctrine": THREE_P_DOCTRINE_ID,
        "constitutional_layer": True,
        "evaluation_stage": stage,
        "evaluator_id": source.get("evaluator_id") if type(source) is dict else None,
        "evaluator_version": (
            source.get("evaluator_version") if type(source) is dict else None
        ),
        "authority_role": (
            source.get("authority_credential", {}).get("authority_role")
            if type(source) is dict
            else None
        ),
        "authority_credential_id": (
            source.get("authority_credential", {}).get("credential_id")
            if type(source) is dict
            else None
        ),
        "evaluation_sequence": (
            source.get("evaluation_sequence") if type(source) is dict else None
        ),
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": snapshot_digest,
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": source_digest,
        "primitive_order": list(THREE_P_PRIMITIVES),
        "primitives": primitive_records,
        "mechanically_constrained_processes": list(
            MECHANICALLY_CONSTRAINED_PROCESSES
        ),
        "result": "PASS" if passed else "DENY",
        "reason": "3P_CORE_SATISFIED" if passed else evaluation["reason"],
        "authority_granted": False,
    }
    record_digest = canonical_integrity_hash(record)
    trace_entry = _build_trace_entry(
        state,
        stage=stage,
        record=record,
        record_digest=record_digest,
    )
    state["three_p_core_record"] = record
    state["three_p_core_result"] = record["result"]
    state["three_p_core_reason"] = record["reason"]
    state["three_p_core_digest"] = record_digest
    state["three_p_trace"].append(trace_entry)
    state["three_p_trace_hash"] = trace_entry["trace_hash"]
    return state


def _record_is_exact(
    record: Any,
    *,
    attestation_provider: SignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> bool:
    if type(record) is not dict:
        return False
    if record.get("doctrine") != THREE_P_DOCTRINE_ID:
        return False
    if record.get("constitutional_layer") is not True:
        return False
    if type(record.get("evaluation_stage")) is not str:
        return False
    evaluator_id = record.get("evaluator_id")
    evaluator_version = record.get("evaluator_version")
    credential_id = record.get("authority_credential_id")
    if (
        not isinstance(evaluator_id, str)
        or not evaluator_id
        or not isinstance(evaluator_version, str)
        or not evaluator_version
        or not isinstance(credential_id, str)
        or not credential_id
    ):
        return False
    if record.get("authority_role") != THREE_P_AUTHORITY_ROLE:
        return False
    sequence = record.get("evaluation_sequence")
    if type(sequence) is not int or sequence < 1:
        return False
    source = record.get("evaluation_source")
    snapshot = record.get("evaluation_snapshot")
    if type(source) is not dict or type(snapshot) is not dict:
        return False
    snapshot_digest = _safe_hash(snapshot)
    if (
        snapshot_digest is None
        or snapshot_digest != record.get("evaluation_snapshot_digest")
    ):
        return False
    error = _evaluation_attestation_error(
        source,
        evaluator_id=evaluator_id,
        evaluator_version=evaluator_version,
        authority_credential_id=credential_id,
        stage=record["evaluation_stage"],
        sequence=sequence,
        snapshot=snapshot,
        snapshot_digest=snapshot_digest,
        provider=attestation_provider,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    if error is not None:
        return False
    source_digest = _safe_hash(source)
    if source_digest is None or source_digest != record.get(
        "evaluation_source_digest"
    ):
        return False
    if record.get("primitive_order") != list(THREE_P_PRIMITIVES):
        return False
    if record.get("mechanically_constrained_processes") != list(
        MECHANICALLY_CONSTRAINED_PROCESSES
    ):
        return False
    if (
        record.get("result") != "PASS"
        or record.get("reason") != "3P_CORE_SATISFIED"
        or record.get("authority_granted") is not False
    ):
        return False
    determinations = source["determinations"]
    if any(
        determinations[primitive]["result"] != _SATISFIED
        for primitive in THREE_P_PRIMITIVES
    ):
        return False
    primitives = record.get("primitives")
    if type(primitives) is not list or len(primitives) != len(THREE_P_PRIMITIVES):
        return False
    for primitive, primitive_record in zip(THREE_P_PRIMITIVES, primitives):
        evidence_references = determinations[primitive]["evidence_references"]
        if primitive_record != {
            "primitive": primitive,
            "name": THREE_P_DEFINITIONS[primitive]["name"],
            "definition": THREE_P_DEFINITIONS[primitive]["definition"],
            "result": "PASS",
            "reason": f"{primitive}_EVALUATOR_PASS",
            "evidence_references": evidence_references,
            "evidence_digest": canonical_integrity_hash(evidence_references),
            "authority_granted": False,
        }:
            return False
    return True


def _trace_is_exact(state: dict[str, Any]) -> bool:
    trace = state.get("three_p_trace")
    if type(trace) is not list or not trace:
        return False
    previous_trace_hash = GENESIS_HASH
    prior_three_p_digest = None
    for index, entry in enumerate(trace, start=1):
        if type(entry) is not dict or set(entry) != {
            "stage",
            "evaluation_sequence",
            "result",
            "reason",
            "three_p_core_digest",
            "evaluation_source_digest",
            "prior_three_p_digest",
            "previous_trace_hash",
            "authority_granted",
            "trace_hash",
        }:
            return False
        if entry.get("evaluation_sequence") != index:
            return False
        if entry.get("result") != "PASS":
            return False
        if entry.get("authority_granted") is not False:
            return False
        if entry.get("prior_three_p_digest") != prior_three_p_digest:
            return False
        if entry.get("previous_trace_hash") != previous_trace_hash:
            return False
        if not is_sha512(entry.get("three_p_core_digest")):
            return False
        if not is_sha512(entry.get("evaluation_source_digest")):
            return False
        unsigned = {key: value for key, value in entry.items() if key != "trace_hash"}
        trace_hash = _safe_hash(unsigned)
        if trace_hash is None or entry.get("trace_hash") != trace_hash:
            return False
        previous_trace_hash = trace_hash
        prior_three_p_digest = entry["three_p_core_digest"]
    record = state.get("three_p_core_record", {})
    if trace[-1].get("stage") != record.get("evaluation_stage"):
        return False
    if trace[-1].get("three_p_core_digest") != state.get("three_p_core_digest"):
        return False
    if trace[-1].get("evaluation_source_digest") != record.get(
        "evaluation_source_digest"
    ):
        return False
    return state.get("three_p_trace_hash") == previous_trace_hash


def three_p_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "evaluation_stage": state.get("three_p_core_record", {}).get(
            "evaluation_stage"
        ),
        "three_p_core_digest": state.get("three_p_core_digest"),
        "three_p_core_result": state.get("three_p_core_result"),
        "three_p_trace_hash": state.get("three_p_trace_hash"),
    }


def _hash_binding_present(state: dict[str, Any]) -> bool:
    record = state.get("three_p_core_record")
    if type(record) is not dict:
        return False
    stage = record.get("evaluation_stage")
    expected_payload_hash = _safe_hash(three_p_hash_payload(state))
    if expected_payload_hash is None:
        return False
    chain = state.get("hash_chain")
    if type(chain) is not list or not verify_hash_chain_entries(
        chain, state.get("state_hash")
    ):
        return False
    bindings = [
        entry
        for entry in chain
        if type(entry) is dict
        and type(entry.get("stage")) is str
        and entry["stage"].startswith("three_p_core:")
    ]
    if not bindings:
        return False
    entry = bindings[-1]
    return (
        entry.get("stage") == f"three_p_core:{stage}"
        and entry.get("payload_hash") == expected_payload_hash
        and entry.get("previous_hash")
        == record.get("evaluation_source", {}).get("pre_evaluation_state_hash")
    )


def _snapshot_matches_current_stable_state(
    state: dict[str, Any], snapshot: dict[str, Any]
) -> bool:
    expected_fields = {
        "request_fingerprint": state.get("request_fingerprint"),
        "action": state.get("action"),
        "payload": state.get("payload"),
        "context": state.get("context"),
        "resolved_authority": state.get("resolved_authority"),
        "jurisdiction": state.get("jurisdiction"),
        "ap_acf_class": state.get("ap_acf_class"),
        "ap_acf_subclass": state.get("ap_acf_subclass"),
        "requested_autonomy_level": state.get("requested_autonomy_level"),
        "requested_system_mode": state.get("requested_system_mode"),
        "autonomy_ceiling": state.get("autonomy_ceiling"),
        "operational_environment": state.get("operational_environment"),
        "public_exposure": state.get("public_exposure"),
        "operational_scope": state.get("operational_scope"),
        "environment_modifiers": state.get("environment_modifiers"),
        "deployment_restrictions": state.get("deployment_restrictions"),
        "deployment_scope": state.get("deployment_scope"),
        "license_profile": state.get("license_profile"),
        "evaluation_time": state.get("evaluation_time"),
        "active_results": {
            key: state.get(key)
            for key in (
                "authority_first_result",
                "procedural_truth_result",
                "classification_result",
                "licensing_result",
                "governance_result",
                "domain_result",
                "aurion15_result",
                "execution_result",
                "decision",
            )
        },
        "current_candidate": state.get("current_candidate"),
        "candidate_attempt_count": state.get("candidate_attempt_count"),
        "token_digests": _token_digests(state),
    }
    return all(snapshot.get(key) == value for key, value in expected_fields.items())


def verify_three_p_core(
    state: dict[str, Any],
    *,
    attestation_provider: SignatureProvider | None = None,
    require_hash_binding: bool = True,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> bool:
    """Fail closed on absence, unsigned evidence, drift, mutation, or replay."""

    try:
        record = state.get("three_p_core_record")
        digest = state.get("three_p_core_digest")
        if not _record_is_exact(
            record,
            attestation_provider=attestation_provider,
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        ) or not is_sha512(digest):
            return False
        if type(record) is not dict:
            return False
        if state.get("three_p_core_result") != "PASS":
            return False
        if canonical_integrity_hash(record) != digest:
            return False
        if not _trace_is_exact(state):
            return False
        source = record["evaluation_source"]
        snapshot = record["evaluation_snapshot"]
        if source.get("request_fingerprint") != state.get("request_fingerprint"):
            return False
        if source.get("evaluation_time") != state.get("evaluation_time"):
            return False
        trace = state["three_p_trace"]
        if type(trace) is not list:
            return False
        if len(trace) != record["evaluation_sequence"]:
            return False
        prior_digest = (
            trace[-2].get("three_p_core_digest") if len(trace) > 1 else None
        )
        if source.get("prior_three_p_digest") != prior_digest:
            return False
        if snapshot.get("prior_three_p_digest") != prior_digest:
            return False
        if snapshot.get("three_p_history") != trace[:-1]:
            return False
        if snapshot.get("evaluation_stage") != record["evaluation_stage"]:
            return False
        if snapshot.get("evaluation_sequence") != record["evaluation_sequence"]:
            return False
        if not _snapshot_matches_current_stable_state(state, snapshot):
            return False
        return not require_hash_binding or _hash_binding_present(state)
    except (IntegrityContractError, KeyError, TypeError, ValueError):
        return False
