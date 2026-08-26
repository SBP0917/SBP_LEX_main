from __future__ import annotations

from copy import deepcopy
import hmac
from types import MappingProxyType
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


FILED_LIFECYCLE_SCHEMA_STATUS: Final = (
    "IMPLEMENTATION_DEFINED_V2_MECHANICS_NOT_FILED_SCHEMA"
)
FILED_LIFECYCLE_ATTESTATION_PURPOSE: Final = (
    "SBP_LEX_V2_FILED_LIFECYCLE_ATTESTATION"
)

AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION: Final = (
    "AI Obsolescence Lifecycle & Supersession Engine"
)
CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION: Final = (
    "Civilisational Successor Intelligence Transition Engine"
)
STRUCTURED_POST_AI_ERA_CONTINUITY: Final = (
    "Structured Post-AI Era Continuity Engine"
)

# The filed specification names these three engines but does not declare their
# runtime order. This deterministic order is a V2 implementation contract only.
FILED_LIFECYCLE_ORDER_AUTHORITY: Final = (
    "V2_IMPLEMENTATION_DEFINED_ORDER_NOT_FILED_ORDER"
)
FILED_LIFECYCLE_ORDER: Final = (
    AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION,
    CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION,
    STRUCTURED_POST_AI_ERA_CONTINUITY,
)
FILED_LIFECYCLE_ENGINE_IDS: Final = MappingProxyType({
    AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION: (
        "AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION"
    ),
    CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION: (
        "CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION"
    ),
    STRUCTURED_POST_AI_ERA_CONTINUITY: (
        "STRUCTURED_POST_AI_ERA_CONTINUITY"
    ),
})
FILED_LIFECYCLE_STAGES: Final = MappingProxyType({
    AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION: (
        "filed_lifecycle:ai_obsolescence_lifecycle_supersession"
    ),
    CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION: (
        "filed_lifecycle:civilisational_successor_intelligence_transition"
    ),
    STRUCTURED_POST_AI_ERA_CONTINUITY: (
        "filed_lifecycle:structured_post_ai_era_continuity"
    ),
})
FILED_LIFECYCLE_AUTHORITY_ROLE: Final = "FILED_LIFECYCLE_EVALUATOR"

LIFECYCLE_PASS: Final = "PASS"
LIFECYCLE_DENY: Final = "DENY"
LIFECYCLE_ESCALATE: Final = "ESCALATE"
_LIFECYCLE_RESULTS: Final = frozenset({
    LIFECYCLE_PASS,
    LIFECYCLE_DENY,
    LIFECYCLE_ESCALATE,
})

_EVALUATOR_METHODS: Final = MappingProxyType({
    AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION: (
        "evaluate_ai_obsolescence_lifecycle_supersession"
    ),
    CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION: (
        "evaluate_civilisational_successor_intelligence_transition"
    ),
    STRUCTURED_POST_AI_ERA_CONTINUITY: (
        "evaluate_structured_post_ai_era_continuity"
    ),
})

_SNAPSHOT_FIELDS: Final = frozenset({
    "schema_status",
    "lifecycle_engine",
    "lifecycle_engine_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "implementation_order",
    "request_fingerprint",
    "state_hash",
    "evaluation_time",
    "prior_lifecycle_digest",
    "three_p_core_result",
    "three_p_core_digest",
    "three_p_trace_hash",
    "three_p_trace",
    "skg_result",
    "skg_digest",
    "skg_record",
    "governance_result",
})
_SOURCE_FIELDS: Final = frozenset({
    "schema_status",
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "lifecycle_engine",
    "lifecycle_engine_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_lifecycle_digest",
    "three_p_core_digest",
    "three_p_trace_hash",
    "skg_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
})
_DETERMINATION_FIELDS: Final = frozenset({
    "result",
    "transition_beyond_current_ai_paradigms_modelled",
    "full_lifecycle_governance_envelope_secured",
    "lawful_authority_continuity_preserved",
    "violent_or_coercive_interaction_prohibited",
    "bound_to_three_p",
    "bound_to_skg",
    "authority_granted",
    "execution_authority_granted",
    "licence_granted",
    "governance_superseded",
    "evidence_references",
})
_RECORD_FIELDS: Final = frozenset({
    "schema_status",
    "lifecycle_engine",
    "lifecycle_engine_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "evidence_references",
    "authority_granted",
    "execution_authority_granted",
    "licence_granted",
    "governance_superseded",
})


class FiledLifecycleEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate_ai_obsolescence_lifecycle_supersession(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_civilisational_successor_intelligence_transition(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_structured_post_ai_era_continuity(
        self, *, stage: str, snapshot: dict[str, Any]
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


def _three_p_error(snapshot: dict[str, Any]) -> str | None:
    trace = snapshot.get("three_p_trace")
    digest = snapshot.get("three_p_core_digest")
    trace_hash = snapshot.get("three_p_trace_hash")
    if snapshot.get("three_p_core_result") != "PASS":
        return "FILED_LIFECYCLE_THREE_P_NOT_PASS"
    if not is_sha512(digest) or not is_sha512(trace_hash):
        return "FILED_LIFECYCLE_THREE_P_BINDING_INVALID"
    if type(trace) is not list or not trace or type(trace[-1]) is not dict:
        return "FILED_LIFECYCLE_THREE_P_TRACE_INVALID"
    if (
        trace[-1].get("three_p_core_digest") != digest
        or trace[-1].get("trace_hash") != trace_hash
    ):
        return "FILED_LIFECYCLE_THREE_P_TRACE_NOT_CURRENT"
    return None


def _skg_error(snapshot: dict[str, Any]) -> str | None:
    record = snapshot.get("skg_record")
    digest = snapshot.get("skg_digest")
    if snapshot.get("skg_result") != "PASS":
        return "FILED_LIFECYCLE_SKG_NOT_PASS"
    if type(record) is not dict or not record or not is_sha512(digest):
        return "FILED_LIFECYCLE_SKG_BINDING_INVALID"
    if _safe_hash(record) != digest:
        return "FILED_LIFECYCLE_SKG_DIGEST_MISMATCH"
    return None


def _snapshot_error(snapshot: Any) -> str | None:
    if type(snapshot) is not dict or set(snapshot) != _SNAPSHOT_FIELDS:
        return "FILED_LIFECYCLE_SNAPSHOT_SHAPE_INVALID"
    if snapshot.get("schema_status") != FILED_LIFECYCLE_SCHEMA_STATUS:
        return "FILED_LIFECYCLE_SCHEMA_STATUS_INVALID"
    engine = snapshot.get("lifecycle_engine")
    if engine not in FILED_LIFECYCLE_ORDER:
        return "FILED_LIFECYCLE_ENGINE_NOT_ADMITTED"
    if snapshot.get("lifecycle_engine_id") != FILED_LIFECYCLE_ENGINE_IDS[engine]:
        return "FILED_LIFECYCLE_ENGINE_ID_INVALID"
    if snapshot.get("stage") != FILED_LIFECYCLE_STAGES[engine]:
        return "FILED_LIFECYCLE_STAGE_INVALID"
    sequence = snapshot.get("evaluation_sequence")
    if type(sequence) is not int or sequence < 1:
        return "FILED_LIFECYCLE_SEQUENCE_INVALID"
    if (
        snapshot.get("implementation_order_authority")
        != FILED_LIFECYCLE_ORDER_AUTHORITY
        or snapshot.get("implementation_order") != list(FILED_LIFECYCLE_ORDER)
    ):
        return "FILED_LIFECYCLE_IMPLEMENTATION_ORDER_METADATA_INVALID"
    if not is_sha512(snapshot.get("request_fingerprint")):
        return "FILED_LIFECYCLE_REQUEST_FINGERPRINT_INVALID"
    if not is_sha512(snapshot.get("state_hash")):
        return "FILED_LIFECYCLE_STATE_HASH_INVALID"
    evaluation_time = snapshot.get("evaluation_time")
    if type(evaluation_time) is not int or evaluation_time < 0:
        return "FILED_LIFECYCLE_EVALUATION_TIME_INVALID"
    prior_digest = snapshot.get("prior_lifecycle_digest")
    if prior_digest is not None and not is_sha512(prior_digest):
        return "FILED_LIFECYCLE_PRIOR_DIGEST_INVALID"
    if snapshot.get("governance_result") != "ALLOW":
        return "FILED_LIFECYCLE_GOVERNANCE_PREREQUISITE_MISSING"
    return _three_p_error(snapshot) or _skg_error(snapshot)


def _evaluation_snapshot(
    state: dict[str, Any], *, lifecycle_engine: str, sequence: int
) -> dict[str, Any]:
    return {
        "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
        "lifecycle_engine": lifecycle_engine,
        "lifecycle_engine_id": FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine],
        "stage": FILED_LIFECYCLE_STAGES[lifecycle_engine],
        "evaluation_sequence": sequence,
        "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
        "implementation_order": list(FILED_LIFECYCLE_ORDER),
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash") or GENESIS_HASH,
        "evaluation_time": state.get("evaluation_time"),
        "prior_lifecycle_digest": state.get("filed_lifecycle_digest"),
        "three_p_core_result": state.get("three_p_core_result"),
        "three_p_core_digest": state.get("three_p_core_digest"),
        "three_p_trace_hash": state.get("three_p_trace_hash"),
        "three_p_trace": deepcopy(state.get("three_p_trace")),
        "skg_result": state.get("skg_authority_result"),
        "skg_digest": state.get("skg_authority_digest"),
        "skg_record": deepcopy(state.get("skg_authority_record")),
        "governance_result": state.get("governance_result"),
    }


def _determination_error(determination: Any, engine_id: str) -> str | None:
    if type(determination) is not dict or set(determination) != _DETERMINATION_FIELDS:
        return f"{engine_id}_DETERMINATION_SHAPE_INVALID"
    result = determination.get("result")
    if result not in _LIFECYCLE_RESULTS:
        return f"{engine_id}_RESULT_INVALID"
    boolean_fields = _DETERMINATION_FIELDS - {"result", "evidence_references"}
    if any(type(determination.get(field)) is not bool for field in boolean_fields):
        return f"{engine_id}_DETERMINATION_BOOLEAN_INVALID"
    if result == LIFECYCLE_PASS and (
        determination.get(
            "transition_beyond_current_ai_paradigms_modelled"
        )
        is not True
    ):
        return f"{engine_id}_TRANSITION_BEYOND_CURRENT_AI_NOT_MODELLED"
    if result == LIFECYCLE_PASS and (
        determination.get(
            "full_lifecycle_governance_envelope_secured"
        )
        is not True
    ):
        return f"{engine_id}_LIFECYCLE_GOVERNANCE_ENVELOPE_NOT_SECURED"
    if result == LIFECYCLE_PASS and (
        determination.get("lawful_authority_continuity_preserved") is not True
    ):
        return f"{engine_id}_LAWFUL_AUTHORITY_CONTINUITY_NOT_PRESERVED"
    if determination.get("violent_or_coercive_interaction_prohibited") is not True:
        return f"{engine_id}_NON_COERCION_NOT_ENFORCED"
    if determination.get("bound_to_three_p") is not True:
        return f"{engine_id}_THREE_P_SUBORDINATION_MISSING"
    if determination.get("bound_to_skg") is not True:
        return f"{engine_id}_SKG_SUBORDINATION_MISSING"
    for field in (
        "authority_granted",
        "execution_authority_granted",
        "licence_granted",
        "governance_superseded",
    ):
        if determination.get(field) is not False:
            return f"{engine_id}_{field.upper()}_PROHIBITED"
    if not _evidence_references_exact(determination.get("evidence_references")):
        return f"{engine_id}_EVIDENCE_REFERENCES_INVALID"
    return None


def _source_error(
    source: Any,
    *,
    lifecycle_engine: str,
    sequence: int,
    snapshot: dict[str, Any],
    evaluator: FiledLifecycleEvaluator,
    provider: HybridSignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    engine_id = FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]
    if (
        not is_hybrid_provider(provider)
        or getattr(provider, "lifecycle_attestation_admitted", None) is not True
    ):
        return "FILED_LIFECYCLE_ATTESTATION_PROVIDER_NOT_ADMITTED"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return f"{engine_id}_EVALUATOR_RESULT_SHAPE_INVALID"
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not _trust_context_owner_pinned(
            trust_context,
            owner_pinned_context_digest,
        )
    ):
        return "FILED_LIFECYCLE_OWNER_TRUST_PIN_INVALID"
    if not verify_hybrid_signed_object(
        source,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_purpose=FILED_LIFECYCLE_ATTESTATION_PURPOSE,
        require_effect_authority=False,
    ):
        return f"{engine_id}_EVALUATION_ATTESTATION_INVALID"
    if source.get("schema_status") != FILED_LIFECYCLE_SCHEMA_STATUS:
        return f"{engine_id}_SCHEMA_STATUS_INVALID"
    if source.get("evaluator_id") != getattr(evaluator, "evaluator_id", None):
        return f"{engine_id}_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != getattr(
        evaluator, "evaluator_version", None
    ):
        return f"{engine_id}_EVALUATOR_VERSION_MISMATCH"
    if source.get("authority_credential") != {
        "credential_id": getattr(evaluator, "authority_credential_id", None),
        "authority_role": FILED_LIFECYCLE_AUTHORITY_ROLE,
    }:
        return f"{engine_id}_AUTHORITY_CREDENTIAL_INVALID"
    expected = {
        "lifecycle_engine": lifecycle_engine,
        "lifecycle_engine_id": engine_id,
        "stage": FILED_LIFECYCLE_STAGES[lifecycle_engine],
        "evaluation_sequence": sequence,
        "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
        "request_fingerprint": snapshot.get("request_fingerprint"),
        "pre_evaluation_state_hash": snapshot.get("state_hash"),
        "evaluation_time": snapshot.get("evaluation_time"),
        "prior_lifecycle_digest": snapshot.get("prior_lifecycle_digest"),
        "three_p_core_digest": snapshot.get("three_p_core_digest"),
        "three_p_trace_hash": snapshot.get("three_p_trace_hash"),
        "skg_digest": snapshot.get("skg_digest"),
        "snapshot_digest": _safe_hash(snapshot),
    }
    for field, expected_value in expected.items():
        if source.get(field) != expected_value:
            return f"{engine_id}_EVALUATION_BINDING_MISMATCH:{field}"
    return _determination_error(source.get("determination"), engine_id)


def _record(
    *,
    lifecycle_engine: str,
    sequence: int,
    snapshot: dict[str, Any],
    source: dict[str, Any] | None,
    result: str,
    reason: str,
) -> dict[str, Any]:
    determination = source.get("determination", {}) if source else {}
    return {
        "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
        "lifecycle_engine": lifecycle_engine,
        "lifecycle_engine_id": FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine],
        "stage": FILED_LIFECYCLE_STAGES[lifecycle_engine],
        "evaluation_sequence": sequence,
        "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "evidence_references": deepcopy(
            determination.get("evidence_references", [])
        ),
        "authority_granted": False,
        "execution_authority_granted": False,
        "licence_granted": False,
        "governance_superseded": False,
    }


def _trace_records_error(
    trace: Any,
    results: Any,
    *,
    evaluator: FiledLifecycleEvaluator | None,
    provider: HybridSignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    require_complete: bool,
) -> str | None:
    if evaluator is None:
        return "FILED_LIFECYCLE_EVALUATOR_NOT_INJECTED"
    if type(trace) is not list or type(results) is not dict:
        return "FILED_LIFECYCLE_STATE_INVALID"
    if require_complete and len(trace) != len(FILED_LIFECYCLE_ORDER):
        return "FILED_LIFECYCLE_TRAVERSAL_INCOMPLETE"
    if len(trace) > len(FILED_LIFECYCLE_ORDER):
        return "FILED_LIFECYCLE_TRACE_TOO_LONG"
    expected_results: dict[str, str] = {}
    prior_digest: str | None = None
    for sequence, record in enumerate(trace, start=1):
        lifecycle_engine = FILED_LIFECYCLE_ORDER[sequence - 1]
        engine_id = FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]
        if type(record) is not dict or set(record) != _RECORD_FIELDS:
            return f"{engine_id}_RECORD_SHAPE_INVALID"
        snapshot = record.get("evaluation_snapshot")
        source = record.get("evaluation_source")
        if type(snapshot) is not dict or type(source) is not dict:
            return f"{engine_id}_RECORD_SHAPE_INVALID"
        if (
            record.get("lifecycle_engine") != lifecycle_engine
            or record.get("schema_status") != FILED_LIFECYCLE_SCHEMA_STATUS
            or record.get("lifecycle_engine_id") != engine_id
            or record.get("stage") != FILED_LIFECYCLE_STAGES[lifecycle_engine]
            or record.get("evaluation_sequence") != sequence
            or record.get("implementation_order_authority")
            != FILED_LIFECYCLE_ORDER_AUTHORITY
            or record.get("result") != LIFECYCLE_PASS
            or record.get("authority_granted") is not False
            or record.get("execution_authority_granted") is not False
            or record.get("licence_granted") is not False
            or record.get("governance_superseded") is not False
            or record.get("evaluation_snapshot_digest") != _safe_hash(snapshot)
            or record.get("evaluation_source_digest") != _safe_hash(source)
        ):
            return f"{engine_id}_RECORD_INVALID"
        snapshot_error = _snapshot_error(snapshot)
        if snapshot_error is not None:
            return snapshot_error
        if snapshot.get("prior_lifecycle_digest") != prior_digest:
            return f"{engine_id}_PRIOR_LIFECYCLE_DIGEST_MISMATCH"
        source_error = _source_error(
            source,
            lifecycle_engine=lifecycle_engine,
            sequence=sequence,
            snapshot=snapshot,
            evaluator=evaluator,
            provider=provider,
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
        if source_error is not None:
            return source_error
        determination = source["determination"]
        if (
            record.get("result") != determination.get("result")
            or record.get("evidence_references")
            != determination.get("evidence_references")
        ):
            return f"{engine_id}_RECORD_SOURCE_MISMATCH"
        expected_results[lifecycle_engine] = LIFECYCLE_PASS
        prior_digest = _safe_hash(trace[:sequence])
    if results != expected_results:
        return "FILED_LIFECYCLE_RESULTS_MISMATCH"
    return None


def _hash_binding_error(
    state: dict[str, Any], trace: list[dict[str, Any]]
) -> str | None:
    chain = state.get("hash_chain")
    if type(chain) is not list or not verify_hash_chain_entries(
        chain, state.get("state_hash")
    ):
        return "FILED_LIFECYCLE_HASH_CHAIN_INVALID"
    previous_index = -1
    for sequence, record in enumerate(trace, start=1):
        lifecycle_engine = FILED_LIFECYCLE_ORDER[sequence - 1]
        stage = FILED_LIFECYCLE_STAGES[lifecycle_engine]
        payload = {
            "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
            "lifecycle_engine": lifecycle_engine,
            "lifecycle_engine_id": FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine],
            "stage": stage,
            "evaluation_sequence": sequence,
            "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
            "result": LIFECYCLE_PASS,
            "reason": record.get("reason"),
            "record_digest": _safe_hash(record),
            "trace_digest": _safe_hash(trace[:sequence]),
            "authority_granted": False,
            "execution_authority_granted": False,
            "licence_granted": False,
            "governance_superseded": False,
        }
        indexes = [
            index
            for index, entry in enumerate(chain)
            if entry.get("stage") == stage
        ]
        if len(indexes) != 1:
            return "FILED_LIFECYCLE_HASH_STAGE_COUNT_INVALID"
        lifecycle_index = indexes[0]
        if (
            lifecycle_index <= previous_index
            or chain[lifecycle_index].get("payload_hash") != _safe_hash(payload)
        ):
            return "FILED_LIFECYCLE_HASH_BINDING_INVALID"
        pre_stage = f"three_p_core:{stage}"
        post_stage = f"{pre_stage}:post"
        if (
            lifecycle_index == 0
            or lifecycle_index + 1 >= len(chain)
            or chain[lifecycle_index - 1].get("stage") != pre_stage
            or chain[lifecycle_index + 1].get("stage") != post_stage
        ):
            return "FILED_LIFECYCLE_THREE_P_HASH_BOUNDARY_INVALID"
        previous_index = lifecycle_index
    return None


def evaluate_filed_lifecycle(
    state: dict[str, Any],
    lifecycle_engine: str,
    *,
    evaluator: FiledLifecycleEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
) -> dict[str, Any]:
    if lifecycle_engine not in FILED_LIFECYCLE_ORDER:
        raise ValueError("FILED_LIFECYCLE_ENGINE_NOT_ADMITTED")
    trace = state.setdefault("filed_lifecycle_trace", [])
    results = state.setdefault("filed_lifecycle_results", {})
    if type(trace) is not list or type(results) is not dict:
        raise ValueError("FILED_LIFECYCLE_STATE_INVALID")
    sequence = len(trace) + 1
    snapshot = _evaluation_snapshot(
        state,
        lifecycle_engine=lifecycle_engine,
        sequence=sequence,
    )
    source: dict[str, Any] | None = None
    error: str | None = None
    expected_engine = (
        FILED_LIFECYCLE_ORDER[sequence - 1]
        if sequence <= len(FILED_LIFECYCLE_ORDER)
        else None
    )
    expected_prior_digest = _safe_hash(trace) if trace else None
    if lifecycle_engine != expected_engine:
        error = "FILED_LIFECYCLE_EXECUTION_ORDER_INVALID"
    elif state.get("filed_lifecycle_digest") != expected_prior_digest:
        error = "FILED_LIFECYCLE_PRIOR_STATE_DIGEST_INVALID"
    elif trace:
        error = _trace_records_error(
            trace,
            results,
            evaluator=evaluator,
            provider=attestation_provider,
            trust_context=attestation_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            require_complete=False,
        )
        if error is None:
            error = _hash_binding_error(state, trace)
    elif results:
        error = "FILED_LIFECYCLE_RESULTS_NOT_EMPTY_AT_START"
    if error is None:
        error = _snapshot_error(snapshot)
    if error is None and evaluator is None:
        error = "FILED_LIFECYCLE_EVALUATOR_NOT_INJECTED"
    method = (
        getattr(evaluator, _EVALUATOR_METHODS[lifecycle_engine], None)
        if evaluator is not None
        else None
    )
    if error is None:
        metadata = (
            getattr(evaluator, "evaluator_id", None),
            getattr(evaluator, "evaluator_version", None),
            getattr(evaluator, "authority_role", None),
            getattr(evaluator, "authority_credential_id", None),
        )
        if (
            not all(_text(value) for value in metadata)
            or metadata[2] != FILED_LIFECYCLE_AUTHORITY_ROLE
            or not callable(method)
        ):
            error = "FILED_LIFECYCLE_EVALUATOR_CONTRACT_INVALID"
        elif (
            not is_hybrid_provider(attestation_provider)
            or getattr(
                attestation_provider,
                "lifecycle_attestation_admitted",
                None,
            )
            is not True
        ):
            error = "FILED_LIFECYCLE_ATTESTATION_PROVIDER_NOT_ADMITTED"
    if error is None:
        if not callable(method):
            error = "FILED_LIFECYCLE_EVALUATOR_CONTRACT_INVALID"
        else:
            try:
                source = method(
                    stage=FILED_LIFECYCLE_STAGES[lifecycle_engine],
                    snapshot=deepcopy(snapshot),
                )
            except Exception as exc:
                error = (
                    f"{FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]}_"
                    f"EVALUATOR_ERROR:{type(exc).__name__}:{exc}"
                )
    if error is None and evaluator is not None:
        error = _source_error(
            source,
            lifecycle_engine=lifecycle_engine,
            sequence=sequence,
            snapshot=snapshot,
            evaluator=evaluator,
            provider=attestation_provider,
            trust_context=attestation_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
    result = (
        source["determination"]["result"]
        if error is None and source is not None
        else LIFECYCLE_DENY
    )
    reason = error or (
        f"{FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]}_EVALUATION_COMPLETED"
    )
    record = _record(
        lifecycle_engine=lifecycle_engine,
        sequence=sequence,
        snapshot=snapshot,
        source=source,
        result=result,
        reason=reason,
    )
    trace.append(record)
    results[lifecycle_engine] = result
    state["filed_lifecycle_digest"] = canonical_integrity_hash(trace)
    state["filed_lifecycle_record"] = deepcopy(record)
    state["filed_lifecycle_result"] = result
    state["filed_lifecycle_reason"] = reason
    return state


def filed_lifecycle_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    trace = state.get("filed_lifecycle_trace", [])
    record = trace[-1] if type(trace) is list and trace else {}
    return {
        "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
        "lifecycle_engine": record.get("lifecycle_engine"),
        "lifecycle_engine_id": record.get("lifecycle_engine_id"),
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
        "result": record.get("result"),
        "reason": record.get("reason"),
        "record_digest": _safe_hash(record),
        "trace_digest": _safe_hash(trace),
        "authority_granted": False,
        "execution_authority_granted": False,
        "licence_granted": False,
        "governance_superseded": False,
    }


def verify_filed_lifecycle(
    state: dict[str, Any],
    *,
    evaluator: FiledLifecycleEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    require_hash_binding: bool = True,
) -> bool:
    try:
        trace = state.get("filed_lifecycle_trace")
        results = state.get("filed_lifecycle_results")
        error = _trace_records_error(
            trace,
            results,
            evaluator=evaluator,
            provider=attestation_provider,
            trust_context=attestation_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            require_complete=True,
        )
        if error is not None:
            return False
        if type(trace) is not list or type(results) is not dict:
            return False
        if (
            state.get("filed_lifecycle_digest") != _safe_hash(trace)
            or state.get("filed_lifecycle_result") != LIFECYCLE_PASS
            or state.get("filed_lifecycle_reason") != trace[-1].get("reason")
        ):
            return False
        live_snapshot = _evaluation_snapshot(
            state,
            lifecycle_engine=FILED_LIFECYCLE_ORDER[-1],
            sequence=len(FILED_LIFECYCLE_ORDER),
        )
        if _three_p_error(live_snapshot) is not None:
            return False
        if _skg_error(live_snapshot) is not None:
            return False
        stable_live_fields = {
            "request_fingerprint": state.get("request_fingerprint"),
            "evaluation_time": state.get("evaluation_time"),
            "skg_result": state.get("skg_authority_result"),
            "skg_digest": state.get("skg_authority_digest"),
            "skg_record": state.get("skg_authority_record"),
            "governance_result": state.get("governance_result"),
        }
        for record in trace:
            snapshot = record.get("evaluation_snapshot")
            if type(snapshot) is not dict or any(
                snapshot.get(field) != value
                for field, value in stable_live_fields.items()
            ):
                return False
        if not require_hash_binding:
            return True
        return _hash_binding_error(state, trace) is None
    except (IntegrityContractError, KeyError, TypeError, ValueError):
        return False
