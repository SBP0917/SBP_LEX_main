from __future__ import annotations

"""Mechanical V2 evidence contract for five filed governance functions.

The filed specification supplies the exact function names.  The schema,
runtime order, result vocabulary, stages, and all mechanics in this module are
implementation-defined V2 contracts, not filed schemas or filed runtime order.
No detection model, propagation model, threshold, containment action,
revocation action, or substantive determination is implemented here.  Those
determinations must come from the injected signed evaluator.
"""

from copy import deepcopy
import hmac
from typing import Any, Final, Protocol

from sbp_lex.security.integrity import (
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


FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS: Final = (
    "IMPLEMENTATION_DEFINED_V2_MECHANICS_NOT_FILED_SCHEMA"
)
FILED_GOVERNANCE_INTEGRITY_ATTESTATION_PURPOSE: Final = (
    "SBP_LEX_V2_FILED_GOVERNANCE_INTEGRITY_ATTESTATION"
)
FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY: Final = (
    "V2_IMPLEMENTATION_DEFINED_ORDER_NOT_FILED_ORDER"
)
FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY: Final = (
    "V2_IMPLEMENTATION_DEFINED_RESULTS_NOT_FILED_VOCABULARY"
)

BLACK_SWAN_DETECTION_ARCHITECTURE: Final = (
    "Black Swan detection architecture"
)
CRISIS_PROPAGATION_MODELLING: Final = "Crisis propagation modelling"
AUTHORITY_ANOMALY_DETECTION: Final = "Authority anomaly detection"
STRATEGIC_INSTABILITY_EARLY_WARNING: Final = (
    "Strategic instability early warning"
)
AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE: Final = (
    "Autonomous containment & revocation cascade"
)

# The filed list supplies these exact names but does not declare runtime order.
FILED_GOVERNANCE_INTEGRITY_ORDER: Final = (
    BLACK_SWAN_DETECTION_ARCHITECTURE,
    CRISIS_PROPAGATION_MODELLING,
    AUTHORITY_ANOMALY_DETECTION,
    STRATEGIC_INSTABILITY_EARLY_WARNING,
    AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE,
)
FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS: Final = {
    BLACK_SWAN_DETECTION_ARCHITECTURE: (
        "BLACK_SWAN_DETECTION_ARCHITECTURE"
    ),
    CRISIS_PROPAGATION_MODELLING: "CRISIS_PROPAGATION_MODELLING",
    AUTHORITY_ANOMALY_DETECTION: "AUTHORITY_ANOMALY_DETECTION",
    STRATEGIC_INSTABILITY_EARLY_WARNING: (
        "STRATEGIC_INSTABILITY_EARLY_WARNING"
    ),
    AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE: (
        "AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE"
    ),
}
FILED_GOVERNANCE_INTEGRITY_STAGES: Final = {
    function: (
        "filed_governance_integrity:"
        f"{FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[function].lower()}"
    )
    for function in FILED_GOVERNANCE_INTEGRITY_ORDER
}
FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE: Final = (
    "FILED_GOVERNANCE_INTEGRITY_EVALUATOR"
)

GOVERNANCE_INTEGRITY_PASS: Final = "PASS"
GOVERNANCE_INTEGRITY_DENY: Final = "DENY"
GOVERNANCE_INTEGRITY_ESCALATE: Final = "ESCALATE"
FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY: Final = (
    GOVERNANCE_INTEGRITY_PASS,
    GOVERNANCE_INTEGRITY_DENY,
    GOVERNANCE_INTEGRITY_ESCALATE,
)

_EVALUATOR_METHODS: Final = {
    BLACK_SWAN_DETECTION_ARCHITECTURE: (
        "evaluate_black_swan_detection_architecture"
    ),
    CRISIS_PROPAGATION_MODELLING: "evaluate_crisis_propagation_modelling",
    AUTHORITY_ANOMALY_DETECTION: "evaluate_authority_anomaly_detection",
    STRATEGIC_INSTABILITY_EARLY_WARNING: (
        "evaluate_strategic_instability_early_warning"
    ),
    AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE: (
        "evaluate_autonomous_containment_revocation_cascade"
    ),
}

_SNAPSHOT_FIELDS: Final = {
    "schema_status",
    "implementation_order_authority",
    "result_vocabulary_authority",
    "result_vocabulary",
    "governance_integrity_function",
    "function_id",
    "stage",
    "evaluation_sequence",
    "implementation_order",
    "request_fingerprint",
    "state_hash",
    "evaluation_time",
    "prior_governance_integrity_digest",
    "three_p_core_result",
    "three_p_core_digest",
    "three_p_trace_hash",
    "three_p_trace",
    "skg_result",
    "skg_digest",
    "skg_record",
    "revocation_binding",
}
_SOURCE_FIELDS: Final = {
    "schema_status",
    "result_vocabulary_authority",
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "governance_integrity_function",
    "function_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_governance_integrity_digest",
    "three_p_core_digest",
    "three_p_trace_hash",
    "skg_digest",
    "revocation_status",
    "revocation_sequence",
    "revocation_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}
_DETERMINATION_FIELDS: Final = {
    "result",
    "evidence_references",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_granted",
    "bypass_permitted",
}
_RECORD_FIELDS: Final = {
    "schema_status",
    "result_vocabulary_authority",
    "governance_integrity_function",
    "function_id",
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
    "licence_granted",
    "execution_authority_granted",
    "effect_granted",
    "bypass_permitted",
}
_REVOCATION_FIELDS: Final = {"status", "sequence", "digest"}
_PROHIBITED_GRANT_FIELDS: Final = (
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_granted",
    "bypass_permitted",
)


class FiledGovernanceIntegrityEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate_black_swan_detection_architecture(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_crisis_propagation_modelling(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_authority_anomaly_detection(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_strategic_instability_early_warning(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_autonomous_containment_revocation_cascade(
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


def _provider_admitted(provider: HybridSignatureProvider | None) -> bool:
    return (
        is_hybrid_provider(provider)
        and getattr(
            provider,
            "governance_integrity_attestation_admitted",
            None,
        )
        is True
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
        and metadata[2] == FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE
        and all(
            callable(getattr(evaluator, method_name, None))
            for method_name in _EVALUATOR_METHODS.values()
        )
    )


def _evidence_references_exact(value: Any) -> bool:
    if type(value) is not list or not value:
        return False
    evidence_ids: set[str] = set()
    for reference in value:
        if type(reference) is not dict or set(reference) != {
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


def governance_integrity_revocation_binding(
    *, status: str, sequence: int
) -> dict[str, Any]:
    """Build the mechanical revocation binding accepted by this contract."""

    body = {"status": status, "sequence": sequence}
    return {**body, "digest": canonical_integrity_hash(body)}


def _revocation_error(binding: Any) -> str | None:
    if type(binding) is not dict or set(binding) != _REVOCATION_FIELDS:
        return "FILED_GOVERNANCE_INTEGRITY_REVOCATION_BINDING_INVALID"
    status = binding.get("status")
    sequence = binding.get("sequence")
    if status != "ACTIVE":
        return "FILED_GOVERNANCE_INTEGRITY_REVOKED"
    if type(sequence) is not int or sequence < 0:
        return "FILED_GOVERNANCE_INTEGRITY_REVOCATION_SEQUENCE_INVALID"
    if binding.get("digest") != _safe_hash(
        {"status": status, "sequence": sequence}
    ):
        return "FILED_GOVERNANCE_INTEGRITY_REVOCATION_DIGEST_INVALID"
    return None


def _three_p_error(snapshot: dict[str, Any]) -> str | None:
    trace = snapshot.get("three_p_trace")
    digest = snapshot.get("three_p_core_digest")
    trace_hash = snapshot.get("three_p_trace_hash")
    if snapshot.get("three_p_core_result") != "PASS":
        return "FILED_GOVERNANCE_INTEGRITY_THREE_P_NOT_PASS"
    if not is_sha512(digest) or not is_sha512(trace_hash):
        return "FILED_GOVERNANCE_INTEGRITY_THREE_P_BINDING_INVALID"
    if type(trace) is not list or not trace or type(trace[-1]) is not dict:
        return "FILED_GOVERNANCE_INTEGRITY_THREE_P_TRACE_INVALID"
    if (
        trace[-1].get("three_p_core_digest") != digest
        or trace[-1].get("trace_hash") != trace_hash
    ):
        return "FILED_GOVERNANCE_INTEGRITY_THREE_P_TRACE_NOT_CURRENT"
    return None


def _skg_error(snapshot: dict[str, Any]) -> str | None:
    record = snapshot.get("skg_record")
    digest = snapshot.get("skg_digest")
    if snapshot.get("skg_result") != "PASS":
        return "FILED_GOVERNANCE_INTEGRITY_SKG_NOT_PASS"
    if type(record) is not dict or not record or not is_sha512(digest):
        return "FILED_GOVERNANCE_INTEGRITY_SKG_BINDING_INVALID"
    if _safe_hash(record) != digest:
        return "FILED_GOVERNANCE_INTEGRITY_SKG_DIGEST_MISMATCH"
    if (
        record.get("result") != "PASS"
        or record.get("authority_granted") is not False
        or record.get("execution_authority_granted") is not False
        or record.get("downstream_override_permitted") is not False
    ):
        return "FILED_GOVERNANCE_INTEGRITY_SKG_RECORD_INVALID"
    return None


def _snapshot(
    state: dict[str, Any],
    *,
    governance_function: str,
    sequence: int,
) -> dict[str, Any]:
    return {
        "schema_status": FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
        "implementation_order_authority": (
            FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        ),
        "result_vocabulary_authority": (
            FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
        ),
        "result_vocabulary": list(
            FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY
        ),
        "governance_integrity_function": governance_function,
        "function_id": FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ],
        "stage": FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function],
        "evaluation_sequence": sequence,
        "implementation_order": list(FILED_GOVERNANCE_INTEGRITY_ORDER),
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash"),
        "evaluation_time": state.get("evaluation_time"),
        "prior_governance_integrity_digest": state.get(
            "filed_governance_integrity_digest"
        ),
        "three_p_core_result": state.get("three_p_core_result"),
        "three_p_core_digest": state.get("three_p_core_digest"),
        "three_p_trace_hash": state.get("three_p_trace_hash"),
        "three_p_trace": deepcopy(state.get("three_p_trace")),
        "skg_result": state.get("skg_authority_result"),
        "skg_digest": state.get("skg_authority_digest"),
        "skg_record": deepcopy(state.get("skg_authority_record")),
        "revocation_binding": deepcopy(
            state.get("filed_governance_integrity_revocation_binding")
        ),
    }


def _snapshot_error(snapshot: Any) -> str | None:
    if type(snapshot) is not dict or set(snapshot) != _SNAPSHOT_FIELDS:
        return "FILED_GOVERNANCE_INTEGRITY_SNAPSHOT_SHAPE_INVALID"
    governance_function = snapshot.get("governance_integrity_function")
    if governance_function not in FILED_GOVERNANCE_INTEGRITY_ORDER:
        return "FILED_GOVERNANCE_INTEGRITY_FUNCTION_NOT_ADMITTED"
    if snapshot.get("function_id") != (
        FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[governance_function]
    ):
        return "FILED_GOVERNANCE_INTEGRITY_FUNCTION_ID_INVALID"
    if snapshot.get("stage") != FILED_GOVERNANCE_INTEGRITY_STAGES[
        governance_function
    ]:
        return "FILED_GOVERNANCE_INTEGRITY_STAGE_INVALID"
    sequence = snapshot.get("evaluation_sequence")
    if type(sequence) is not int or sequence < 1:
        return "FILED_GOVERNANCE_INTEGRITY_SEQUENCE_INVALID"
    if (
        snapshot.get("schema_status")
        != FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS
        or snapshot.get("implementation_order_authority")
        != FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        or snapshot.get("implementation_order")
        != list(FILED_GOVERNANCE_INTEGRITY_ORDER)
        or snapshot.get("result_vocabulary_authority")
        != FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
        or snapshot.get("result_vocabulary")
        != list(FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY)
    ):
        return "FILED_GOVERNANCE_INTEGRITY_IMPLEMENTATION_METADATA_INVALID"
    if not is_sha512(snapshot.get("request_fingerprint")):
        return "FILED_GOVERNANCE_INTEGRITY_REQUEST_FINGERPRINT_INVALID"
    if not is_sha512(snapshot.get("state_hash")):
        return "FILED_GOVERNANCE_INTEGRITY_STATE_HASH_INVALID"
    evaluation_time = snapshot.get("evaluation_time")
    if type(evaluation_time) is not int or evaluation_time < 0:
        return "FILED_GOVERNANCE_INTEGRITY_EVALUATION_TIME_INVALID"
    prior_digest = snapshot.get("prior_governance_integrity_digest")
    if prior_digest is not None and not is_sha512(prior_digest):
        return "FILED_GOVERNANCE_INTEGRITY_PRIOR_DIGEST_INVALID"
    return (
        _three_p_error(snapshot)
        or _skg_error(snapshot)
        or _revocation_error(snapshot.get("revocation_binding"))
    )


def _determination_error(determination: Any, function_id: str) -> str | None:
    if type(determination) is not dict or set(determination) != (
        _DETERMINATION_FIELDS
    ):
        return f"{function_id}_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in (
        FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY
    ):
        return f"{function_id}_RESULT_INVALID"
    if not _evidence_references_exact(
        determination.get("evidence_references")
    ):
        return f"{function_id}_EVIDENCE_REFERENCES_INVALID"
    for field in _PROHIBITED_GRANT_FIELDS:
        if determination.get(field) is not False:
            return f"{function_id}_{field.upper()}_PROHIBITED"
    return None


def _source_error(
    source: Any,
    *,
    governance_function: str,
    sequence: int,
    snapshot: dict[str, Any],
    evaluator: FiledGovernanceIntegrityEvaluator,
    provider: HybridSignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    function_id = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
        governance_function
    ]
    if not _provider_admitted(provider):
        return "FILED_GOVERNANCE_INTEGRITY_PROVIDER_NOT_ADMITTED"
    if not _evaluator_contract_exact(evaluator):
        return "FILED_GOVERNANCE_INTEGRITY_EVALUATOR_CONTRACT_INVALID"
    if type(source) is not dict or set(source) != _SOURCE_FIELDS:
        return f"{function_id}_EVALUATOR_RESULT_SHAPE_INVALID"
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not _trust_context_owner_pinned(
            trust_context,
            owner_pinned_context_digest,
        )
    ):
        return "FILED_GOVERNANCE_INTEGRITY_OWNER_TRUST_PIN_INVALID"
    if not verify_hybrid_signed_object(
        source,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_purpose=FILED_GOVERNANCE_INTEGRITY_ATTESTATION_PURPOSE,
        require_effect_authority=False,
    ):
        return f"{function_id}_EVALUATION_ATTESTATION_INVALID"
    revocation = snapshot["revocation_binding"]
    expected = {
        "schema_status": FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
        "result_vocabulary_authority": (
            FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
        ),
        "evaluator_id": getattr(evaluator, "evaluator_id", None),
        "evaluator_version": getattr(evaluator, "evaluator_version", None),
        "authority_credential": {
            "credential_id": getattr(
                evaluator, "authority_credential_id", None
            ),
            "authority_role": FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE,
        },
        "governance_integrity_function": governance_function,
        "function_id": function_id,
        "stage": FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function],
        "evaluation_sequence": sequence,
        "implementation_order_authority": (
            FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        ),
        "request_fingerprint": snapshot.get("request_fingerprint"),
        "pre_evaluation_state_hash": snapshot.get("state_hash"),
        "evaluation_time": snapshot.get("evaluation_time"),
        "prior_governance_integrity_digest": snapshot.get(
            "prior_governance_integrity_digest"
        ),
        "three_p_core_digest": snapshot.get("three_p_core_digest"),
        "three_p_trace_hash": snapshot.get("three_p_trace_hash"),
        "skg_digest": snapshot.get("skg_digest"),
        "revocation_status": revocation.get("status"),
        "revocation_sequence": revocation.get("sequence"),
        "revocation_digest": revocation.get("digest"),
        "snapshot_digest": _safe_hash(snapshot),
    }
    if any(source.get(field) != value for field, value in expected.items()):
        return f"{function_id}_EVALUATION_BINDING_MISMATCH"
    return _determination_error(source.get("determination"), function_id)


def _record(
    *,
    governance_function: str,
    sequence: int,
    snapshot: dict[str, Any],
    source: dict[str, Any] | None,
    result: str,
    reason: str,
) -> dict[str, Any]:
    determination = source.get("determination", {}) if source else {}
    return {
        "schema_status": FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
        "result_vocabulary_authority": (
            FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
        ),
        "governance_integrity_function": governance_function,
        "function_id": FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ],
        "stage": FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function],
        "evaluation_sequence": sequence,
        "implementation_order_authority": (
            FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        ),
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
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_granted": False,
        "bypass_permitted": False,
    }


def _trace_error(
    trace: Any,
    results: Any,
    *,
    evaluator: FiledGovernanceIntegrityEvaluator | None,
    provider: HybridSignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    require_complete: bool,
) -> str | None:
    if evaluator is None:
        return "FILED_GOVERNANCE_INTEGRITY_EVALUATOR_NOT_INJECTED"
    if not _evaluator_contract_exact(evaluator):
        return "FILED_GOVERNANCE_INTEGRITY_EVALUATOR_CONTRACT_INVALID"
    if not _provider_admitted(provider):
        return "FILED_GOVERNANCE_INTEGRITY_PROVIDER_NOT_ADMITTED"
    if type(trace) is not list or type(results) is not dict:
        return "FILED_GOVERNANCE_INTEGRITY_STATE_INVALID"
    if require_complete and len(trace) != len(
        FILED_GOVERNANCE_INTEGRITY_ORDER
    ):
        return "FILED_GOVERNANCE_INTEGRITY_TRAVERSAL_INCOMPLETE"
    if len(trace) > len(FILED_GOVERNANCE_INTEGRITY_ORDER):
        return "FILED_GOVERNANCE_INTEGRITY_TRACE_TOO_LONG"

    expected_results: dict[str, str] = {}
    prior_digest: str | None = None
    prior_revocation_sequence = -1
    for sequence, record in enumerate(trace, start=1):
        governance_function = FILED_GOVERNANCE_INTEGRITY_ORDER[sequence - 1]
        function_id = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ]
        if type(record) is not dict or set(record) != _RECORD_FIELDS:
            return f"{function_id}_RECORD_SHAPE_INVALID"
        snapshot = record.get("evaluation_snapshot")
        source = record.get("evaluation_source")
        if type(snapshot) is not dict or type(source) is not dict:
            return f"{function_id}_RECORD_SHAPE_INVALID"
        expected_reason = f"{function_id}_EVALUATION_COMPLETED"
        if (
            record.get("schema_status")
            != FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS
            or record.get("result_vocabulary_authority")
            != FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
            or record.get("governance_integrity_function")
            != governance_function
            or record.get("function_id") != function_id
            or record.get("stage")
            != FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
            or record.get("evaluation_sequence") != sequence
            or record.get("implementation_order_authority")
            != FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
            or record.get("result") != GOVERNANCE_INTEGRITY_PASS
            or record.get("reason") != expected_reason
            or any(record.get(field) is not False for field in _PROHIBITED_GRANT_FIELDS)
            or record.get("evaluation_snapshot_digest")
            != _safe_hash(snapshot)
            or record.get("evaluation_source_digest") != _safe_hash(source)
        ):
            return f"{function_id}_RECORD_INVALID"
        snapshot_error = _snapshot_error(snapshot)
        if snapshot_error is not None:
            return snapshot_error
        if (
            snapshot.get("governance_integrity_function")
            != governance_function
            or snapshot.get("evaluation_sequence") != sequence
            or snapshot.get("prior_governance_integrity_digest")
            != prior_digest
        ):
            return f"{function_id}_SNAPSHOT_SEQUENCE_BINDING_INVALID"
        revocation_sequence = snapshot["revocation_binding"]["sequence"]
        if revocation_sequence < prior_revocation_sequence:
            return "FILED_GOVERNANCE_INTEGRITY_REVOCATION_ROLLBACK"
        source_error = _source_error(
            source,
            governance_function=governance_function,
            sequence=sequence,
            snapshot=snapshot,
            evaluator=evaluator,
            provider=provider,
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
        if source_error is not None:
            return source_error
        if (
            record.get("result") != source["determination"].get("result")
            or record.get("evidence_references")
            != source["determination"].get("evidence_references")
        ):
            return f"{function_id}_RECORD_SOURCE_MISMATCH"
        expected_results[governance_function] = GOVERNANCE_INTEGRITY_PASS
        prior_digest = _safe_hash(trace[:sequence])
        if prior_digest is None:
            return "FILED_GOVERNANCE_INTEGRITY_TRACE_DIGEST_INVALID"
        prior_revocation_sequence = revocation_sequence
    if results != expected_results:
        return "FILED_GOVERNANCE_INTEGRITY_RESULTS_MISMATCH"
    return None


def _record_hash_payload(
    record: dict[str, Any], *, trace_digest: str | None
) -> dict[str, Any]:
    return {
        "schema_status": FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
        "result_vocabulary_authority": (
            FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
        ),
        "governance_integrity_function": record.get(
            "governance_integrity_function"
        ),
        "function_id": record.get("function_id"),
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "implementation_order_authority": (
            FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        ),
        "result": record.get("result"),
        "reason": record.get("reason"),
        "record_digest": _safe_hash(record),
        "trace_digest": trace_digest,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_granted": False,
        "bypass_permitted": False,
    }


def filed_governance_integrity_hash_payload(
    state: dict[str, Any],
) -> dict[str, Any]:
    trace = state.get("filed_governance_integrity_trace", [])
    record = trace[-1] if type(trace) is list and trace else {}
    return _record_hash_payload(record, trace_digest=_safe_hash(trace))


def _hash_binding_error(
    state: dict[str, Any], trace: list[dict[str, Any]]
) -> str | None:
    chain = state.get("hash_chain")
    if type(chain) is not list or not verify_hash_chain_entries(
        chain, state.get("state_hash")
    ):
        return "FILED_GOVERNANCE_INTEGRITY_HASH_CHAIN_INVALID"
    previous_index = -1
    for sequence, record in enumerate(trace, start=1):
        governance_function = FILED_GOVERNANCE_INTEGRITY_ORDER[sequence - 1]
        stage = FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
        expected_payload = _record_hash_payload(
            record,
            trace_digest=_safe_hash(trace[:sequence]),
        )
        indexes = [
            index
            for index, entry in enumerate(chain)
            if entry.get("stage") == stage
        ]
        if len(indexes) != 1:
            return "FILED_GOVERNANCE_INTEGRITY_HASH_STAGE_COUNT_INVALID"
        function_index = indexes[0]
        if (
            function_index <= previous_index
            or chain[function_index].get("payload_hash")
            != _safe_hash(expected_payload)
            or chain[function_index].get("previous_hash")
            != record["evaluation_snapshot"].get("state_hash")
        ):
            return "FILED_GOVERNANCE_INTEGRITY_HASH_BINDING_INVALID"
        pre_stage = f"three_p_core:{stage}"
        post_stage = f"{pre_stage}:post"
        if (
            function_index == 0
            or function_index + 1 >= len(chain)
            or chain[function_index - 1].get("stage") != pre_stage
            or chain[function_index + 1].get("stage") != post_stage
        ):
            return "FILED_GOVERNANCE_INTEGRITY_THREE_P_BOUNDARY_INVALID"
        previous_index = function_index
    return None


def _deny_state(state: dict[str, Any], reason: str) -> dict[str, Any]:
    state["filed_governance_integrity_result"] = GOVERNANCE_INTEGRITY_DENY
    state["filed_governance_integrity_reason"] = reason
    for field in _PROHIBITED_GRANT_FIELDS:
        state[f"filed_governance_integrity_{field}"] = False
    return state


def evaluate_filed_governance_integrity(
    state: dict[str, Any],
    governance_function: str,
    *,
    evaluator: FiledGovernanceIntegrityEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
) -> dict[str, Any]:
    """Evaluate one function using only signed injected evidence."""

    if governance_function not in FILED_GOVERNANCE_INTEGRITY_ORDER:
        raise ValueError("FILED_GOVERNANCE_INTEGRITY_FUNCTION_NOT_ADMITTED")
    trace = state.setdefault("filed_governance_integrity_trace", [])
    results = state.setdefault("filed_governance_integrity_results", {})
    if type(trace) is not list or type(results) is not dict:
        raise ValueError("FILED_GOVERNANCE_INTEGRITY_STATE_INVALID")

    sequence = len(trace) + 1
    snapshot = _snapshot(
        state,
        governance_function=governance_function,
        sequence=sequence,
    )
    source: dict[str, Any] | None = None
    error: str | None = None
    expected_function = (
        FILED_GOVERNANCE_INTEGRITY_ORDER[sequence - 1]
        if sequence <= len(FILED_GOVERNANCE_INTEGRITY_ORDER)
        else None
    )
    expected_prior_digest = _safe_hash(trace) if trace else None

    if governance_function != expected_function:
        error = "FILED_GOVERNANCE_INTEGRITY_EXECUTION_ORDER_INVALID"
    elif state.get("filed_governance_integrity_digest") != (
        expected_prior_digest
    ):
        error = "FILED_GOVERNANCE_INTEGRITY_PRIOR_STATE_DIGEST_INVALID"
    if error is None:
        error = _snapshot_error(snapshot)
    if error is None and trace:
        error = _trace_error(
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
        if error is None and (
            snapshot["revocation_binding"]["sequence"]
            < trace[-1]["evaluation_snapshot"]["revocation_binding"][
                "sequence"
            ]
        ):
            error = "FILED_GOVERNANCE_INTEGRITY_REVOCATION_ROLLBACK"
    elif error is None and results:
        error = "FILED_GOVERNANCE_INTEGRITY_RESULTS_NOT_EMPTY_AT_START"
    if error is None and evaluator is None:
        error = "FILED_GOVERNANCE_INTEGRITY_EVALUATOR_NOT_INJECTED"
    if error is None and not _evaluator_contract_exact(evaluator):
        error = "FILED_GOVERNANCE_INTEGRITY_EVALUATOR_CONTRACT_INVALID"
    if error is None and not _provider_admitted(attestation_provider):
        error = "FILED_GOVERNANCE_INTEGRITY_PROVIDER_NOT_ADMITTED"

    method = (
        getattr(evaluator, _EVALUATOR_METHODS[governance_function], None)
        if evaluator is not None
        else None
    )
    if error is None:
        if not callable(method):
            error = "FILED_GOVERNANCE_INTEGRITY_EVALUATOR_CONTRACT_INVALID"
        else:
            try:
                source = method(
                    stage=FILED_GOVERNANCE_INTEGRITY_STAGES[
                        governance_function
                    ],
                    snapshot=deepcopy(snapshot),
                )
            except Exception as exc:
                error = (
                    f"{FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[governance_function]}_"
                    f"EVALUATOR_ERROR:{type(exc).__name__}:{exc}"
                )
    if error is None:
        if evaluator is None:
            error = "FILED_GOVERNANCE_INTEGRITY_EVALUATOR_NOT_INJECTED"
        else:
            error = _source_error(
                source,
                governance_function=governance_function,
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
        else GOVERNANCE_INTEGRITY_DENY
    )
    function_id = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
        governance_function
    ]
    reason = error or f"{function_id}_EVALUATION_COMPLETED"
    record = _record(
        governance_function=governance_function,
        sequence=sequence,
        snapshot=snapshot,
        source=source,
        result=result,
        reason=reason,
    )
    trace.append(record)
    results[governance_function] = result
    state["filed_governance_integrity_record"] = deepcopy(record)
    state["filed_governance_integrity_digest"] = canonical_integrity_hash(
        trace
    )
    state["filed_governance_integrity_result"] = result
    state["filed_governance_integrity_reason"] = reason
    for field in _PROHIBITED_GRANT_FIELDS:
        state[f"filed_governance_integrity_{field}"] = False
    return state


def verify_filed_governance_integrity(
    state: dict[str, Any],
    *,
    evaluator: FiledGovernanceIntegrityEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    require_hash_binding: bool = True,
) -> bool:
    """Verify the complete five-function traversal fail closed."""

    try:
        trace = state.get("filed_governance_integrity_trace")
        results = state.get("filed_governance_integrity_results")
        error = _trace_error(
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
            state.get("filed_governance_integrity_record") != trace[-1]
            or state.get("filed_governance_integrity_digest")
            != _safe_hash(trace)
            or state.get("filed_governance_integrity_result")
            != GOVERNANCE_INTEGRITY_PASS
            or state.get("filed_governance_integrity_reason")
            != trace[-1].get("reason")
            or any(
                state.get(f"filed_governance_integrity_{field}") is not False
                for field in _PROHIBITED_GRANT_FIELDS
            )
        ):
            return False
        live_snapshot = _snapshot(
            state,
            governance_function=FILED_GOVERNANCE_INTEGRITY_ORDER[-1],
            sequence=len(FILED_GOVERNANCE_INTEGRITY_ORDER),
        )
        if _snapshot_error(live_snapshot) is not None:
            return False
        latest_snapshot = trace[-1]["evaluation_snapshot"]
        if type(latest_snapshot) is not dict:
            return False
        for field in (
            "request_fingerprint",
            "evaluation_time",
            "skg_result",
            "skg_digest",
            "skg_record",
            "revocation_binding",
        ):
            if latest_snapshot.get(field) != live_snapshot.get(field):
                return False
        if not require_hash_binding:
            return True
        return _hash_binding_error(state, trace) is None
    except (
        AttributeError,
        IntegrityContractError,
        KeyError,
        TypeError,
        ValueError,
    ):
        return False
