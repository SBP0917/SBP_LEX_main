"""Implementation-defined V2 aggregate for foundational baseline controls.

The aggregate records that the exact upstream mechanical prerequisites were
present.  It never grants governance ALLOW, authority, a licence, execution or
effect authority, or pipeline bypass.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Final

from sbp_lex.compliance.australian_minor_access import (
    AGE_AT_LEAST_16,
    AGE_INDETERMINATE,
    RESULT_NOT_APPLICABLE,
    RESULT_PASS as AUSTRALIAN_MINOR_ACCESS_PASS,
)
from sbp_lex.config.pipeline_config import (
    FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
    FOUNDATIONAL_BASELINE_ORDER,
    FOUNDATIONAL_BASELINE_ORDER_AUTHORITY,
)
from sbp_lex.identity.impersonation_protection import IMPERSONATION_PASS
from sbp_lex.identity.sovereign_identity import IDENTITY_VERIFIED
from sbp_lex.interface.authority_boundary import BOUNDARY_PASS
from sbp_lex.provenance.digital_provenance import (
    ADMIT as DIGITAL_PROVENANCE_ADMIT,
    DURABLE_CLAIMED,
    NO_AUTHORIZATION_EFFECT as PROVENANCE_NO_AUTHORIZATION_EFFECT,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    build_hash_chain_entry,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)


FOUNDATIONAL_BASELINE_CONTRACT_ID: Final = "SBP_LEX_V2_FOUNDATIONAL_BASELINE"
FOUNDATIONAL_BASELINE_SCHEMA_STATUS: Final = (
    "IMPLEMENTATION_DEFINED_V2_MECHANICS_NOT_FILED_RUNTIME_ORDER"
)
FOUNDATIONAL_BASELINE_PASS: Final = "PASS"
FOUNDATIONAL_BASELINE_DENY: Final = "DENY"

_AGGREGATE_AUTHORITY_FIELDS: Final = (
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
)
_APPLICATION_INTEGRITY_DIGEST_FIELDS: Final = (
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "application_integrity_manifest_digest",
    "application_integrity_runtime_measurement_digest",
    "application_integrity_trust_context_digest",
)
_SIGNATURE_FIELDS: Final = frozenset({
    "provider_id",
    "algorithm",
    "key_id",
    "custody_class",
    "effect_authority",
    "signature_b64",
})
_SOVEREIGN_IDENTITY_FALSE_FIELDS: Final = (
    "biometric_proof_established",
    "access_granted",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
)
_AUTHORITY_BOUNDARY_RECORD_FALSE_FIELDS: Final = (
    "stakeholder_label_grants_rights",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
)
_AUTHORITY_BOUNDARY_STATE_FALSE_FIELDS: Final = (
    "stakeholder_label_grants_rights",
    "participant_authority_granted",
    "participant_licence_granted",
    "participant_execution_authority_granted",
    "participant_effect_authority_granted",
    "participant_pipeline_bypass_permitted",
)
_IMPERSONATION_FALSE_FIELDS: Final = (
    "biometric_proof_established",
    "identity_issued",
    "identity_label_grants_access",
    "role_label_grants_authority",
    "mandate_label_grants_authority",
    "access_granted",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
)
_AUSTRALIAN_MINOR_FALSE_FIELDS: Final = (
    "access_granted",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority",
)
_RECORD_FIELDS: Final = frozenset({
    "contract_id",
    "schema_status",
    "foundational_order",
    "foundational_order_authority",
    "result",
    "reason",
    "application_integrity_result",
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "application_integrity_manifest_digest",
    "application_integrity_runtime_measurement_digest",
    "application_integrity_trust_context_digest",
    "digital_provenance_result",
    "digital_provenance_digest",
    "digital_provenance_verification_receipt_digest",
    "sovereign_identity_result",
    "sovereign_identity_digest",
    "sovereign_identity_revocation_status",
    "authority_boundary_result",
    "authority_boundary_digest",
    "authority_boundary_trace_digest",
    "impersonation_protection_result",
    "impersonation_protection_digest",
    "australian_minor_access_result",
    "australian_minor_access_record_digest",
    *_AGGREGATE_AUTHORITY_FIELDS,
})
_HASH_PAYLOAD_FIELDS: Final = frozenset({
    "contract_id",
    "schema_status",
    "result",
    "reason",
    "record_digest",
    "foundational_order",
    "foundational_order_authority",
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "digital_provenance_digest",
    "digital_provenance_verification_receipt_digest",
    "sovereign_identity_digest",
    "authority_boundary_digest",
    "authority_boundary_trace_digest",
    "impersonation_protection_digest",
    "australian_minor_access_record_digest",
    *_AGGREGATE_AUTHORITY_FIELDS,
})


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _safe_scalar(value: Any) -> str | int | bool | None:
    return value if value is None or type(value) in {str, int, bool} else None


def _safe_order(value: Any) -> list[str] | None:
    if type(value) is list and all(_text(item) for item in value):
        return list(value)
    return None


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError, OverflowError, RecursionError):
        return None
    except Exception:
        return None


def _exact_false_fields(value: Any, fields: tuple[str, ...]) -> bool:
    return type(value) is dict and all(value.get(field) is False for field in fields)


def _provenance_receipt_digest(state: dict[str, Any]) -> str | None:
    receipt = state.get("digital_provenance_verification_receipt")
    if type(receipt) is not dict:
        return None
    digest = receipt.get("digest")
    return digest if is_sha512(digest) else None


def _provenance_receipt_valid(state: dict[str, Any]) -> bool:
    receipt = state.get("digital_provenance_verification_receipt")
    if type(receipt) is not dict:
        return False
    signature = receipt.get("signature")
    if (
        type(signature) is not dict
        or set(signature) != _SIGNATURE_FIELDS
        or any(
            not _text(signature.get(field))
            for field in (
                "provider_id",
                "algorithm",
                "key_id",
                "custody_class",
                "signature_b64",
            )
        )
        or signature.get("effect_authority") is not False
        or receipt.get("verified") is not False
        or not is_sha512(receipt.get("digest"))
        or receipt.get("result") != DIGITAL_PROVENANCE_ADMIT
        or receipt.get("graph_digest") != state.get("digital_provenance_digest")
        or receipt.get("release_manifest_digest")
        != state.get("application_integrity_manifest_digest")
        or receipt.get("runtime_measurement_digest")
        != state.get("application_integrity_runtime_measurement_digest")
        or receipt.get("durable_claim_result") != DURABLE_CLAIMED
        or any(
            not is_sha512(receipt.get(field))
            for field in (
                "durable_claim_digest",
                "durable_transition_receipt_digest",
                "durable_live_heads_digest",
                "revocation_head_digest",
                "clock_evidence_digest",
            )
        )
        or receipt.get("production_durable_storage_proven_by_module") is not False
        or receipt.get("lineage_authenticated") is not True
        or receipt.get("lineage_only") is not True
        or any(
            receipt.get(field) is not expected
            for field, expected in PROVENANCE_NO_AUTHORIZATION_EFFECT.items()
        )
    ):
        return False
    payload = {
        key: value
        for key, value in receipt.items()
        if key not in {"digest", "signature", "verified"}
    }
    return _safe_hash(payload) == receipt["digest"]


def _application_integrity_valid(state: dict[str, Any]) -> bool:
    return state.get("application_integrity_result") == "PASS" and all(
        is_sha512(state.get(field))
        for field in _APPLICATION_INTEGRITY_DIGEST_FIELDS
    )


def _digital_provenance_valid(state: dict[str, Any]) -> bool:
    return (
        state.get("digital_provenance_result") == DIGITAL_PROVENANCE_ADMIT
        and state.get("digital_provenance_lineage_authenticated") is True
        and state.get("digital_provenance_lineage_only") is True
        and is_sha512(state.get("digital_provenance_digest"))
        and _provenance_receipt_valid(state)
    )


def _sovereign_identity_valid(state: dict[str, Any]) -> bool:
    record = state.get("sovereign_identity_record")
    return (
        state.get("sovereign_identity_result") == IDENTITY_VERIFIED
        and state.get("sovereign_identity_revocation_status") == "ACTIVE"
        and is_sha512(state.get("sovereign_identity_digest"))
        and type(record) is dict
        and record.get("result") == IDENTITY_VERIFIED
        and record.get("revocation_status") == "ACTIVE"
        and _exact_false_fields(record, _SOVEREIGN_IDENTITY_FALSE_FIELDS)
    )


def _authority_boundary_valid(state: dict[str, Any]) -> bool:
    record = state.get("authority_boundary_record")
    return (
        state.get("authority_boundary_result") == BOUNDARY_PASS
        and is_sha512(state.get("authority_boundary_digest"))
        and is_sha512(state.get("authority_boundary_trace_digest"))
        and type(record) is dict
        and record.get("result") == BOUNDARY_PASS
        and _exact_false_fields(record, _AUTHORITY_BOUNDARY_RECORD_FALSE_FIELDS)
        and all(
            state.get(field) is False
            for field in _AUTHORITY_BOUNDARY_STATE_FALSE_FIELDS
        )
    )


def _impersonation_valid(state: dict[str, Any]) -> bool:
    record = state.get("impersonation_protection_record")
    trace = state.get("impersonation_protection_trace")
    return (
        state.get("impersonation_protection_result") == IMPERSONATION_PASS
        and is_sha512(state.get("impersonation_protection_digest"))
        and type(record) is dict
        and type(trace) is list
        and bool(trace)
        and trace[-1] == record
        and state.get("impersonation_protection_digest") == _safe_hash(trace)
        and record.get("result") == IMPERSONATION_PASS
        and state.get("impersonation_protection_reason") == record.get("reason")
        and _exact_false_fields(record, _IMPERSONATION_FALSE_FIELDS)
        and all(
            state.get(f"impersonation_{field}") is False
            for field in _IMPERSONATION_FALSE_FIELDS
        )
    )


def _australian_minor_record_digest(record: Any) -> str | None:
    if type(record) is not dict:
        return None
    digest = record.get("record_digest")
    payload = {key: value for key, value in record.items() if key != "record_digest"}
    return digest if is_sha512(digest) and _safe_hash(payload) == digest else None


def _australian_minor_access_valid(state: dict[str, Any]) -> bool:
    record = state.get("australian_minor_access")
    if type(record) is not dict:
        return False
    result = record.get("result")
    result_contract_valid = (
        result == AUSTRALIAN_MINOR_ACCESS_PASS
        and record.get("applicable") is True
        and record.get("age_assurance_result") == AGE_AT_LEAST_16
        and record.get("privacy_data_destroyed") is True
    ) or (
        result == RESULT_NOT_APPLICABLE
        and record.get("applicable") is False
        and record.get("age_assurance_result") == AGE_INDETERMINATE
        and record.get("privacy_data_destroyed") is None
    )
    return (
        type(record) is dict
        and result_contract_valid
        and record.get("reason") == "AUTHENTICATED_DETERMINATION"
        and record.get("youth_penalty_applied") is False
        and _australian_minor_record_digest(record) is not None
        and _exact_false_fields(record, _AUSTRALIAN_MINOR_FALSE_FIELDS)
    )


def _first_failure(state: dict[str, Any]) -> str | None:
    checks = (
        (_application_integrity_valid, "APPLICATION_INTEGRITY_PREREQUISITE_FAILED"),
        (_digital_provenance_valid, "DIGITAL_PROVENANCE_PREREQUISITE_FAILED"),
        (_sovereign_identity_valid, "SOVEREIGN_IDENTITY_PREREQUISITE_FAILED"),
        (_authority_boundary_valid, "AUTHORITY_BOUNDARY_PREREQUISITE_FAILED"),
        (_impersonation_valid, "IMPERSONATION_PROTECTION_PREREQUISITE_FAILED"),
        (
            _australian_minor_access_valid,
            "AUSTRALIAN_MINOR_ACCESS_PREREQUISITE_FAILED",
        ),
    )
    for check, reason in checks:
        try:
            if not check(state):
                return reason
        except Exception:
            return reason
    return None


def _record(state: dict[str, Any], *, result: str, reason: str) -> dict[str, Any]:
    australian = state.get("australian_minor_access")
    australian = australian if type(australian) is dict else {}
    return {
        "contract_id": FOUNDATIONAL_BASELINE_CONTRACT_ID,
        "schema_status": FOUNDATIONAL_BASELINE_SCHEMA_STATUS,
        "foundational_order": deepcopy(FOUNDATIONAL_BASELINE_ORDER),
        "foundational_order_authority": FOUNDATIONAL_BASELINE_ORDER_AUTHORITY,
        "result": result,
        "reason": reason,
        "application_integrity_result": _safe_scalar(
            state.get("application_integrity_result")
        ),
        "application_integrity_result_digest": _safe_scalar(
            state.get("application_integrity_result_digest")
        ),
        "application_integrity_receipt_digest": _safe_scalar(
            state.get("application_integrity_receipt_digest")
        ),
        "application_integrity_manifest_digest": _safe_scalar(
            state.get("application_integrity_manifest_digest")
        ),
        "application_integrity_runtime_measurement_digest": _safe_scalar(
            state.get("application_integrity_runtime_measurement_digest")
        ),
        "application_integrity_trust_context_digest": _safe_scalar(
            state.get("application_integrity_trust_context_digest")
        ),
        "digital_provenance_result": _safe_scalar(
            state.get("digital_provenance_result")
        ),
        "digital_provenance_digest": _safe_scalar(
            state.get("digital_provenance_digest")
        ),
        "digital_provenance_verification_receipt_digest": (
            _provenance_receipt_digest(state)
        ),
        "sovereign_identity_result": _safe_scalar(
            state.get("sovereign_identity_result")
        ),
        "sovereign_identity_digest": _safe_scalar(
            state.get("sovereign_identity_digest")
        ),
        "sovereign_identity_revocation_status": _safe_scalar(
            state.get("sovereign_identity_revocation_status")
        ),
        "authority_boundary_result": _safe_scalar(
            state.get("authority_boundary_result")
        ),
        "authority_boundary_digest": _safe_scalar(
            state.get("authority_boundary_digest")
        ),
        "authority_boundary_trace_digest": _safe_scalar(
            state.get("authority_boundary_trace_digest")
        ),
        "impersonation_protection_result": _safe_scalar(
            state.get("impersonation_protection_result")
        ),
        "impersonation_protection_digest": _safe_scalar(
            state.get("impersonation_protection_digest")
        ),
        "australian_minor_access_result": _safe_scalar(
            australian.get("result")
        ),
        "australian_minor_access_record_digest": (
            _australian_minor_record_digest(australian)
        ),
        **{field: False for field in _AGGREGATE_AUTHORITY_FIELDS},
    }


def evaluate_foundational_baseline(state: Any) -> dict[str, Any]:
    """Evaluate the exact aggregate prerequisites and write one record."""

    malformed = type(state) is not dict
    target: dict[str, Any] = state if not malformed else {}
    reason: str | None
    if malformed:
        result = FOUNDATIONAL_BASELINE_DENY
        reason = "FOUNDATIONAL_BASELINE_STATE_INVALID"
    else:
        reason = _first_failure(target)
        result = (
            FOUNDATIONAL_BASELINE_PASS
            if reason is None
            else FOUNDATIONAL_BASELINE_DENY
        )
        if reason is None:
            reason = "FOUNDATIONAL_BASELINE_PREREQUISITES_VERIFIED"
    record = _record(target, result=result, reason=reason)
    digest = canonical_integrity_hash(record)
    target["foundational_baseline_record"] = deepcopy(record)
    target["foundational_baseline_result"] = result
    target["foundational_baseline_reason"] = reason
    target["foundational_baseline_digest"] = digest
    for field in _AGGREGATE_AUTHORITY_FIELDS:
        target[f"foundational_baseline_{field}"] = False
    return target


def foundational_baseline_hash_payload(state: Any) -> dict[str, Any]:
    """Return the exact canonical aggregate hash payload."""

    source = state if type(state) is dict else {}
    record = source.get("foundational_baseline_record")
    record = record if type(record) is dict else {}
    payload = {
        "contract_id": _safe_scalar(record.get("contract_id")),
        "schema_status": _safe_scalar(record.get("schema_status")),
        "result": _safe_scalar(record.get("result")),
        "reason": _safe_scalar(record.get("reason")),
        "record_digest": _safe_scalar(source.get("foundational_baseline_digest")),
        "foundational_order": _safe_order(record.get("foundational_order")),
        "foundational_order_authority": _safe_scalar(
            record.get("foundational_order_authority")
        ),
        "application_integrity_result_digest": _safe_scalar(
            record.get("application_integrity_result_digest")
        ),
        "application_integrity_receipt_digest": _safe_scalar(
            record.get("application_integrity_receipt_digest")
        ),
        "digital_provenance_digest": _safe_scalar(
            record.get("digital_provenance_digest")
        ),
        "digital_provenance_verification_receipt_digest": _safe_scalar(
            record.get("digital_provenance_verification_receipt_digest")
        ),
        "sovereign_identity_digest": _safe_scalar(
            record.get("sovereign_identity_digest")
        ),
        "authority_boundary_digest": _safe_scalar(
            record.get("authority_boundary_digest")
        ),
        "authority_boundary_trace_digest": _safe_scalar(
            record.get("authority_boundary_trace_digest")
        ),
        "impersonation_protection_digest": _safe_scalar(
            record.get("impersonation_protection_digest")
        ),
        "australian_minor_access_record_digest": _safe_scalar(
            record.get("australian_minor_access_record_digest")
        ),
        **{field: False for field in _AGGREGATE_AUTHORITY_FIELDS},
    }
    return payload


def _verify_record(state: dict[str, Any]) -> bool:
    if _first_failure(state) is not None:
        return False
    expected = _record(
        state,
        result=FOUNDATIONAL_BASELINE_PASS,
        reason="FOUNDATIONAL_BASELINE_PREREQUISITES_VERIFIED",
    )
    record = state.get("foundational_baseline_record")
    digest = _safe_hash(expected)
    return (
        type(record) is dict
        and set(record) == _RECORD_FIELDS
        and record == expected
        and is_sha512(digest)
        and state.get("foundational_baseline_digest") == digest
        and state.get("foundational_baseline_result") == FOUNDATIONAL_BASELINE_PASS
        and state.get("foundational_baseline_reason")
        == "FOUNDATIONAL_BASELINE_PREREQUISITES_VERIFIED"
        and all(
            state.get(f"foundational_baseline_{field}") is False
            for field in _AGGREGATE_AUTHORITY_FIELDS
        )
    )


def verify_foundational_baseline(
    state: Any,
    require_hash_binding: bool = True,
) -> bool:
    """Verify the exact aggregate record and optional unique chain binding."""

    try:
        if type(state) is not dict or not _verify_record(state):
            return False
        payload = foundational_baseline_hash_payload(state)
        if set(payload) != _HASH_PAYLOAD_FIELDS:
            return False
        if not require_hash_binding:
            return True
        chain = state.get("hash_chain")
        state_hash = state.get("state_hash")
        if type(chain) is not list:
            return False
        if not verify_hash_chain_entries(chain, state_hash):
            return False
        index = state.get("foundational_baseline_hash_binding_index")
        binding_hash = state.get("foundational_baseline_hash_binding_hash")
        if (
            type(index) is not int
            or index < 0
            or not is_sha512(binding_hash)
            or index >= len(chain)
        ):
            return False
        matches = [
            (candidate_index, entry)
            for candidate_index, entry in enumerate(chain)
            if type(entry) is dict
            and entry.get("stage") == FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
        ]
        if len(matches) != 1 or matches[0][0] != index:
            return False
        entry = matches[0][1]
        return (
            entry is chain[index]
            and entry.get("hash") == binding_hash
            and entry.get("payload_hash") == canonical_integrity_hash(payload)
            and entry.get("previous_hash")
            == (GENESIS_HASH if index == 0 else chain[index - 1]["hash"])
        )
    except Exception:
        return False


def bind_foundational_baseline_hash(state: Any) -> dict[str, Any]:
    """Append the one canonical aggregate binding at the current chain tail."""

    if type(state) is not dict or not verify_foundational_baseline(
        state, require_hash_binding=False
    ):
        raise ValueError("FOUNDATIONAL_BASELINE_NOT_VERIFIED")
    if (
        state.get("foundational_baseline_hash_binding_index") is not None
        or state.get("foundational_baseline_hash_binding_hash") is not None
    ):
        raise ValueError("FOUNDATIONAL_BASELINE_PREBOUND")
    chain = state.get("hash_chain")
    if type(chain) is not list:
        raise ValueError("FOUNDATIONAL_BASELINE_HASH_CHAIN_INVALID")
    if any(
        type(entry) is dict
        and entry.get("stage") == FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
        for entry in chain
    ):
        raise ValueError("FOUNDATIONAL_BASELINE_HASH_BINDING_DUPLICATE")
    if chain:
        if not verify_hash_chain_entries(chain, state.get("state_hash")):
            raise ValueError("FOUNDATIONAL_BASELINE_HASH_CHAIN_INVALID")
        previous_hash = chain[-1]["hash"]
    else:
        if state.get("state_hash") != GENESIS_HASH:
            raise ValueError("FOUNDATIONAL_BASELINE_HASH_CHAIN_INVALID")
        previous_hash = GENESIS_HASH
    entry = build_hash_chain_entry(
        previous_hash=previous_hash,
        stage=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        payload=foundational_baseline_hash_payload(state),
    )
    index = len(chain)
    chain.append(entry)
    state["state_hash"] = entry["hash"]
    state["foundational_baseline_hash_binding_index"] = index
    state["foundational_baseline_hash_binding_hash"] = entry["hash"]
    if not verify_foundational_baseline(state):
        chain.pop()
        state["state_hash"] = previous_hash
        state["foundational_baseline_hash_binding_index"] = None
        state["foundational_baseline_hash_binding_hash"] = None
        raise ValueError("FOUNDATIONAL_BASELINE_HASH_BINDING_FAILED")
    return deepcopy(entry)


__all__ = [
    "FOUNDATIONAL_BASELINE_CONTRACT_ID",
    "FOUNDATIONAL_BASELINE_DENY",
    "FOUNDATIONAL_BASELINE_PASS",
    "FOUNDATIONAL_BASELINE_SCHEMA_STATUS",
    "bind_foundational_baseline_hash",
    "evaluate_foundational_baseline",
    "foundational_baseline_hash_payload",
    "verify_foundational_baseline",
]
