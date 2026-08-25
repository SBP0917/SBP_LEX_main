from __future__ import annotations

from copy import deepcopy

import pytest

from sbp_lex.baseline.foundational_baseline import (
    FOUNDATIONAL_BASELINE_CONTRACT_ID,
    FOUNDATIONAL_BASELINE_DENY,
    FOUNDATIONAL_BASELINE_PASS,
    FOUNDATIONAL_BASELINE_SCHEMA_STATUS,
    bind_foundational_baseline_hash,
    evaluate_foundational_baseline,
    foundational_baseline_hash_payload,
    verify_foundational_baseline,
)
from sbp_lex.compliance.australian_minor_access import (
    RESULT_DENY,
    RESULT_NOT_APPLICABLE,
    RESULT_PASS as AUSTRALIAN_MINOR_ACCESS_PASS,
)
from sbp_lex.config.pipeline_config import (
    FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
    FOUNDATIONAL_BASELINE_ORDER,
    FOUNDATIONAL_BASELINE_ORDER_AUTHORITY,
)
from sbp_lex.provenance.digital_provenance import (
    ADMIT as DIGITAL_PROVENANCE_ADMIT,
    NO_AUTHORIZATION_EFFECT as PROVENANCE_NO_AUTHORIZATION_EFFECT,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)


AGGREGATE_AUTHORITY_FIELDS = (
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
)
APPLICATION_DIGEST_FIELDS = (
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "application_integrity_manifest_digest",
    "application_integrity_runtime_measurement_digest",
    "application_integrity_trust_context_digest",
)
RECORD_FIELDS = {
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
    *AGGREGATE_AUTHORITY_FIELDS,
}
HASH_PAYLOAD_FIELDS = {
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
    *AGGREGATE_AUTHORITY_FIELDS,
}


def _digest(label: str) -> str:
    return canonical_integrity_hash({"fixture": label})


def _signed_provenance_receipt(graph_digest: str) -> dict:
    payload = {
        "schema_id": "SBP_LEX_PROVENANCE_VERIFICATION_RECEIPT_V2",
        "result": DIGITAL_PROVENANCE_ADMIT,
        "graph_digest": graph_digest,
        "release_manifest_digest": _digest(
            "application_integrity_manifest_digest"
        ),
        "runtime_measurement_digest": _digest(
            "application_integrity_runtime_measurement_digest"
        ),
        "durable_claim_result": "CLAIMED",
        "durable_claim_digest": _digest("durable-claim"),
        "durable_transition_receipt_digest": _digest(
            "durable-transition"
        ),
        "durable_live_heads_digest": _digest("durable-live-heads"),
        "revocation_head_digest": _digest("revocation-head"),
        "clock_evidence_digest": _digest("clock-evidence"),
        "production_durable_storage_proven_by_module": False,
        "lineage_authenticated": True,
        "lineage_only": True,
        **dict(PROVENANCE_NO_AUTHORIZATION_EFFECT),
    }
    return {
        **payload,
        "digest": canonical_integrity_hash(payload),
        "signature": {
            "provider_id": "provider-1",
            "algorithm": "Ed25519",
            "key_id": "key-1",
            "custody_class": "HARDWARE_BACKED",
            "effect_authority": False,
            "signature_b64": "c2lnbmF0dXJl",
        },
        "verified": False,
    }


def _minor_record(result: str) -> dict:
    applicable = result != RESULT_NOT_APPLICABLE
    record = {
        "schema": "SBP-LEX-AU-MINOR-ACCESS-V3",
        "result": result,
        "age_assurance_result": (
            "UNDER_16"
            if result == RESULT_DENY
            else "INDETERMINATE"
            if result == RESULT_NOT_APPLICABLE
            else "AT_LEAST_16"
        ),
        "applicable": applicable,
        "reason": "AUTHENTICATED_DETERMINATION",
        "privacy_data_destroyed": True if applicable else None,
        "youth_penalty_applied": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority": False,
    }
    record["record_digest"] = canonical_integrity_hash(record)
    return record


def _passing_state(
    minor_result: str = AUSTRALIAN_MINOR_ACCESS_PASS,
) -> dict:
    provenance_digest = _digest("provenance")
    sovereign_record = {
        "result": "VERIFIED",
        "revocation_status": "ACTIVE",
        "biometric_proof_established": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
    }
    authority_record = {
        "result": "BOUNDARY_PASS",
        "stakeholder_label_grants_rights": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }
    impersonation_record = {
        "result": "PASS",
        "reason": "IMPERSONATION_PROTECTION_COMPLETED",
        "biometric_proof_established": False,
        "identity_issued": False,
        "identity_label_grants_access": False,
        "role_label_grants_authority": False,
        "mandate_label_grants_authority": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }
    state = {
        "application_integrity_result": "PASS",
        **{field: _digest(field) for field in APPLICATION_DIGEST_FIELDS},
        "digital_provenance_result": DIGITAL_PROVENANCE_ADMIT,
        "digital_provenance_digest": provenance_digest,
        "digital_provenance_lineage_authenticated": True,
        "digital_provenance_lineage_only": True,
        "digital_provenance_verification_receipt": (
            _signed_provenance_receipt(provenance_digest)
        ),
        "sovereign_identity_result": "VERIFIED",
        "sovereign_identity_revocation_status": "ACTIVE",
        "sovereign_identity_digest": _digest("sovereign-identity"),
        "sovereign_identity_record": sovereign_record,
        "authority_boundary_result": "BOUNDARY_PASS",
        "authority_boundary_digest": _digest("authority-boundary"),
        "authority_boundary_trace_digest": _digest("authority-boundary-trace"),
        "authority_boundary_record": authority_record,
        "stakeholder_label_grants_rights": False,
        "participant_authority_granted": False,
        "participant_licence_granted": False,
        "participant_execution_authority_granted": False,
        "participant_effect_authority_granted": False,
        "participant_pipeline_bypass_permitted": False,
        "impersonation_protection_result": "PASS",
        "impersonation_protection_digest": canonical_integrity_hash(
            [impersonation_record]
        ),
        "impersonation_protection_trace": [deepcopy(impersonation_record)],
        "impersonation_protection_record": impersonation_record,
        "impersonation_protection_reason": (
            "IMPERSONATION_PROTECTION_COMPLETED"
        ),
        "australian_minor_access": _minor_record(minor_result),
        "hash_chain": [],
        "state_hash": GENESIS_HASH,
        "foundational_baseline_hash_binding_index": None,
        "foundational_baseline_hash_binding_hash": None,
    }
    for field in (
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
    ):
        state[f"impersonation_{field}"] = False
    return state


def _append_stage(state: dict, stage: str) -> dict:
    entry = build_hash_chain_entry(
        previous_hash=state["state_hash"],
        stage=stage,
        payload={"stage": stage},
    )
    state["hash_chain"].append(entry)
    state["state_hash"] = entry["hash"]
    return entry


def _evaluate_pass(state: dict | None = None) -> dict:
    target = _passing_state() if state is None else state
    evaluate_foundational_baseline(target)
    assert verify_foundational_baseline(target, require_hash_binding=False)
    return target


def test_exact_pass_record_and_payload() -> None:
    state = _evaluate_pass()
    record = state["foundational_baseline_record"]
    payload = foundational_baseline_hash_payload(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_PASS
    assert state["foundational_baseline_reason"] == (
        "FOUNDATIONAL_BASELINE_PREREQUISITES_VERIFIED"
    )
    assert record["contract_id"] == FOUNDATIONAL_BASELINE_CONTRACT_ID
    assert record["schema_status"] == FOUNDATIONAL_BASELINE_SCHEMA_STATUS
    assert record["foundational_order"] == FOUNDATIONAL_BASELINE_ORDER
    assert record["foundational_order_authority"] == (
        FOUNDATIONAL_BASELINE_ORDER_AUTHORITY
    )
    assert set(record) == RECORD_FIELDS
    assert set(payload) == HASH_PAYLOAD_FIELDS
    assert state["foundational_baseline_digest"] == canonical_integrity_hash(record)
    assert payload["record_digest"] == state["foundational_baseline_digest"]
    assert verify_foundational_baseline(state) is False


@pytest.mark.parametrize("field", APPLICATION_DIGEST_FIELDS)
def test_each_application_integrity_digest_is_required(field: str) -> None:
    state = _passing_state()
    state[field] = None

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert state["foundational_baseline_reason"] == (
        "APPLICATION_INTEGRITY_PREREQUISITE_FAILED"
    )
    assert verify_foundational_baseline(state, require_hash_binding=False) is False


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("application_integrity_result", "DENY", "APPLICATION_INTEGRITY_PREREQUISITE_FAILED"),
        ("digital_provenance_result", "DENY", "DIGITAL_PROVENANCE_PREREQUISITE_FAILED"),
        ("digital_provenance_lineage_authenticated", False, "DIGITAL_PROVENANCE_PREREQUISITE_FAILED"),
        ("digital_provenance_lineage_only", False, "DIGITAL_PROVENANCE_PREREQUISITE_FAILED"),
        ("digital_provenance_digest", None, "DIGITAL_PROVENANCE_PREREQUISITE_FAILED"),
        ("sovereign_identity_result", "DENY", "SOVEREIGN_IDENTITY_PREREQUISITE_FAILED"),
        ("sovereign_identity_revocation_status", "REVOKED", "SOVEREIGN_IDENTITY_PREREQUISITE_FAILED"),
        ("sovereign_identity_digest", None, "SOVEREIGN_IDENTITY_PREREQUISITE_FAILED"),
        ("authority_boundary_result", "BOUNDARY_DENY", "AUTHORITY_BOUNDARY_PREREQUISITE_FAILED"),
        ("authority_boundary_digest", None, "AUTHORITY_BOUNDARY_PREREQUISITE_FAILED"),
        ("authority_boundary_trace_digest", None, "AUTHORITY_BOUNDARY_PREREQUISITE_FAILED"),
        ("impersonation_protection_result", "DENY", "IMPERSONATION_PROTECTION_PREREQUISITE_FAILED"),
        ("impersonation_protection_digest", None, "IMPERSONATION_PROTECTION_PREREQUISITE_FAILED"),
    ],
)
def test_each_component_prerequisite_fails_closed(
    field: str,
    value: object,
    reason: str,
) -> None:
    state = _passing_state()
    state[field] = value

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert state["foundational_baseline_reason"] == reason


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_receipt",
        "verified_true",
        "signature_extra_field",
        "empty_signature_value",
        "signature_effect_authority",
        "tampered_digest",
        "graph_digest_mismatch",
        "receipt_authority_grant",
    ],
)
def test_provenance_receipt_structural_admission_fails_closed(
    mutation: str,
) -> None:
    state = _passing_state()
    receipt = state["digital_provenance_verification_receipt"]
    if mutation == "missing_receipt":
        state["digital_provenance_verification_receipt"] = None
    elif mutation == "verified_true":
        receipt["verified"] = True
    elif mutation == "signature_extra_field":
        receipt["signature"]["extra"] = "not-exact"
    elif mutation == "empty_signature_value":
        receipt["signature"]["signature_b64"] = ""
    elif mutation == "signature_effect_authority":
        receipt["signature"]["effect_authority"] = True
    elif mutation == "tampered_digest":
        receipt["digest"] = _digest("tampered")
    elif mutation == "graph_digest_mismatch":
        receipt["graph_digest"] = _digest("substituted")
        payload = {
            key: value
            for key, value in receipt.items()
            if key not in {"digest", "signature", "verified"}
        }
        receipt["digest"] = canonical_integrity_hash(payload)
    else:
        receipt["governance_allow_granted"] = True
        payload = {
            key: value
            for key, value in receipt.items()
            if key not in {"digest", "signature", "verified"}
        }
        receipt["digest"] = canonical_integrity_hash(payload)

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert state["foundational_baseline_reason"] == (
        "DIGITAL_PROVENANCE_PREREQUISITE_FAILED"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("release_manifest_digest", _digest("wrong-release")),
        ("runtime_measurement_digest", _digest("wrong-runtime")),
        ("durable_claim_result", "ALREADY_CLAIMED"),
        ("durable_claim_digest", None),
        ("durable_transition_receipt_digest", None),
        ("durable_live_heads_digest", None),
        ("revocation_head_digest", None),
        ("clock_evidence_digest", None),
        ("production_durable_storage_proven_by_module", True),
    ],
)
def test_provenance_release_and_durable_bindings_fail_closed(
    field: str,
    value: object,
) -> None:
    state = _passing_state()
    receipt = state["digital_provenance_verification_receipt"]
    receipt[field] = value
    payload = {
        key: value
        for key, value in receipt.items()
        if key not in {"digest", "signature", "verified"}
    }
    receipt["digest"] = canonical_integrity_hash(payload)

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert state["foundational_baseline_reason"] == (
        "DIGITAL_PROVENANCE_PREREQUISITE_FAILED"
    )


@pytest.mark.parametrize(
    "mutation",
    ["missing_trace", "terminal_record_mismatch", "trace_digest_mismatch", "reason_mismatch"],
)
def test_impersonation_terminal_trace_binding_fails_closed(mutation: str) -> None:
    state = _passing_state()
    if mutation == "missing_trace":
        state["impersonation_protection_trace"] = None
    elif mutation == "terminal_record_mismatch":
        state["impersonation_protection_trace"][-1] = {
            **state["impersonation_protection_record"],
            "reason": "SUBSTITUTED",
        }
        state["impersonation_protection_digest"] = canonical_integrity_hash(
            state["impersonation_protection_trace"]
        )
    elif mutation == "trace_digest_mismatch":
        state["impersonation_protection_digest"] = _digest("wrong-trace")
    else:
        state["impersonation_protection_reason"] = "SUBSTITUTED"

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert state["foundational_baseline_reason"] == (
        "IMPERSONATION_PROTECTION_PREREQUISITE_FAILED"
    )


@pytest.mark.parametrize(
    ("result", "field", "value"),
    [
        (AUSTRALIAN_MINOR_ACCESS_PASS, "applicable", False),
        (AUSTRALIAN_MINOR_ACCESS_PASS, "age_assurance_result", "UNDER_16"),
        (AUSTRALIAN_MINOR_ACCESS_PASS, "privacy_data_destroyed", False),
        (AUSTRALIAN_MINOR_ACCESS_PASS, "youth_penalty_applied", True),
        (RESULT_NOT_APPLICABLE, "applicable", True),
        (RESULT_NOT_APPLICABLE, "age_assurance_result", "AT_LEAST_16"),
        (RESULT_NOT_APPLICABLE, "privacy_data_destroyed", True),
    ],
)
def test_minor_privacy_outcome_correlations_fail_closed(
    result: str,
    field: str,
    value: object,
) -> None:
    state = _passing_state(result)
    record = state["australian_minor_access"]
    record[field] = value
    payload = {
        key: value
        for key, value in record.items()
        if key != "record_digest"
    }
    record["record_digest"] = canonical_integrity_hash(payload)

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert state["foundational_baseline_reason"] == (
        "AUSTRALIAN_MINOR_ACCESS_PREREQUISITE_FAILED"
    )


@pytest.mark.parametrize(
    ("component", "field"),
    [
        ("sovereign_identity_record", "authority_granted"),
        ("authority_boundary_record", "pipeline_bypass_permitted"),
        ("authority_boundary_state", "participant_licence_granted"),
        ("impersonation_protection_record", "effect_authority_granted"),
        ("impersonation_state", "impersonation_execution_authority_granted"),
        ("australian_minor_access", "authority_granted"),
    ],
)
def test_component_authority_flags_must_remain_false(
    component: str,
    field: str,
) -> None:
    state = _passing_state()
    if component == "authority_boundary_state" or component == "impersonation_state":
        state[field] = True
    else:
        state[component][field] = True
        if component == "australian_minor_access":
            record = state[component]
            payload = {
                key: value for key, value in record.items() if key != "record_digest"
            }
            record["record_digest"] = canonical_integrity_hash(payload)

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY


@pytest.mark.parametrize(
    "minor_result",
    [AUSTRALIAN_MINOR_ACCESS_PASS, RESULT_NOT_APPLICABLE],
)
def test_minor_pass_and_not_applicable_are_accepted(minor_result: str) -> None:
    state = _passing_state(minor_result)

    evaluate_foundational_baseline(state)

    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_PASS
    assert verify_foundational_baseline(state, require_hash_binding=False)


def test_under_16_minor_deny_is_rejected() -> None:
    state = _passing_state(RESULT_DENY)

    evaluate_foundational_baseline(state)

    assert state["australian_minor_access"]["age_assurance_result"] == "UNDER_16"
    assert state["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert state["foundational_baseline_reason"] == (
        "AUSTRALIAN_MINOR_ACCESS_PREREQUISITE_FAILED"
    )


def test_no_component_or_aggregate_grants_authority() -> None:
    state = _evaluate_pass()
    record = state["foundational_baseline_record"]

    assert record["result"] == FOUNDATIONAL_BASELINE_PASS
    assert record["result"] != "ALLOW"
    for field in AGGREGATE_AUTHORITY_FIELDS:
        assert record[field] is False
        assert state[f"foundational_baseline_{field}"] is False
    for field, expected in PROVENANCE_NO_AUTHORIZATION_EFFECT.items():
        assert state["digital_provenance_verification_receipt"][field] is expected
    assert state["sovereign_identity_record"]["authority_granted"] is False
    assert state["authority_boundary_record"]["authority_granted"] is False
    assert state["impersonation_protection_record"]["authority_granted"] is False
    assert state["australian_minor_access"]["authority_granted"] is False


def test_result_is_deterministic() -> None:
    first = _passing_state()
    second = deepcopy(first)

    evaluate_foundational_baseline(first)
    evaluate_foundational_baseline(second)

    assert first["foundational_baseline_record"] == second[
        "foundational_baseline_record"
    ]
    assert first["foundational_baseline_digest"] == second[
        "foundational_baseline_digest"
    ]


def test_bind_appends_exact_canonical_entry_and_rejects_prebinding() -> None:
    state = _evaluate_pass()
    prefix = _append_stage(state, "australian_minor_access")

    entry = bind_foundational_baseline_hash(state)

    assert entry["stage"] == FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
    assert entry["previous_hash"] == prefix["hash"]
    assert entry["payload_hash"] == canonical_integrity_hash(
        foundational_baseline_hash_payload(state)
    )
    assert state["foundational_baseline_hash_binding_index"] == 1
    assert state["foundational_baseline_hash_binding_hash"] == entry["hash"]
    assert verify_foundational_baseline(state)
    with pytest.raises(ValueError, match="FOUNDATIONAL_BASELINE_PREBOUND"):
        bind_foundational_baseline_hash(state)


def test_missing_binding_fails() -> None:
    state = _evaluate_pass()
    _append_stage(state, "australian_minor_access")
    bind_foundational_baseline_hash(state)
    state["hash_chain"].pop()
    state["state_hash"] = state["hash_chain"][-1]["hash"]

    assert verify_foundational_baseline(state) is False


def test_duplicate_binding_fails() -> None:
    state = _evaluate_pass()
    bind_foundational_baseline_hash(state)
    duplicate = build_hash_chain_entry(
        previous_hash=state["state_hash"],
        stage=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        payload=foundational_baseline_hash_payload(state),
    )
    state["hash_chain"].append(duplicate)
    state["state_hash"] = duplicate["hash"]

    assert verify_foundational_baseline(state) is False


def test_reordered_binding_fails() -> None:
    state = _evaluate_pass()
    _append_stage(state, "state_construction")
    _append_stage(state, "australian_minor_access")
    bind_foundational_baseline_hash(state)
    state["hash_chain"][0], state["hash_chain"][1] = (
        state["hash_chain"][1],
        state["hash_chain"][0],
    )

    assert verify_foundational_baseline(state) is False


def test_tampered_binding_fails() -> None:
    state = _evaluate_pass()
    bind_foundational_baseline_hash(state)
    state["hash_chain"][0]["payload_hash"] = _digest("tampered")

    assert verify_foundational_baseline(state) is False


def test_wrong_previous_binding_fails() -> None:
    state = _evaluate_pass()
    _append_stage(state, "australian_minor_access")
    bind_foundational_baseline_hash(state)
    entry = state["hash_chain"][1]
    entry["previous_hash"] = GENESIS_HASH
    entry["hash"] = canonical_integrity_hash(
        {
            "stage": entry["stage"],
            "previous_hash": entry["previous_hash"],
            "payload_hash": entry["payload_hash"],
        }
    )
    state["foundational_baseline_hash_binding_hash"] = entry["hash"]
    state["state_hash"] = entry["hash"]

    assert verify_foundational_baseline(state) is False


def test_later_canonical_stage_append_remains_valid() -> None:
    state = _evaluate_pass()
    bind_foundational_baseline_hash(state)

    later = _append_stage(state, "collective_attach")

    assert later["previous_hash"] == state["hash_chain"][0]["hash"]
    assert verify_foundational_baseline(state)


def test_malformed_state_fails_closed() -> None:
    denied = evaluate_foundational_baseline(None)
    malformed_payload = foundational_baseline_hash_payload(
        {"foundational_baseline_record": {"foundational_order": object()}}
    )

    assert denied["foundational_baseline_result"] == FOUNDATIONAL_BASELINE_DENY
    assert denied["foundational_baseline_reason"] == (
        "FOUNDATIONAL_BASELINE_STATE_INVALID"
    )
    assert verify_foundational_baseline(None) is False
    assert verify_foundational_baseline({}) is False
    assert malformed_payload["foundational_order"] is None
    with pytest.raises(ValueError, match="FOUNDATIONAL_BASELINE_NOT_VERIFIED"):
        bind_foundational_baseline_hash(None)
