from __future__ import annotations

from copy import deepcopy

from sbp_lex.shared.state_builder import build_state
from sbp_lex.shared.state_schema import STATE_TEMPLATE


REQUEST_EVIDENCE_FIELDS = (
    "digital_provenance_graph",
    "biometric_attestation_digest",
    "identity_jurisdictions",
    "identity_access_grants",
    "participant_id",
    "stakeholder_class",
    "participant_role",
    "participant_mandate_id",
    "impersonation_session_id",
    "impersonation_audience",
    "impersonation_challenge",
    "subject_id",
    "session_id",
    "service_id",
    "request_nonce",
)

CONTROL_DEFAULTS = {
    "application_integrity_result": "",
    "application_integrity_result_digest": None,
    "application_integrity_receipt_digest": None,
    "application_integrity_manifest_digest": None,
    "application_integrity_runtime_measurement_digest": None,
    "application_integrity_trust_context_digest": None,
    "digital_provenance_result": "",
    "digital_provenance_reason": "",
    "digital_provenance_digest": None,
    "digital_provenance_lineage_authenticated": False,
    "digital_provenance_verification_trace": [],
    "digital_provenance_verification_receipt": {},
    "digital_provenance_lineage_only": True,
    "sovereign_identity_trace": [],
    "sovereign_identity_record": {},
    "sovereign_identity_digest": None,
    "sovereign_identity_result": "",
    "sovereign_identity_reason": "",
    "sovereign_identity_revocation_status": "",
    "sovereign_identity_revocation_sequence": None,
    "authority_boundary_trace": [],
    "authority_boundary_record": {},
    "authority_boundary_digest": None,
    "authority_boundary_trace_digest": None,
    "authority_boundary_result": "",
    "authority_boundary_reason": "",
    "stakeholder_label_grants_rights": False,
    "participant_authority_granted": False,
    "participant_licence_granted": False,
    "participant_execution_authority_granted": False,
    "participant_effect_authority_granted": False,
    "participant_pipeline_bypass_permitted": False,
    "impersonation_protection_trace": [],
    "impersonation_protection_record": {},
    "impersonation_protection_digest": None,
    "impersonation_protection_result": "",
    "impersonation_protection_reason": "",
    "impersonation_biometric_proof_established": False,
    "impersonation_identity_issued": False,
    "impersonation_identity_label_grants_access": False,
    "impersonation_role_label_grants_authority": False,
    "impersonation_mandate_label_grants_authority": False,
    "impersonation_access_granted": False,
    "impersonation_authority_granted": False,
    "impersonation_licence_granted": False,
    "impersonation_execution_authority_granted": False,
    "impersonation_effect_authority_granted": False,
    "impersonation_pipeline_bypass_permitted": False,
    "australian_minor_access": {},
    "australian_minor_access_hash_binding_index": None,
    "australian_minor_access_hash_binding_hash": None,
    "foundational_baseline_record": {},
    "foundational_baseline_result": "",
    "foundational_baseline_reason": "",
    "foundational_baseline_digest": None,
    "foundational_baseline_hash_binding_index": None,
    "foundational_baseline_hash_binding_hash": None,
    "foundational_baseline_authority_granted": False,
    "foundational_baseline_licence_granted": False,
    "foundational_baseline_execution_authority_granted": False,
    "foundational_baseline_effect_authority_granted": False,
    "foundational_baseline_pipeline_bypass_permitted": False,
}


def test_foundational_request_evidence_is_deep_copied() -> None:
    source = {
        "digital_provenance_graph": {
            "nodes": [{"node_id": "source"}],
            "edges": [],
        },
        "biometric_attestation_digest": "a" * 128,
        "identity_jurisdictions": ["AU", "NZ"],
        "identity_access_grants": [
            {
                "grant_id": "grant-1",
                "jurisdiction": "AU",
                "actions": ["READ"],
            }
        ],
        "participant_id": "participant-1",
        "stakeholder_class": "regulators",
        "participant_role": "reviewer",
        "participant_mandate_id": "mandate-1",
        "impersonation_session_id": "impersonation-session-1",
        "impersonation_audience": ["service-1"],
        "impersonation_challenge": {"nonce": "challenge-1"},
        "subject_id": "subject-1",
        "session_id": "session-1",
        "service_id": "service-1",
        "request_nonce": {"nonce": "request-1"},
    }
    expected = deepcopy(source)

    state = build_state(source)
    source["digital_provenance_graph"]["nodes"][0]["node_id"] = "changed"
    source["identity_jurisdictions"].append("US")
    source["identity_access_grants"][0]["actions"].append("WRITE")
    source["impersonation_audience"].append("service-2")
    source["impersonation_challenge"]["nonce"] = "changed"
    source["request_nonce"]["nonce"] = "changed"

    for field in REQUEST_EVIDENCE_FIELDS:
        assert state[field] == expected[field]


def test_foundational_fields_have_fail_closed_missing_defaults() -> None:
    state = build_state()

    for field in REQUEST_EVIDENCE_FIELDS:
        assert state[field] is None
    for field, expected in CONTROL_DEFAULTS.items():
        assert state[field] == expected
    assert state["digital_provenance_result"] != "ADMIT"
    assert state["sovereign_identity_result"] != "VERIFIED"
    assert state["authority_boundary_result"] != "BOUNDARY_PASS"
    assert state["impersonation_protection_result"] != "PASS"


def test_possession_proof_is_not_retained_in_state() -> None:
    state = build_state(
        {
            "possession_proof": {"signature": "sensitive"},
            "impersonation_possession_proof": {"signature": "sensitive"},
            "proof_of_possession": {"signature": "sensitive"},
        }
    )

    assert "possession_proof" not in state
    assert "impersonation_possession_proof" not in state
    assert "proof_of_possession" not in state


def test_foundational_schema_and_builder_defaults_are_equal() -> None:
    state = build_state()

    expected_defaults = {
        **{field: None for field in REQUEST_EVIDENCE_FIELDS},
        **CONTROL_DEFAULTS,
    }
    for field, expected in expected_defaults.items():
        assert field in STATE_TEMPLATE
        assert STATE_TEMPLATE[field] == expected
        assert state[field] == expected


def test_foundational_mutable_outputs_are_not_shared_between_states() -> None:
    first = build_state()
    second = build_state()

    first["digital_provenance_verification_trace"].append({"stage": "test"})
    first["sovereign_identity_trace"].append({"stage": "test"})
    first["authority_boundary_record"]["stage"] = "test"
    first["impersonation_protection_trace"].append({"stage": "test"})
    first["australian_minor_access"]["result"] = "test"
    first["foundational_baseline_record"]["result"] = "test"

    assert second["digital_provenance_verification_trace"] == []
    assert second["sovereign_identity_trace"] == []
    assert second["authority_boundary_record"] == {}
    assert second["impersonation_protection_trace"] == []
    assert second["australian_minor_access"] == {}
    assert second["foundational_baseline_record"] == {}


def test_startup_and_aggregate_outputs_cannot_be_prepopulated() -> None:
    attempted_outputs = {
        field: (
            True
            if type(default) is bool
            else 7
            if default is None
            else {"caller": "supplied"}
            if type(default) is dict
            else "CALLER_SUPPLIED"
        )
        for field, default in CONTROL_DEFAULTS.items()
        if field.startswith("application_integrity_")
        or field.startswith("foundational_baseline_")
    }

    state = build_state(attempted_outputs)

    for field in attempted_outputs:
        assert state[field] == CONTROL_DEFAULTS[field]
