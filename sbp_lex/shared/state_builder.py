from __future__ import annotations

from copy import deepcopy
from typing import Dict, Any, Optional

from sbp_lex.config.security_config import build_security_config
from sbp_lex.config.pipeline_config import build_pipeline_config
from sbp_lex.config.thresholds import (
    ensure_safety_profile,
)


# ─────────────────────────────────────────────
# SBP-LEX V2 SINGLE-PIPELINE STATE BUILDER
# ─────────────────────────────────────────────

def build_state(input_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Construct the canonical V2 single-pipeline state object.

    This is the only supported entry construction point for pipeline state.
    It:
    - normalises incoming request data
    - applies locked defaults
    - attaches config snapshots
    - prepares all mandatory state keys
    """

    source = deepcopy(input_data or {})

    state: Dict[str, Any] = {
        # Request identity / raw request
        "request_fingerprint": None,
        "action": source.get("action", ""),
        "payload": deepcopy(source.get("payload", {})),
        "context": deepcopy(source.get("context", {})),
        "identity": deepcopy(source.get("identity")),

        # Submitted authority claims are untrusted until P0 provenance.
        "submitted_authority_claim": deepcopy(
            source.get("resolved_authority")
        ),
        "requested_jurisdiction": deepcopy(source.get("jurisdiction")),
        "submitted_ap_acf_class": deepcopy(source.get("ap_acf_class")),
        "submitted_ap_acf_subclass": deepcopy(
            source.get("ap_acf_subclass")
        ),
        "submitted_policy_artifact": deepcopy(
            source.get("payload", {}).get("policy")
            if type(source.get("payload")) is dict
            else None
        ),
        "resolved_authority": "",
        "jurisdiction": "",
        "aj_saaf_operational_context": deepcopy(
            source.get("aj_saaf_operational_context")
        ),
        "abegf_request": deepcopy(source.get("abegf_request")),

        # Optional raw supporting inputs
        "sources": deepcopy(source.get("sources", [])),
        "financial_amount": source.get("financial_amount", 0.0),
        "evaluation_time": source.get("evaluation_time", 0),

        # Foundational baseline request evidence
        "digital_provenance_graph": deepcopy(
            source.get("digital_provenance_graph")
        ),
        "biometric_attestation_digest": deepcopy(
            source.get("biometric_attestation_digest")
        ),
        "identity_jurisdictions": deepcopy(
            source.get("identity_jurisdictions")
        ),
        "identity_access_grants": deepcopy(
            source.get("identity_access_grants")
        ),
        "participant_id": deepcopy(source.get("participant_id")),
        "stakeholder_class": deepcopy(source.get("stakeholder_class")),
        "participant_role": deepcopy(source.get("participant_role")),
        "participant_mandate_id": deepcopy(
            source.get("participant_mandate_id")
        ),
        "impersonation_session_id": deepcopy(
            source.get("impersonation_session_id")
        ),
        "impersonation_audience": deepcopy(
            source.get("impersonation_audience")
        ),
        "impersonation_challenge": deepcopy(
            source.get("impersonation_challenge")
        ),
        "subject_id": deepcopy(source.get("subject_id")),
        "session_id": deepcopy(source.get("session_id")),
        "service_id": deepcopy(source.get("service_id")),
        "request_nonce": deepcopy(source.get("request_nonce")),

        # Foundational baseline control outputs
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

        # Collective
        "collective_signals": {},
        "collective_signal_status": "unattached",

        # Safety / consequentiality
        "safety_profile": deepcopy(
            source.get(
                "safety_profile",
                {
                    "human_safety": 0,
                    "irreversibility": 0,
                    "cascading_impact": 0,
                    "financial_operational": 0,
                    "computed_tier": None,
                },
            )
        ),
        "corroboration_required": None,
        "corroboration_met": False,

        # AP-ACF classification control inputs
        "ap_acf_class": None,
        "ap_acf_subclass": None,
        "requested_autonomy_level": deepcopy(
            source.get("requested_autonomy_level")
        ),
        "requested_system_mode": deepcopy(source.get("requested_system_mode")),
        "autonomy_ceiling": deepcopy(source.get("autonomy_ceiling")),
        "operational_environment": deepcopy(
            source.get("operational_environment")
        ),
        "public_exposure": deepcopy(source.get("public_exposure")),
        "operational_scope": deepcopy(source.get("operational_scope")),
        "environment_modifiers": deepcopy(source.get("environment_modifiers")),
        "deployment_restrictions": deepcopy(
            source.get("deployment_restrictions")
        ),
        "deployment_scope": deepcopy(source.get("deployment_scope")),

        # Root of Trust / Authority First
        "authority_first_result": "",
        "authority_first_reason": "",

        # Procedural truth
        "procedural_truth_result": "",

        # Classification
        "classification_result": "",
        "classification_reason": "",

        # Licensing
        "license_tier": deepcopy(source.get("license_tier")),
        "execution_rights": deepcopy(source.get("execution_rights")),
        "license_profile": deepcopy(source.get("license_profile")),
        "licensing_result": "",
        "licensing_reason": "",
        "filed_licence_trace": [],
        "filed_licence_record": {},
        "filed_licence_result": "",
        "filed_licence_reason": "",
        "filed_licence_digest": None,
        "licence_id": "",
        "licence_invalidation_status": "",
        "licence_execution_disabled": False,
        "licence_invalidation_trace": [],
        "licence_invalidation_digest": None,
        "licence_revocation_status": "",
        "licence_revocation_sequence": None,

        # Authenticated Sovereign Knowledge Graph authority substrate
        "skg_authority_trace": [],
        "skg_authority_record": {},
        "skg_authority_digest": None,
        "skg_authority_trace_digest": None,
        "skg_authority_result": "",
        "skg_authority_reason": "",
        "skg_authority_granted": False,
        "skg_execution_authority_granted": False,
        "skg_downstream_override_permitted": False,

        # P0 authority provenance (non-authorising eligibility evidence)
        "authority_provenance_trace": [],
        "authority_provenance_record": {},
        "authority_provenance_digest": None,
        "authority_provenance_trace_digest": None,
        "authority_provenance_result": "",
        "authority_provenance_reason": "",
        "authority_provenance_trust_context_digest": None,
        "authority_provenance_clock_receipt_digest": None,
        "authority_provenance_registry_head_digest": None,
        "authority_provenance_authority_granted": False,
        "authority_provenance_licence_granted": False,
        "authority_provenance_execution_authority_granted": False,
        "authority_provenance_effect_authority_granted": False,
        "authority_provenance_pipeline_bypass_permitted": False,
        "authority_provenance_downstream_override_permitted": False,
        "governance_policy_record": {},
        "governance_policy_digest": None,

        # Governance
        "governance_result": "",
        "governance_reason": "",
        "governance_feedback": {},

        # Filed mandatory governance frameworks (Block 7)
        "filed_framework_trace": [],
        "filed_framework_results": {},
        "filed_framework_result": "",
        "filed_framework_reason": "",
        "filed_framework_digest": None,
        "gala_attestation": {},

        # Filed lifecycle-governance components (implementation-defined V2)
        "filed_lifecycle_trace": [],
        "filed_lifecycle_results": {},
        "filed_lifecycle_record": {},
        "filed_lifecycle_result": "",
        "filed_lifecycle_reason": "",
        "filed_lifecycle_digest": None,

        # Filed governance-integrity functions (implementation-defined V2)
        "filed_governance_integrity_revocation_binding": {},
        "filed_governance_integrity_trace": [],
        "filed_governance_integrity_results": {},
        "filed_governance_integrity_record": {},
        "filed_governance_integrity_result": "",
        "filed_governance_integrity_reason": "",
        "filed_governance_integrity_digest": None,
        "filed_governance_integrity_authority_granted": False,
        "filed_governance_integrity_licence_granted": False,
        "filed_governance_integrity_execution_authority_granted": False,
        "filed_governance_integrity_effect_granted": False,
        "filed_governance_integrity_bypass_permitted": False,

        # Domain / Aurion / Execution
        "domain_result": "",
        "aurion15_result": "",
        "candidate_attempt_count": 0,
        "current_candidate": {},
        "execution_result": "",
        "execution_reason": "",
        "decision": "",

        # Controlled local point-of-use effect boundary
        "effect_adapter_id": "",
        "effect_id": "",
        "effect_permit": {},
        "effect_receipt": {},
        "effect_result": "",
        "effect_trace": [],

        # Tokens / verification
        "tokens": {},
        "token_stack_valid": False,
        "token_verification_failures": [],
        "token_trace": [],

        # Hashing / integrity
        "hash_chain": [],
        "state_hash": "",

        # Audit
        "audit_trace": [],
        "audit_record": {},
        "audit_hash": "",
        "audit_ledger": [],

        # GRC / re-entry control
        "last_denied_fingerprint": source.get("last_denied_fingerprint"),

        # Optional threshold flags
        "autonomy_boundary_required": bool(source.get("autonomy_boundary_required", False)),
        "escalation_threshold_required": bool(source.get("escalation_threshold_required", False)),

        # Config snapshots
        "security_config": build_security_config(),
        "pipeline_config": build_pipeline_config(),
    }

    # Carry through optional pre-existing fields if present
    optional_passthrough_fields = [
        # Caller-supplied anchors and attestations are deliberately retained
        # only as submitted shadow evidence and never become active authority.
        "output",
        "truth_anchor",
        "previous_truth_anchor",
        "truth_continuity",
        "truth_expiry",
        "truth_revocation",
        "revoked_truth_anchors",
        "authority_link_signal",
        "jurisdiction_signal",
        "dependency_signal",
        "policy_conflict_signal",
        "operational_context_signal",
        "precedence_signal",
        "intent_signal",
        "risk_potential_signal",
        "authority",
        "authority_chain",
        "baseline_jurisdiction",
        "baseline_policy",
        "constraints",
        "country",
        "decision_token",
        "decision_token_claims",
        "digital_twin",
        "execution_request",
        "override",
        "precedence",
        "region",
        "revocation_list",
    ]

    for field in optional_passthrough_fields:
        if field in source:
            state[field] = deepcopy(source[field])

    # Ensure locked safety structure exists
    state = ensure_safety_profile(state)

    return state
