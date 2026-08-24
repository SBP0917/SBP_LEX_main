from __future__ import annotations

from sbp_lex.compliance.australian_minor_access import (
    AUSTRALIAN_MINOR_ACCESS_STAGE,
)
from sbp_lex.config.pipeline_config import (
    APPLICATION_INTEGRITY_STARTUP_STAGE,
    AUTHORITY_PROVENANCE_STAGE,
    AUTHORITY_BOUNDARY_ADMISSION_STAGE,
    DIGITAL_PROVENANCE_STAGE,
    EXECUTION_GATE_REQUIRED_CHECKS,
    FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
    FOUNDATIONAL_BASELINE_ORDER,
    FOUNDATIONAL_BASELINE_ORDER_AUTHORITY,
    HASH_CHAIN_REQUIRED_STAGES,
    PIPELINE_ORDER,
    STARTUP_REQUIRED_STAGES,
    build_pipeline_config,
)
from sbp_lex.identity.impersonation_protection import (
    IMPERSONATION_PROTECTION_STAGE,
)
from sbp_lex.identity.sovereign_identity import IDENTITY_ADMISSION_STAGE
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
)


EXISTING_PIPELINE_ORDER = [
    "entry",
    "state_construction",
    "collective_attach",
    "root_of_trust",
    "filed_licence:root_binding",
    "skg_authority:constitutional_authority_substrate",
    "procedural_truth",
    "filed_framework:ptodf",
    "classification",
    "filed_licence:validation",
    "licensing",
    "filed_framework:aj_saaf",
    "governance:determination",
    "filed_framework:gala",
    "filed_framework:abegf",
    "filed_lifecycle:ai_obsolescence_lifecycle_supersession",
    "filed_lifecycle:civilisational_successor_intelligence_transition",
    "filed_lifecycle:structured_post_ai_era_continuity",
    *[
        FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
        for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
    ],
    "governance",
    "grc",
    "domain_wrap",
    "aurion_candidate",
    "aurion_runtime",
    "filed_licence:revalidation",
    "execution_gate",
    "audit",
]

EXISTING_HASH_CHAIN_ORDER = [
    stage for stage in EXISTING_PIPELINE_ORDER if stage not in {"entry", "grc"}
]

FOUNDATIONAL_GATE_CHECKS = [
    "application_integrity_current_and_valid",
    "digital_provenance_authenticated",
    "sovereign_identity_current_and_valid",
    "authority_boundary_current_and_valid",
    "impersonation_protection_current_and_valid",
    "australian_minor_access_current_and_valid",
    "foundational_request_controls_current_and_valid",
    "foundational_baseline_digest_current_and_valid",
]
AUTHORITY_PROVENANCE_GATE_CHECK = "authority_provenance_current_and_valid"

EXISTING_GATE_CHECKS = [
    "hash_chain_presence_and_integrity",
    "three_p_core_constitutional_constraint",
    "skg_authority_complete_and_valid",
    "filed_four_tier_licence_current_and_valid",
    "filed_frameworks_complete_and_valid",
    "filed_lifecycle_complete_and_valid",
    "filed_governance_integrity_complete_and_valid",
    "governance_allow",
    "procedural_truth_pass",
    "corroboration_threshold_satisfied",
    "domain_pass",
    "aurion_pass",
    "required_tokens_present",
    "token_digest_valid",
    "token_signature_valid",
    "request_fingerprint_match",
    "state_hash_match",
    "tier_consistency",
    "execution_boundary_clear",
    "execution_attestation_clear",
    "collective_signal_consistency",
]


def test_foundational_constants_and_exact_order() -> None:
    assert APPLICATION_INTEGRITY_STARTUP_STAGE == "application_integrity:startup"
    assert DIGITAL_PROVENANCE_STAGE == "digital_provenance:lineage_authentication"
    assert AUTHORITY_BOUNDARY_ADMISSION_STAGE == "authority_boundary:participant_request"
    assert FOUNDATIONAL_BASELINE_AGGREGATE_STAGE == "foundational_baseline"
    assert FOUNDATIONAL_BASELINE_ORDER_AUTHORITY == (
        "IMPLEMENTATION_DEFINED_V2_ORDER_NOT_EXPRESSLY_FILED_RUNTIME_ORDER"
    )
    assert STARTUP_REQUIRED_STAGES == [APPLICATION_INTEGRITY_STARTUP_STAGE]
    assert FOUNDATIONAL_BASELINE_ORDER == [
        DIGITAL_PROVENANCE_STAGE,
        IDENTITY_ADMISSION_STAGE,
        AUTHORITY_BOUNDARY_ADMISSION_STAGE,
        IMPERSONATION_PROTECTION_STAGE,
        AUSTRALIAN_MINOR_ACCESS_STAGE,
    ]


def test_pipeline_places_startup_and_request_baseline_exactly() -> None:
    assert PIPELINE_ORDER[:11] == [
        APPLICATION_INTEGRITY_STARTUP_STAGE,
        "entry",
        "state_construction",
        *FOUNDATIONAL_BASELINE_ORDER,
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        AUTHORITY_PROVENANCE_STAGE,
        "collective_attach",
    ]
    assert len(PIPELINE_ORDER) == len(set(PIPELINE_ORDER))
    assert len(FOUNDATIONAL_BASELINE_ORDER) == len(set(FOUNDATIONAL_BASELINE_ORDER))


def test_hash_chain_places_startup_and_six_request_stages() -> None:
    assert HASH_CHAIN_REQUIRED_STAGES[:10] == [
        APPLICATION_INTEGRITY_STARTUP_STAGE,
        "state_construction",
        *FOUNDATIONAL_BASELINE_ORDER,
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        AUTHORITY_PROVENANCE_STAGE,
        "collective_attach",
    ]
    assert len(HASH_CHAIN_REQUIRED_STAGES) == len(set(HASH_CHAIN_REQUIRED_STAGES))


def test_existing_relative_orders_are_unchanged() -> None:
    new_pipeline_stages = {
        APPLICATION_INTEGRITY_STARTUP_STAGE,
        *FOUNDATIONAL_BASELINE_ORDER,
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        AUTHORITY_PROVENANCE_STAGE,
    }
    assert [stage for stage in PIPELINE_ORDER if stage not in new_pipeline_stages] == (
        EXISTING_PIPELINE_ORDER
    )
    assert [
        stage for stage in HASH_CHAIN_REQUIRED_STAGES
        if stage not in new_pipeline_stages
    ] == EXISTING_HASH_CHAIN_ORDER
    assert [
        check for check in EXECUTION_GATE_REQUIRED_CHECKS
        if check not in (
            *FOUNDATIONAL_GATE_CHECKS,
            AUTHORITY_PROVENANCE_GATE_CHECK,
        )
    ] == EXISTING_GATE_CHECKS


def test_execution_gate_foundational_checks_precede_governance_checks() -> None:
    assert EXECUTION_GATE_REQUIRED_CHECKS == [
        EXISTING_GATE_CHECKS[0],
        *FOUNDATIONAL_GATE_CHECKS,
        AUTHORITY_PROVENANCE_GATE_CHECK,
        *EXISTING_GATE_CHECKS[1:],
    ]
    assert len(EXECUTION_GATE_REQUIRED_CHECKS) == len(
        set(EXECUTION_GATE_REQUIRED_CHECKS)
    )


def test_pipeline_config_exposes_independent_foundational_copies() -> None:
    first = build_pipeline_config()
    second = build_pipeline_config()
    structure = first["structure"]

    assert structure["startup_required_stages"] == STARTUP_REQUIRED_STAGES
    assert structure["foundational_baseline_order"] == FOUNDATIONAL_BASELINE_ORDER
    assert structure["foundational_baseline_order_authority"] == (
        FOUNDATIONAL_BASELINE_ORDER_AUTHORITY
    )
    assert structure["foundational_baseline_aggregate_stage"] == (
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
    )
    assert structure["order"] == PIPELINE_ORDER
    assert structure["hash_chain_required_stages"] == HASH_CHAIN_REQUIRED_STAGES

    structure["startup_required_stages"].append("changed")
    structure["foundational_baseline_order"].append("changed")
    structure["order"].append("changed")
    first["execution_gate"]["required_checks"].append("changed")

    assert STARTUP_REQUIRED_STAGES == [APPLICATION_INTEGRITY_STARTUP_STAGE]
    assert second["structure"]["startup_required_stages"] == STARTUP_REQUIRED_STAGES
    assert second["structure"]["foundational_baseline_order"] == (
        FOUNDATIONAL_BASELINE_ORDER
    )
    assert second["structure"]["order"] == PIPELINE_ORDER
    assert second["execution_gate"]["required_checks"] == (
        EXECUTION_GATE_REQUIRED_CHECKS
    )
