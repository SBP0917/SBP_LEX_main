from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

from sbp_lex.aurion15.core import contracts as aurion_contracts
from sbp_lex.aurion15.runtime import engine_graph
from sbp_lex.baseline import (
    application_startup,
    foundational_baseline,
    request_controls,
)
from sbp_lex.classification import router as classification_router
from sbp_lex.compliance import australian_minor_access
from sbp_lex.composition import ciga_composition
from sbp_lex.config import security_config, thresholds
from sbp_lex.exchange import durable_replay, segmented_exchange
from sbp_lex.governance import (
    authority_provenance,
    filed_frameworks,
    filed_governance_integrity,
    filed_lifecycle,
    skg_authority,
    three_p_doctrine,
)
from sbp_lex.identity import durable_boundaries, impersonation_protection
from sbp_lex.interface import authority_boundary
from sbp_lex.legacy_admission import runtime as legacy_runtime
from sbp_lex.local_trust import constants as local_constants
from sbp_lex.local_trust import repository_guard
from sbp_lex.provenance import digital_provenance
from sbp_lex.rules import rule_artifact_register
from sbp_lex.security import (
    application_integrity,
    authority_trust,
    hybrid_signature,
    token_stack,
)
from sbp_lex.supply_chain import python_inventory
from sbp_ptde import constants as ptde_constants


@pytest.mark.parametrize(
    ("policy", "key", "hostile_value"),
    (
        (local_constants.NO_AUTHORITY, "authority_granted", True),
        (local_constants.DETACHED_BOUNDARY, "runtime_detached", False),
        (local_constants.DEPLOYMENT_LIMITS, "hardware_key_custody", "PROVEN"),
        (
            local_constants.PYTHON_DEPENDENCY_TARGET_ENVIRONMENT,
            "python_version",
            "0.0.0",
        ),
        (repository_guard.NO_AUTHORITY, "release_admitted", True),
        (repository_guard.CHANGE_CONTROL_POLICY, "authority_granted", True),
        (segmented_exchange.NO_AUTHORIZATION_EFFECT, "access_granted", True),
        (segmented_exchange.EXTERNAL_BOUNDARIES, "transport", "PROVEN"),
        (digital_provenance.NO_AUTHORIZATION_EFFECT, "licence_granted", True),
        (
            digital_provenance.PROVENANCE_NODE_SIGNER_ROLES,
            "runtime_measurement",
            "hostile",
        ),
        (impersonation_protection.NO_AUTHORIZATION_EFFECT, "access_granted", True),
        (
            impersonation_protection.DEPLOYMENT_DEPENDENCIES,
            "signing_key_custody",
            "PROVEN",
        ),
        (
            impersonation_protection.IMPERSONATION_SIGNING_PURPOSES,
            impersonation_protection.POSSESSION_PROOF_SCHEMA,
            "hostile",
        ),
        (python_inventory.GOVERNED_PYTHON_ENVIRONMENT, "python_version", "0"),
        (filed_frameworks.FILED_FRAMEWORK_STAGES, filed_frameworks.PTODF, "hostile"),
        (durable_replay._EXPECTED_SCHEMA, "metadata", ()),
        (
            filed_lifecycle.FILED_LIFECYCLE_STAGES,
            filed_lifecycle.AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION,
            "hostile",
        ),
        (
            filed_governance_integrity.FILED_GOVERNANCE_INTEGRITY_STAGES,
            filed_governance_integrity.BLACK_SWAN_DETECTION_ARCHITECTURE,
            "hostile",
        ),
        (three_p_doctrine.THREE_P_DEFINITIONS, "P1", {}),
        (three_p_doctrine.THREE_P_DEFINITIONS["P1"], "name", "hostile"),
        (
            aurion_contracts.ENGINE_CONTRACTS,
            "authority_resolution_engine",
            None,
        ),
        (
            application_startup.APPLICATION_STARTUP_DEPLOYMENT_DEPENDENCIES,
            "tpm_measurement",
            "PROVEN",
        ),
        (
            classification_router.AP_ACF_EXACT_CLASS_5_CEILINGS,
            "CLASS_5",
            101,
        ),
        (legacy_runtime._ACTIVE_OUTCOMES, "decision", {}),
        (thresholds.TIER_ORDER, thresholds.TOP_TIER, 0),
        (thresholds.FINANCIAL_THRESHOLDS, "medium_max", 0),
        (ptde_constants.NO_AUTHORITY, "authority", True),
        (ptde_constants.ASSURANCE_LIMITS, "production_admitted", True),
        (
            cast(Mapping[str, Any], ptde_constants.ASSURANCE_LIMITS["resource_maxima"]),
            "stream_byte_count",
            2**63,
        ),
        (
            application_integrity.NO_AUTHORIZATION_EFFECT,
            "effect_authority_granted",
            True,
        ),
        (
            application_integrity.ASSURANCE_LIMITS,
            "tpm_measurement",
            "PROVEN",
        ),
    ),
)
def test_security_policy_globals_cannot_be_mutated_in_process(
    policy: Mapping[str, Any],
    key: str,
    hostile_value: Any,
) -> None:
    original = policy[key]

    with pytest.raises(TypeError):
        cast(dict[str, Any], policy)[key] = hostile_value

    assert policy[key] == original


@pytest.mark.parametrize(
    "policy",
    (
        token_stack._TOKEN_ISSUANCE_CONTRACTS,
        token_stack._FRAMEWORK_TOKEN_BINDINGS,
        token_stack._LIFECYCLE_TOKEN_BINDINGS,
        token_stack._GOVERNANCE_INTEGRITY_TOKEN_BINDINGS,
    ),
)
def test_token_contract_maps_cannot_be_mutated(policy: Mapping[str, Any]) -> None:
    with pytest.raises(TypeError):
        cast(dict[str, Any], policy)["hostile"] = ("hostile", "hostile")


@pytest.mark.parametrize(
    "policy",
    (
        token_stack.REQUIRED_CORE_TOKENS,
        token_stack.CONDITIONAL_THRESHOLD_TOKENS,
        security_config.REQUIRED_CORE_TOKENS,
        security_config.CONDITIONAL_THRESHOLD_TOKENS,
    ),
)
def test_required_token_sequence_cannot_be_reduced(policy: tuple[str, ...]) -> None:
    original = policy[0]
    with pytest.raises(TypeError):
        cast(list[str], policy)[0] = "hostile"
    assert policy[0] == original


def test_security_config_builders_emit_detached_token_lists() -> None:
    first = security_config.build_token_requirements()
    first["required_core_tokens"].clear()
    first["conditional_threshold_tokens"].clear()

    second = security_config.build_token_requirements()
    assert second["required_core_tokens"] == list(
        security_config.REQUIRED_CORE_TOKENS
    )
    assert second["conditional_threshold_tokens"] == list(
        security_config.CONDITIONAL_THRESHOLD_TOKENS
    )


@pytest.mark.parametrize(
    "policy",
    (
        application_integrity._MANIFEST_PAYLOAD_FIELDS,
        application_integrity._RECEIPT_PAYLOAD_FIELDS,
        token_stack._FOUNDATIONAL_TOKEN_BODY_FIELDS,
        token_stack._GOVERNANCE_INTEGRITY_RECORD_FIELDS,
        hybrid_signature._DESCRIPTOR_FIELDS,
        hybrid_signature._CONTEXT_FIELDS,
        hybrid_signature._PROTECTED_FIELDS,
        authority_trust._SIGNATURE_FIELDS,
        australian_minor_access._OWNER_KEYS,
        segmented_exchange._SIGNED_ENVELOPE_FIELDS,
        digital_provenance._GRAPH_FIELDS,
        digital_provenance._VERIFICATION_RECEIPT_FIELDS,
        impersonation_protection._CONTEXT_PAYLOAD_FIELDS,
        impersonation_protection._RECORD_FIELDS,
        python_inventory._LOCK_FIELDS,
        filed_frameworks._COMMON_SOURCE_FIELDS,
        durable_boundaries._REPLAY_CLAIM_FIELDS,
        authority_provenance._SOURCE_FIELDS,
        filed_lifecycle._SOURCE_FIELDS,
        filed_governance_integrity._SOURCE_FIELDS,
        skg_authority._SOURCE_FIELDS,
        three_p_doctrine._EVALUATION_FIELDS,
        foundational_baseline._RECORD_FIELDS,
        request_controls._PROVENANCE_PAYLOAD_FIELDS,
        ciga_composition._SOURCE_FIELDS,
        authority_boundary._SOURCE_FIELDS,
        rule_artifact_register._SOURCE_FIELDS,
        engine_graph._ALLOW_ACTIONS,
    ),
)
def test_signed_schema_field_sets_cannot_be_mutated(policy: frozenset[object]) -> None:
    with pytest.raises(AttributeError):
        cast(set[object], policy).add("hostile")
