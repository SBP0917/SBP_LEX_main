from __future__ import annotations

from importlib import import_module
from typing import Final, Tuple

from .registry import AurionRegistry, aurion_registry


AURION_ENGINE_MODULES: Final[Tuple[str, ...]] = (
    "sbp_lex.governance.Procedural_validation_engine",
    "sbp_lex.governance.authority_first_execution_engine",
    "sbp_lex.governance.authority_resolution_engine",
    "sbp_lex.governance.autonomy_boundary_engine",
    "sbp_lex.governance.governance_compliance_engine",
    "sbp_lex.governance.governance_routing_engine",
    "sbp_lex.governance.legal_conflict_resolution_engine",
    "sbp_lex.governance.legitimacy_engine",
    "sbp_lex.governance.policy_simulation_engine",
    "sbp_lex.aurion15.runtime.cascading_failure_detection_engine",
    "sbp_lex.aurion15.runtime.constraint_alignment_engine",
    "sbp_lex.aurion15.runtime.crisis_recognition_engine",
    "sbp_lex.aurion15.runtime.decision_integrity_engine",
    "sbp_lex.aurion15.runtime.evidence_corroboration_engine",
    "sbp_lex.aurion15.runtime.evidence_sufficiency_engine",
    "sbp_lex.aurion15.runtime.information_integrity_engine",
    "sbp_lex.aurion15.runtime.system_interdependency_engine",
    "sbp_lex.domains.demographic_monitoring_engine",
    "sbp_lex.domains.economic_signal_engine",
    "sbp_lex.domains.ecological_constraint_engine",
    "sbp_lex.domains.ethical_constraint_engine",
    "sbp_lex.domains.infrastructure_state_engine",
    "sbp_lex.domains.institutional_integrity_engine",
    "sbp_lex.domains.operational_stability_engine",
    "sbp_lex.domains.predictive_risk_engine",
    "sbp_lex.domains.resource_allocation_engine",
    "sbp_lex.domains.risk_detection_engine",
    "sbp_lex.domains.security_state_engine",
    "sbp_lex.domains.societal_stability_engine",
    "sbp_lex.domains.strategic_conflict_detection_engine",
    "sbp_lex.domains.technology_impact_engine",
)


EXTERNAL_ENGINE_DEPENDENCIES: Final[frozenset[str]] = frozenset(
    {
        "attestation_engine",
        "escalation_engine",
        "execution_gate_engine",
        "jurisdiction_engine",
        "output_discipline_engine",
        "procedural_truth_engine",
    }
)


def load_aurion_catalog() -> AurionRegistry:
    """Import every class-based Aurion engine into the shared registry."""
    for module_name in AURION_ENGINE_MODULES:
        import_module(module_name)

    aurion_registry.register_alias(
        "legitimacy_engine",
        "legitimacy_verification_engine",
    )
    aurion_registry.register_alias(
        "jurisdiction_determination_engine",
        "jurisdiction_engine",
    )
    return aurion_registry
