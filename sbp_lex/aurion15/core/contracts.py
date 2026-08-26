from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final


@dataclass(frozen=True, slots=True)
class EngineContract:
    """Closed-world mutation contract for a class-based V2 engine."""

    writes: frozenset[str]
    pure: bool = True
    external_effects: bool = False


def _contract(*writes: str) -> EngineContract:
    return EngineContract(writes=frozenset(writes))


# These fields are deliberately explicit.  A new or changed engine cannot enter
# the runtime merely because it imported successfully; its mutation surface must
# be reviewed here and is enforced around every invocation.
ENGINE_CONTRACTS: Final = MappingProxyType({
    "authority_first_execution_engine": _contract(
        "aurion15_result",
        "authority_first_execution_context",
        "authority_first_execution_status",
        "candidate_action",
    ),
    "authority_resolution_engine": _contract(
        "aurion15_resolved_authority", "aurion_reason", "status"
    ),
    "autonomy_boundary_engine": _contract("aurion15_boundary_status", "status"),
    "cascading_failure_detection_engine": _contract(
        "candidate_action",
        "cascade_indicators",
        "cascade_score",
        "cascading_failure_status",
    ),
    "constraint_alignment_engine": _contract(
        "candidate_action", "constraint_alignment_score", "constraint_alignment_status"
    ),
    "crisis_recognition_engine": _contract(
        "candidate_action", "crisis_indicators", "crisis_recognition_status", "crisis_score"
    ),
    "decision_integrity_engine": _contract("candidate_action", "decision_integrity_status"),
    "demographic_monitoring_engine": _contract(
        "candidate_action",
        "demographic_monitoring_status",
        "demographic_shift_flags",
        "demographic_stability_score",
    ),
    "ecological_constraint_engine": _contract(
        "candidate_action",
        "ecological_constraint_score",
        "ecological_constraint_status",
        "ecological_violation_flags",
    ),
    "economic_signal_engine": _contract(
        "candidate_action", "economic_indicators", "economic_signal_score", "economic_signal_status"
    ),
    "ethical_constraint_engine": _contract(
        "candidate_action",
        "ethical_constraint_score",
        "ethical_constraint_status",
        "ethical_violation_flags",
    ),
    "evidence_corroboration_engine": _contract(
        "candidate_action", "corroboration_score", "corroboration_sources", "evidence_corroboration_status"
    ),
    "evidence_sufficiency_engine": _contract(
        "candidate_action",
        "evidence_count",
        "evidence_quality",
        "evidence_sources",
        "evidence_sufficiency_status",
    ),
    "governance_compliance_engine": _contract(
        "candidate_action", "governance_compliance_context", "governance_compliance_status"
    ),
    "governance_routing_engine": _contract(
        "candidate_action", "governance_route", "governance_routing_status"
    ),
    "information_integrity_engine": _contract(
        "candidate_action",
        "contradiction_count",
        "information_integrity_score",
        "information_integrity_status",
        "tamper_flags",
    ),
    "infrastructure_state_engine": _contract(
        "candidate_action", "infrastructure_events", "infrastructure_health_score", "infrastructure_state_status"
    ),
    "institutional_integrity_engine": _contract(
        "candidate_action",
        "institutional_corruption_flags",
        "institutional_integrity_score",
        "institutional_integrity_status",
    ),
    "legal_conflict_resolution_engine": _contract(
        "candidate_action", "legal_conflict_resolution_context", "legal_conflict_resolution_status"
    ),
    "legitimacy_verification_engine": _contract("aurion15_legitimacy_status", "status"),
    "operational_stability_engine": _contract(
        "candidate_action", "operational_disruptions", "operational_stability_score", "operational_stability_status"
    ),
    "policy_simulation_engine": _contract(
        "candidate_action", "policy_simulation_context", "policy_simulation_status"
    ),
    "predictive_risk_engine": _contract(
        "candidate_action", "predictive_risk_indicators", "predictive_risk_score", "predictive_risk_status"
    ),
    "procedural_validation_engine": _contract(
        "aurion15_procedural_truth_status", "candidate_result", "status"
    ),
    "resource_allocation_engine": _contract(
        "candidate_action", "resource_allocation_status", "resource_availability_score", "resource_constraints"
    ),
    "risk_detection_engine": _contract(
        "candidate_action", "risk_detection_status", "risk_level", "risk_score"
    ),
    "security_state_engine": _contract(
        "candidate_action", "security_flags", "security_state_score", "security_state_status"
    ),
    "societal_stability_engine": _contract(
        "candidate_action", "societal_disruption_flags", "societal_stability_score", "societal_stability_status"
    ),
    "strategic_conflict_detection_engine": _contract(
        "candidate_action",
        "strategic_conflict_detection_status",
        "strategic_conflict_flags",
        "strategic_conflict_score",
    ),
    "system_interdependency_engine": _contract(
        "candidate_action", "interdependency_links", "interdependency_score", "system_interdependency_status"
    ),
    "technology_impact_engine": _contract(
        "candidate_action", "technology_impact_flags", "technology_impact_score", "technology_impact_status"
    ),
})


KNOWN_CONVERGENCE_FIELDS: Final = MappingProxyType({
    "demographic_monitoring_engine": (
        "demographic_monitoring_status",
        "demographic_shift_flags",
        "demographic_stability_score",
    ),
    "ecological_constraint_engine": (
        "ecological_constraint_score",
        "ecological_constraint_status",
        "ecological_violation_flags",
    ),
    "economic_signal_engine": (
        "economic_indicators",
        "economic_signal_score",
        "economic_signal_status",
    ),
    "resource_allocation_engine": (
        "resource_allocation_status",
        "resource_availability_score",
        "resource_constraints",
    ),
    "societal_stability_engine": (
        "societal_disruption_flags",
        "societal_stability_score",
        "societal_stability_status",
    ),
})


def validate_engine_contracts(engine_names: set[str]) -> None:
    declared = set(ENGINE_CONTRACTS)
    missing = sorted(engine_names - declared)
    stale = sorted(declared - engine_names)
    if missing or stale:
        raise RuntimeError(
            f"ENGINE_CONTRACT_CLOSED_WORLD_MISMATCH:missing={missing}:stale={stale}"
        )
