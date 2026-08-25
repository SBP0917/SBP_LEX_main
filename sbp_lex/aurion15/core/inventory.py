"""Non-authorising source inventory for the current cognitive engine layers.

This module records what the repository can prove from its current source.  It
does not register or execute an engine, supply any missing filed name, or grant
authority, licence, execution, effect, or pipeline-bypass capability.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Final, Mapping, NoReturn


COGNITIVE_ENGINE_INVENTORY_SCHEMA_VERSION: Final = (
    "sbp.v2.cognitive-engine-inventory/1"
)
COGNITIVE_ENGINE_INVENTORY_STATUS: Final = (
    "IMPLEMENTATION_DEFINED_V2_SOURCE_INVENTORY"
)
PROVISIONAL_CURRENT: Final = "PROVISIONAL_CURRENT"
AUTHORITATIVE_SOURCE_UNAVAILABLE: Final = "AUTHORITATIVE_SOURCE_UNAVAILABLE"
NON_COUNTING: Final = "NON_COUNTING"

AURION_LAYER_ID: Final = "AURION_15"
CKC_LAYER_ID: Final = "CKC"
NGK_LAYER_ID: Final = "NGK"
COGNITIVE_LAYER_ORDER: Final = (
    AURION_LAYER_ID,
    CKC_LAYER_ID,
    NGK_LAYER_ID,
)

AURION_FILED_COUNT: Final = 38
AURION_CURRENT_COUNT: Final = 31
AURION_UNAVAILABLE_NAME_COUNT: Final = 7
CKC_FILED_COUNT: Final = 26
NGK_FILED_COUNT: Final = 32


class CognitiveInventoryError(ValueError):
    """Raised when an inventory differs from the source-locked record."""


@dataclass(frozen=True, slots=True)
class ProvisionalEngine:
    canonical_name: str
    module: str
    class_name: str
    stage: int
    dependencies: tuple[str, ...]

    def as_record(self) -> dict[str, Any]:
        return {
            "canonical_name": self.canonical_name,
            "module": self.module,
            "class_name": self.class_name,
            "implementation_type": "AURION_ENGINE_CLASS",
            "status": PROVISIONAL_CURRENT,
            "stage": self.stage,
            "dependencies": list(self.dependencies),
            "counted": True,
        }


def _engine(
    canonical_name: str,
    module: str,
    class_name: str,
    stage: int,
    *dependencies: str,
) -> ProvisionalEngine:
    return ProvisionalEngine(
        canonical_name=canonical_name,
        module=module,
        class_name=class_name,
        stage=stage,
        dependencies=dependencies,
    )


# Order is the exact current order in AURION_ENGINE_MODULES.  These entries are
# provisional current-source identities, not the unavailable filed inventory.
AURION_PROVISIONAL_ENGINES: Final[tuple[ProvisionalEngine, ...]] = (
    _engine(
        "procedural_validation_engine",
        "sbp_lex.governance.Procedural_validation_engine",
        "ProceduralValidationEngine",
        1,
    ),
    _engine(
        "authority_first_execution_engine",
        "sbp_lex.governance.authority_first_execution_engine",
        "AuthorityFirstExecutionEngine",
        6,
        "authority_resolution_engine",
        "execution_gate_engine",
        "governance_compliance_engine",
        "legal_conflict_resolution_engine",
        "decision_integrity_engine",
        "policy_simulation_engine",
    ),
    _engine(
        "authority_resolution_engine",
        "sbp_lex.governance.authority_resolution_engine",
        "AuthorityResolutionEngine",
        1,
        "jurisdiction_determination_engine",
    ),
    _engine(
        "autonomy_boundary_engine",
        "sbp_lex.governance.autonomy_boundary_engine",
        "AutonomyBoundaryEngine",
        1,
    ),
    _engine(
        "governance_compliance_engine",
        "sbp_lex.governance.governance_compliance_engine",
        "GovernanceComplianceEngine",
        3,
        "governance_routing_engine",
        "legitimacy_engine",
        "attestation_engine",
    ),
    _engine(
        "governance_routing_engine",
        "sbp_lex.governance.governance_routing_engine",
        "GovernanceRoutingEngine",
        3,
        "jurisdiction_engine",
        "authority_resolution_engine",
    ),
    _engine(
        "legal_conflict_resolution_engine",
        "sbp_lex.governance.legal_conflict_resolution_engine",
        "LegalConflictResolutionEngine",
        3,
        "jurisdiction_engine",
        "authority_resolution_engine",
        "governance_compliance_engine",
    ),
    _engine(
        "legitimacy_verification_engine",
        "sbp_lex.governance.legitimacy_engine",
        "LegitimacyVerificationEngine",
        1,
    ),
    _engine(
        "policy_simulation_engine",
        "sbp_lex.governance.policy_simulation_engine",
        "PolicySimulationEngine",
        6,
        "governance_compliance_engine",
        "resource_allocation_engine",
        "legal_conflict_resolution_engine",
        "ethical_constraint_engine",
    ),
    _engine(
        "cascading_failure_detection_engine",
        "sbp_lex.aurion15.runtime.cascading_failure_detection_engine",
        "CascadingFailureDetectionEngine",
        4,
        "predictive_risk_engine",
        "crisis_recognition_engine",
    ),
    _engine(
        "constraint_alignment_engine",
        "sbp_lex.aurion15.runtime.constraint_alignment_engine",
        "ConstraintAlignmentEngine",
        3,
        "autonomy_boundary_engine",
        "procedural_validation_engine",
        "legal_conflict_resolution_engine",
    ),
    _engine(
        "crisis_recognition_engine",
        "sbp_lex.aurion15.runtime.crisis_recognition_engine",
        "CrisisRecognitionEngine",
        4,
        "risk_detection_engine",
    ),
    _engine(
        "decision_integrity_engine",
        "sbp_lex.aurion15.runtime.decision_integrity_engine",
        "DecisionIntegrityEngine",
        2,
        "legitimacy_engine",
        "attestation_engine",
        "evidence_sufficiency_engine",
        "evidence_corroboration_engine",
        "output_discipline_engine",
        "procedural_truth_engine",
    ),
    _engine(
        "evidence_corroboration_engine",
        "sbp_lex.aurion15.runtime.evidence_corroboration_engine",
        "EvidenceCorroborationEngine",
        2,
        "evidence_sufficiency_engine",
        "information_integrity_engine",
    ),
    _engine(
        "evidence_sufficiency_engine",
        "sbp_lex.aurion15.runtime.evidence_sufficiency_engine",
        "EvidenceSufficiencyEngine",
        2,
        "procedural_validation_engine",
    ),
    _engine(
        "information_integrity_engine",
        "sbp_lex.aurion15.runtime.information_integrity_engine",
        "InformationIntegrityEngine",
        2,
        "procedural_validation_engine",
        "evidence_sufficiency_engine",
    ),
    _engine(
        "system_interdependency_engine",
        "sbp_lex.aurion15.runtime.system_interdependency_engine",
        "SystemInterdependencyEngine",
        4,
        "cascading_failure_detection_engine",
    ),
    _engine(
        "demographic_monitoring_engine",
        "sbp_lex.domains.demographic_monitoring_engine",
        "DemographicMonitoringEngine",
        5,
        "societal_stability_engine",
    ),
    _engine(
        "economic_signal_engine",
        "sbp_lex.domains.economic_signal_engine",
        "EconomicSignalEngine",
        5,
        "risk_detection_engine",
        "resource_allocation_engine",
    ),
    _engine(
        "ecological_constraint_engine",
        "sbp_lex.domains.ecological_constraint_engine",
        "EcologicalConstraintEngine",
        5,
        "risk_detection_engine",
        "demographic_monitoring_engine",
    ),
    _engine(
        "ethical_constraint_engine",
        "sbp_lex.domains.ethical_constraint_engine",
        "EthicalConstraintEngine",
        3,
        "constraint_alignment_engine",
        "legal_conflict_resolution_engine",
    ),
    _engine(
        "infrastructure_state_engine",
        "sbp_lex.domains.infrastructure_state_engine",
        "InfrastructureStateEngine",
        5,
        "risk_detection_engine",
        "operational_stability_engine",
    ),
    _engine(
        "institutional_integrity_engine",
        "sbp_lex.domains.institutional_integrity_engine",
        "InstitutionalIntegrityEngine",
        5,
        "legitimacy_engine",
        "attestation_engine",
        "governance_compliance_engine",
    ),
    _engine(
        "operational_stability_engine",
        "sbp_lex.domains.operational_stability_engine",
        "OperationalStabilityEngine",
        4,
        "risk_detection_engine",
        "system_interdependency_engine",
        "cascading_failure_detection_engine",
    ),
    _engine(
        "predictive_risk_engine",
        "sbp_lex.domains.predictive_risk_engine",
        "PredictiveRiskEngine",
        4,
        "risk_detection_engine",
        "crisis_recognition_engine",
    ),
    _engine(
        "resource_allocation_engine",
        "sbp_lex.domains.resource_allocation_engine",
        "ResourceAllocationEngine",
        6,
        "economic_signal_engine",
        "societal_stability_engine",
        "ecological_constraint_engine",
    ),
    _engine(
        "risk_detection_engine",
        "sbp_lex.domains.risk_detection_engine",
        "RiskDetectionEngine",
        4,
        "execution_gate_engine",
        "autonomy_boundary_engine",
        "escalation_engine",
    ),
    _engine(
        "security_state_engine",
        "sbp_lex.domains.security_state_engine",
        "SecurityStateEngine",
        4,
        "attestation_engine",
        "system_interdependency_engine",
        "cascading_failure_detection_engine",
    ),
    _engine(
        "societal_stability_engine",
        "sbp_lex.domains.societal_stability_engine",
        "SocietalStabilityEngine",
        5,
        "economic_signal_engine",
        "institutional_integrity_engine",
        "strategic_conflict_detection_engine",
    ),
    _engine(
        "strategic_conflict_detection_engine",
        "sbp_lex.domains.strategic_conflict_detection_engine",
        "StrategicConflictDetectionEngine",
        5,
        "jurisdiction_engine",
        "authority_resolution_engine",
        "risk_detection_engine",
        "institutional_integrity_engine",
    ),
    _engine(
        "technology_impact_engine",
        "sbp_lex.domains.technology_impact_engine",
        "TechnologyImpactEngine",
        5,
        "risk_detection_engine",
        "ecological_constraint_engine",
    ),
)

AURION_NON_COUNTING_ALIASES: Final[tuple[tuple[str, str], ...]] = (
    ("legitimacy_engine", "legitimacy_verification_engine"),
    ("jurisdiction_determination_engine", "jurisdiction_engine"),
)
AURION_NON_COUNTING_EXTERNAL_DEPENDENCIES: Final[tuple[str, ...]] = (
    "attestation_engine",
    "escalation_engine",
    "execution_gate_engine",
    "jurisdiction_engine",
    "output_discipline_engine",
    "procedural_truth_engine",
)


def _aurion_layer() -> dict[str, Any]:
    return {
        "layer_id": AURION_LAYER_ID,
        "status": PROVISIONAL_CURRENT,
        "filed_count": AURION_FILED_COUNT,
        "admitted_count": AURION_CURRENT_COUNT,
        "authoritative_complete_naming_list_available": False,
        "unavailable_name_count": AURION_UNAVAILABLE_NAME_COUNT,
        "unavailable_sets": ["SEVEN_CANONICAL_ENGINE_NAMES"],
        "engines": [engine.as_record() for engine in AURION_PROVISIONAL_ENGINES],
        "aliases": [
            {
                "alias": alias,
                "target": target,
                "status": NON_COUNTING,
                "counted": False,
            }
            for alias, target in AURION_NON_COUNTING_ALIASES
        ],
        "external_dependencies": [
            {
                "name": name,
                "implementation_type": "EXTERNAL_ENGINE_DEPENDENCY",
                "status": NON_COUNTING,
                "counted": False,
            }
            for name in AURION_NON_COUNTING_EXTERNAL_DEPENDENCIES
        ],
        "legacy_counting_policy": "EXCLUDED_SHADOW_ONLY",
        "authority_granted": False,
        "runtime_activation": False,
    }


def _unavailable_layer(
    *,
    layer_id: str,
    filed_count: int,
    horizon_years: tuple[int, int],
    unavailable_sets: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "layer_id": layer_id,
        "status": AUTHORITATIVE_SOURCE_UNAVAILABLE,
        "filed_count": filed_count,
        "admitted_count": 0,
        "authoritative_complete_naming_list_available": False,
        "unavailable_name_count": filed_count,
        "unavailable_sets": list(unavailable_sets),
        "horizon_years": {
            "minimum": horizon_years[0],
            "maximum": horizon_years[1],
        },
        "engines": [],
        "aliases": [],
        "external_dependencies": [],
        "legacy_counting_policy": "EXCLUDED_SHADOW_ONLY",
        "authority_granted": False,
        "runtime_activation": False,
    }


def build_cognitive_engine_inventory() -> dict[str, Any]:
    """Return a fresh JSON-compatible copy of the source-locked inventory."""

    manifest = {
        "schema_version": COGNITIVE_ENGINE_INVENTORY_SCHEMA_VERSION,
        "inventory_status": COGNITIVE_ENGINE_INVENTORY_STATUS,
        "authority_effect": "NONE",
        "runtime_activation": False,
        "layer_order": list(COGNITIVE_LAYER_ORDER),
        "layers": [
            _aurion_layer(),
            _unavailable_layer(
                layer_id=CKC_LAYER_ID,
                filed_count=CKC_FILED_COUNT,
                horizon_years=(25, 150),
                unavailable_sets=(
                    "ALL_26_CANONICAL_ENGINE_NAMES",
                    "FOUR_NAMED_LONG_HORIZON_FUNCTION_NAMES",
                ),
            ),
            _unavailable_layer(
                layer_id=NGK_LAYER_ID,
                filed_count=NGK_FILED_COUNT,
                horizon_years=(50, 500),
                unavailable_sets=(
                    "ALL_32_CANONICAL_ENGINE_NAMES",
                    "CONDITIONAL_TAG_AND_CLASSIFICATION_VOCABULARY",
                ),
            ),
        ],
    }
    return deepcopy(manifest)


def _fail(code: str) -> NoReturn:
    raise CognitiveInventoryError(code)


def validate_cognitive_engine_inventory(candidate: Mapping[str, Any]) -> None:
    """Reject any deviation from the current non-authorising source record."""

    expected = build_cognitive_engine_inventory()
    if type(candidate) is not dict:
        _fail("COGNITIVE_INVENTORY_NOT_EXACT_DICT")
    if set(candidate) != set(expected):
        _fail("COGNITIVE_INVENTORY_TOP_LEVEL_FIELDS_INVALID")
    for field in (
        "schema_version",
        "inventory_status",
        "authority_effect",
        "runtime_activation",
    ):
        if candidate.get(field) != expected[field]:
            _fail(f"COGNITIVE_INVENTORY_{field.upper()}_INVALID")

    layer_order = candidate.get("layer_order")
    layers = candidate.get("layers")
    if layer_order != list(COGNITIVE_LAYER_ORDER):
        _fail("COGNITIVE_LAYER_ORDER_INVALID")
    if type(layers) is not list or len(layers) != len(COGNITIVE_LAYER_ORDER):
        _fail("COGNITIVE_LAYER_SET_INVALID")
    observed_layer_ids = [
        layer.get("layer_id") if type(layer) is dict else None for layer in layers
    ]
    if len(observed_layer_ids) != len(set(observed_layer_ids)):
        _fail("COGNITIVE_LAYER_DUPLICATE")
    if observed_layer_ids != list(COGNITIVE_LAYER_ORDER):
        _fail("COGNITIVE_LAYER_IDENTITY_OR_ORDER_INVALID")

    for observed, canonical in zip(layers, expected["layers"], strict=True):
        if type(observed) is not dict:
            _fail(f"{canonical['layer_id']}_NOT_EXACT_DICT")
        if set(observed) != set(canonical):
            _fail(f"{canonical['layer_id']}_FIELDS_INVALID")
        for field in (
            "status",
            "filed_count",
            "admitted_count",
            "authoritative_complete_naming_list_available",
            "unavailable_name_count",
            "unavailable_sets",
            "legacy_counting_policy",
            "authority_granted",
            "runtime_activation",
        ):
            if observed.get(field) != canonical[field]:
                _fail(f"{canonical['layer_id']}_{field.upper()}_INVALID")

        engines = observed.get("engines")
        if type(engines) is not list:
            _fail(f"{canonical['layer_id']}_ENGINES_INVALID")
        names = [
            engine.get("canonical_name") if type(engine) is dict else None
            for engine in engines
        ]
        if len(names) != len(set(names)):
            _fail(f"{canonical['layer_id']}_ENGINE_DUPLICATE")
        expected_names = [engine["canonical_name"] for engine in canonical["engines"]]
        if names != expected_names:
            _fail(f"{canonical['layer_id']}_ENGINE_IDENTITY_OR_ORDER_INVALID")
        if engines != canonical["engines"]:
            _fail(f"{canonical['layer_id']}_ENGINE_CONTRACT_MISMATCH")
        if observed.get("admitted_count") != len(engines):
            _fail(f"{canonical['layer_id']}_ADMITTED_COUNT_MISMATCH")

        for collection in ("aliases", "external_dependencies"):
            if observed.get(collection) != canonical[collection]:
                _fail(f"{canonical['layer_id']}_{collection.upper()}_INVALID")
            if any(
                type(item) is not dict or item.get("counted") is not False
                for item in observed[collection]
            ):
                _fail(f"{canonical['layer_id']}_{collection.upper()}_COUNTED")

        if canonical["layer_id"] in {CKC_LAYER_ID, NGK_LAYER_ID}:
            if engines or observed["aliases"] or observed["external_dependencies"]:
                _fail(f"{canonical['layer_id']}_PLACEHOLDER_ENTRY_PROHIBITED")
            if observed.get("horizon_years") != canonical["horizon_years"]:
                _fail(f"{canonical['layer_id']}_HORIZON_INVALID")

    if candidate != expected:
        _fail("COGNITIVE_INVENTORY_UNRECOGNISED_TAMPER")


__all__ = [
    "AUTHORITATIVE_SOURCE_UNAVAILABLE",
    "AURION_CURRENT_COUNT",
    "AURION_FILED_COUNT",
    "AURION_LAYER_ID",
    "AURION_NON_COUNTING_ALIASES",
    "AURION_NON_COUNTING_EXTERNAL_DEPENDENCIES",
    "AURION_PROVISIONAL_ENGINES",
    "AURION_UNAVAILABLE_NAME_COUNT",
    "CKC_FILED_COUNT",
    "CKC_LAYER_ID",
    "COGNITIVE_ENGINE_INVENTORY_SCHEMA_VERSION",
    "COGNITIVE_ENGINE_INVENTORY_STATUS",
    "COGNITIVE_LAYER_ORDER",
    "CognitiveInventoryError",
    "NGK_FILED_COUNT",
    "NGK_LAYER_ID",
    "NON_COUNTING",
    "PROVISIONAL_CURRENT",
    "ProvisionalEngine",
    "build_cognitive_engine_inventory",
    "validate_cognitive_engine_inventory",
]
