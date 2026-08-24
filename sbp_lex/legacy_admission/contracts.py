from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal


LegacyRole = Literal["mandatory_veto", "corroboration", "shadow_only"]
LegacyKind = Literal[
    "engine_result_function",
    "state_function",
    "state_predicate",
    "domain_class",
    "authority_resolver",
    "controller",
    "quarantined_source",
]


@dataclass(frozen=True, slots=True)
class LegacyEngineContract:
    engine_id: str
    phase: str
    position: int
    module: str
    callable_name: str
    kind: LegacyKind
    reads: tuple[str, ...]
    role: LegacyRole
    output_contract: str
    isolated_outputs: tuple[str, ...]
    allowed_writes: tuple[str, ...]
    dependencies: tuple[str, ...]
    applicability: str
    comparison_adapter: str
    trigger_inputs: tuple[str, ...] = ()
    comparison_target: str | None = None
    deterministic: bool = True
    failure_policy: str = "record_only"
    promotion_candidate_role: LegacyRole | None = None
    promotion_evidence: tuple[str, ...] = ()
    source_path: str | None = None
    runnable: bool = True
    contract_version: str = "1.0.0"


def _engine(
    engine_id: str,
    phase: str,
    position: int,
    module: str,
    callable_name: str,
    reads: tuple[str, ...],
    *,
    promotion_candidate_role: LegacyRole | None = None,
    role: LegacyRole | None = None,
    trigger_inputs: tuple[str, ...] = (),
    comparison_target: str | None = None,
    deterministic: bool = True,
    kind: LegacyKind = "engine_result_function",
    output_contract: str | None = None,
    isolated_outputs: tuple[str, ...] | None = None,
    allowed_writes: tuple[str, ...] = (),
    dependencies: tuple[str, ...] = (),
    source_path: str | None = None,
    runnable: bool = True,
) -> LegacyEngineContract:
    if promotion_candidate_role is not None and role is not None:
        raise ValueError("LEGACY_PROMOTION_CANDIDATE_ROLE_DUPLICATED")
    if promotion_candidate_role is None and role not in {None, "shadow_only"}:
        promotion_candidate_role = role
    if output_contract is None:
        output_contract = {
            "engine_result_function": "EngineResult(ok:bool,detail:str,data:dict)",
            "state_function": "isolated_state_delta",
            "state_predicate": "bool_predicate",
            "domain_class": "isolated_candidate_action",
            "authority_resolver": "isolated_mapping",
            "controller": "not_admitted",
            "quarantined_source": "not_executable",
        }[kind]
    if isolated_outputs is None:
        isolated_outputs = {
            "engine_result_function": ("EngineResult.data",),
            "state_function": (),
            "state_predicate": ("predicate",),
            "domain_class": ("candidate_action",),
            "authority_resolver": ("authority_resolution",),
            "controller": (),
            "quarantined_source": (),
        }[kind]
    return LegacyEngineContract(
        engine_id=engine_id,
        phase=phase,
        position=position,
        module=module,
        callable_name=callable_name,
        kind=kind,
        reads=reads,
        role="shadow_only",
        output_contract=output_contract,
        isolated_outputs=isolated_outputs,
        allowed_writes=allowed_writes,
        dependencies=dependencies,
        applicability=(
            "trusted_trigger_inputs_present" if trigger_inputs else "always"
        ),
        comparison_adapter=(
            f"unverified:{engine_id}:{comparison_target}"
            if comparison_target
            else "unmapped"
        ),
        trigger_inputs=trigger_inputs,
        comparison_target=comparison_target,
        deterministic=deterministic,
        failure_policy="record_only",
        promotion_candidate_role=promotion_candidate_role,
        source_path=source_path,
        runnable=runnable,
    )


# Deterministic position is global and unique. Every artifact begins shadow-only;
# candidate roles are non-authoritative labels until separate promotion evidence
# is admitted. No contract below can grant ALLOW.
LEGACY_ENGINE_CONTRACTS: Final[tuple[LegacyEngineContract, ...]] = (
    _engine("collective.sovereign_knowledge_graph", "collective", 110, "sbp_lex.collective.sovereign_knowledge_graph_engine", "sovereign_knowledge_graph_engine", ("jurisdiction", "authority", "action"), role="corroboration", trigger_inputs=("legacy_authority_supplied",), comparison_target="authority_first_result"),
    _engine("collective.digital_twin_network", "collective", 120, "sbp_lex.collective.digital_twin_network_engine", "digital_twin_network_engine", ("jurisdiction", "digital_twin", "action"), role="corroboration", trigger_inputs=("digital_twin",), comparison_target="collective_signal_status"),
    _engine("collective.planetary_population_constraints", "collective", 130, "sbp_lex.collective.planetary_population_constraints_engine", "planetary_population_constraints_engine", ("constraints", "action"), role="mandatory_veto", trigger_inputs=("constraints",), comparison_target="authority_first_result"),
    _engine("collective.policy_validation", "collective", 140, "sbp_lex.collective.policy_validation_engine", "policy_validation_engine", ("policy", "action", "authority"), role="mandatory_veto", trigger_inputs=("policy",), comparison_target="governance_result"),
    _engine("collective.policy_drift_detection", "collective", 150, "sbp_lex.collective.policy_drift_detection_engine", "policy_drift_detection_engine", ("policy", "baseline_policy", "action"), role="corroboration", trigger_inputs=("baseline_policy",), comparison_target="governance_result"),
    _engine("collective.jurisdiction_drift", "collective", 160, "sbp_lex.collective.jurisdiction_drift_engine", "jurisdiction_drift_engine", ("jurisdiction", "baseline_jurisdiction", "action"), role="corroboration", trigger_inputs=("baseline_jurisdiction",), comparison_target="authority_first_result"),
    _engine("collective.sovereign_precedence_matrix", "collective", 170, "sbp_lex.collective.sovereign_precedence_matrix_engine", "sovereign_precedence_matrix_engine", ("jurisdiction", "authority", "action"), role="corroboration", trigger_inputs=("sovereign_precedence_available",), comparison_target="domain_result"),
    _engine("collective.conflict_detection", "collective", 180, "sbp_lex.collective.conflict_detection_engine", "conflict_detection_engine", ("jurisdiction", "authority", "precedence", "action"), role="corroboration", trigger_inputs=("precedence",), comparison_target="governance_result"),

    _engine("governance.authority_resolver", "authority", 210, "sbp_lex.governance.Authority_engine", "AuthorityEngine", ("context",), kind="authority_resolver", deterministic=False),
    _engine("governance.jurisdiction_determination", "authority", 220, "sbp_lex.governance.jurisdiction_engine", "jurisdiction_engine", ("country", "region", "action"), role="corroboration", trigger_inputs=("country",), comparison_target="authority_first_result"),
    _engine("governance.precedence", "authority", 230, "sbp_lex.governance.precedence_engine", "precedence_engine", ("authority", "action"), role="corroboration", trigger_inputs=("legacy_authority_supplied",), comparison_target="authority_first_result"),
    _engine("governance.authority_attestation", "authority", 240, "sbp_lex.governance.authority_attestation_engine", "authority_attestation_engine", ("authority_chain", "jurisdiction", "action", "evaluation_time"), trigger_inputs=("authority_chain",), deterministic=True),
    _engine("governance.indexed_attestation", "authority", 250, "sbp_lex.governance.indexed_attestation_engine", "indexed_attestation_engine", ("indexed_attestations", "output", "action", "evaluation_time"), role="mandatory_veto", trigger_inputs=("indexed_attestations",), comparison_target="authority_first_result"),
    _engine("governance.authority_confidence", "authority", 260, "sbp_lex.governance.authority_confidence_engine", "authority_confidence_engine", ("authority", "jurisdiction", "action"), role="corroboration", trigger_inputs=("legacy_authority_supplied",), comparison_target="authority_first_result"),
    _engine("governance.jurisdiction_verification_quarantined", "authority", 270, "", "", ("jurisdiction", "authority"), kind="quarantined_source", deterministic=False, source_path="sbp_lex/governance/jurisdiction_verification_engine.p", runnable=False),

    _engine("governance.authority_scope", "governance", 310, "sbp_lex.governance.authority_scope_engine", "authority_scope_engine", ("authority", "action"), trigger_inputs=("authorized_scope",), comparison_target="governance_result"),
    _engine("governance.authority_revocation", "governance", 320, "sbp_lex.governance.authority_revocation_engine", "authority_revocation_engine", ("authority", "decision_token", "revocation_list", "action"), role="mandatory_veto", trigger_inputs=("revocation_list",), comparison_target="governance_result"),
    _engine("governance.governance_state", "governance", 330, "sbp_lex.governance.governance_state_engine", "governance_state_engine", ("jurisdiction", "authority", "precedence", "policy", "anchors"), comparison_target="governance_result"),
    _engine("governance.governance_confidence", "governance", 340, "sbp_lex.governance.governance_confidence_engine", "governance_confidence_engine", ("jurisdiction", "authority", "anchors", "decision_token", "action"), role="corroboration", trigger_inputs=("decision_token",), comparison_target="governance_result"),
    _engine("governance.governance_integrity", "governance", 350, "sbp_lex.governance.governance_integrity_engine", "governance_integrity_engine", ("jurisdiction", "authority", "policy", "anchors", "decision_token", "action"), trigger_inputs=("decision_token",), comparison_target="governance_result"),
    _engine("governance.governance_audit", "governance", 360, "sbp_lex.governance.authority_chain_engine", "audit_engine", ("action", "authority", "jurisdiction", "precedence", "attestation", "anchor_validation", "evaluation_time"), trigger_inputs=("legacy_authority_supplied",)),
    _engine("governance.governance_immutability", "governance", 370, "sbp_lex.governance.governance_immutability_engine", "governance_immutability_engine", ("decision_token", "attestation", "audit_record", "evaluation_time"), trigger_inputs=("decision_token",)),
    _engine("governance.permanent_sovereign_cycle", "governance", 380, "sbp_lex.governance.permanent_sovereign_governance_cycle_engine", "permanent_sovereign_governance_cycle_engine", ("action", "jurisdiction", "authority", "anchors", "decision_token", "evaluation_time"), trigger_inputs=("decision_token",)),
    _engine("governance.supervisory_override", "governance", 390, "sbp_lex.governance.supervisory_override_engine", "supervisory_override_engine", ("override", "decision_token", "action"), trigger_inputs=("override",)),

    _engine("domain.legal", "domain", 410, "sbp_lex.domains.legal_domain", "LegalDomain", ("candidate", "jurisdiction", "authority"), kind="domain_class", comparison_target="domain_result"),
    _engine("domain.sovereign", "domain", 420, "sbp_lex.domains.sovereign_domain", "SovereignDomain", ("candidate", "authority", "jurisdiction"), kind="domain_class", comparison_target="domain_result"),
    _engine("domain.operational", "domain", 430, "sbp_lex.domains.operational_domain", "OperationalDomain", ("candidate", "action", "payload"), kind="domain_class", comparison_target="domain_result"),
    _engine("domain.risk", "domain", 440, "sbp_lex.domains.risk_domain", "RiskDomain", ("risk_score", "candidate"), kind="domain_class", comparison_target="domain_result"),

    _engine("candidate.generator", "candidate", 510, "sbp_lex.aurion15.candidate.candidate_generator", "generate_candidates", ("action", "payload"), kind="state_function", isolated_outputs=("candidate_pathways",), comparison_target="aurion15_result"),
    _engine("candidate.ranker", "candidate", 520, "sbp_lex.aurion15.candidate.candidate_ranker", "rank_candidates", ("candidate_pathways",), kind="state_function", isolated_outputs=("candidate_pathways",), comparison_target="aurion15_result"),
    _engine("candidate.runtime_constraints", "candidate", 530, "sbp_lex.aurion15.candidate.runtime_constraint_controller", "apply_runtime_constraints", ("candidate_pathways", "risk_score"), kind="state_function", isolated_outputs=("candidate_pathways",), comparison_target="aurion15_result"),
    _engine("candidate.selector", "candidate", 540, "sbp_lex.aurion15.candidate.candidate_selector", "select_candidate", ("candidate_pathways", "candidate_attempt_count"), kind="state_function", isolated_outputs=("current_candidate",), comparison_target="aurion15_result"),
    _engine("candidate.search_controller", "candidate", 550, "sbp_lex.aurion15.candidate.candidate_search_controller", "candidate_search_required", ("candidate_pathways", "candidate_attempt_count"), kind="state_predicate", comparison_target="aurion15_result"),
    _engine("candidate.loop_controller", "candidate", 560, "sbp_lex.aurion15.candidate.candidate_loop_controller", "CandidateLoopController", (), kind="controller", deterministic=False),

    _engine("runtime.decision_token", "pre_execution", 610, "sbp_lex.aurion15.runtime.decision_token_engine", "decision_token_engine", ("procedural_truth", "execution_gate"), comparison_target="execution_result"),
    _engine("runtime.decision_expiry", "pre_execution", 620, "sbp_lex.aurion15.runtime.decision_expiry_engine", "decision_expiry_engine", ("decision_token", "action", "evaluation_time"), role="mandatory_veto", trigger_inputs=("decision_token",), comparison_target="execution_result"),
    _engine("runtime.runtime_revalidation", "pre_execution", 630, "sbp_lex.aurion15.runtime.runtime_revalidation_engine", "runtime_revalidation_engine", ("procedural_truth", "decision_token_claims"), role="mandatory_veto", trigger_inputs=("decision_token_claims",), comparison_target="execution_result"),
    _engine("runtime.output_discipline", "pre_execution", 640, "sbp_lex.aurion15.runtime.output_discipline_engine", "output_discipline_engine", ("action", "output", "decision_token", "procedural_truth"), role="mandatory_veto", trigger_inputs=("decision_token", "output"), comparison_target="execution_result"),
    _engine("runtime.execution_boundary", "pre_execution", 650, "sbp_lex.aurion15.runtime.execution_boundary_engine", "execution_boundary_engine", ("action", "policy", "decision_token"), role="mandatory_veto", trigger_inputs=("decision_token", "allowed_scope"), comparison_target="execution_result"),
    _engine("runtime.non_bypass", "pre_execution", 660, "sbp_lex.governance.non_bypass_verification_engine", "non_bypass_verification_engine", ("decision_token", "execution_request", "action"), role="mandatory_veto", trigger_inputs=("execution_request",), comparison_target="execution_result"),
    _engine("runtime.execution_gate", "pre_execution", 670, "sbp_lex.execution.execution_gate_engine", "execution_gate_engine", ("procedural_truth", "payload", "action_class"), role="mandatory_veto", trigger_inputs=("procedural_truth",), comparison_target="execution_result"),
    _engine("runtime.execution_attestation", "pre_execution", 680, "sbp_lex.aurion15.runtime.execution_attestation_engine", "execution_attestation_engine", ("action", "authority_chain", "jurisdiction", "anchor_validation", "evaluation_time"), trigger_inputs=("authority_chain",)),
    _engine("runtime.escalation", "pre_execution", 690, "sbp_lex.aurion15.runtime.escalation_engine", "escalation_engine", ("conflict_detection", "precedence", "action", "authority"), role="corroboration", trigger_inputs=("conflict_detection", "precedence"), comparison_target="decision"),
    _engine("runtime.execution_trace_quarantined", "pre_execution", 695, "", "", ("action", "jurisdiction", "authority", "decision_token", "audit_record"), kind="quarantined_source", deterministic=False, source_path="sbp_lex/execution/execution_trace_engine.p", runnable=False),

    _engine("audit.legacy_audit", "audit", 710, "sbp_lex.audit.audit_engine", "audit_engine", ("action", "authority", "jurisdiction", "precedence", "attestation", "anchor_validation", "evaluation_time"), trigger_inputs=("legacy_authority_supplied",)),
)


def validate_legacy_contracts() -> None:
    ids = [contract.engine_id for contract in LEGACY_ENGINE_CONTRACTS]
    positions = [contract.position for contract in LEGACY_ENGINE_CONTRACTS]
    if len(ids) != len(set(ids)):
        raise RuntimeError("LEGACY_ENGINE_ID_COLLISION")
    if len(positions) != len(set(positions)):
        raise RuntimeError("LEGACY_ENGINE_POSITION_COLLISION")
    if positions != sorted(positions):
        raise RuntimeError("LEGACY_ENGINE_POSITION_ORDER_INVALID")
    for contract in LEGACY_ENGINE_CONTRACTS:
        if contract.role != "shadow_only":
            raise RuntimeError(f"LEGACY_ENGINE_NOT_INITIAL_SHADOW:{contract.engine_id}")
        if contract.failure_policy != "record_only":
            raise RuntimeError(f"LEGACY_SHADOW_HAS_AUTHORITY:{contract.engine_id}")
        if contract.allowed_writes:
            raise RuntimeError(f"LEGACY_SHADOW_CAN_WRITE:{contract.engine_id}")
        if not contract.output_contract:
            raise RuntimeError(f"LEGACY_OUTPUT_CONTRACT_MISSING:{contract.engine_id}")
        if contract.promotion_evidence:
            raise RuntimeError(f"LEGACY_UNADMITTED_PROMOTION_EVIDENCE:{contract.engine_id}")
        if contract.runnable and (not contract.module or not contract.callable_name):
            raise RuntimeError(f"LEGACY_RUNNABLE_TARGET_MISSING:{contract.engine_id}")
        if not contract.runnable and contract.kind != "quarantined_source":
            raise RuntimeError(f"LEGACY_NONRUNNABLE_NOT_QUARANTINED:{contract.engine_id}")
