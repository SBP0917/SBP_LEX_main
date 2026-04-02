from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class EthicalConstraintEngine(AurionEngine):
    name = "ethical_constraint_engine"
    stage = 3
    depends_on = [
        "constraint_alignment_engine",
        "legal_conflict_resolution_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        constraint_alignment_status = state.get("constraint_alignment_status")
        legal_conflict_status = state.get("legal_conflict_resolution_status")
        boundary_status = state.get("boundary_status")
        procedural_truth = state.get("procedural_truth_status")

        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        ethical_constraint_score = payload.get(
            "ethical_constraint_score",
            current_candidate.get("ethical_constraint_score", 0.0),
        )

        ethical_violation_flags = payload.get(
            "ethical_violation_flags",
            current_candidate.get("ethical_violation_flags", []),
        )

        try:
            ethical_constraint_score = float(ethical_constraint_score)
        except (TypeError, ValueError):
            ethical_constraint_score = 0.0

        if not isinstance(ethical_violation_flags, list):
            ethical_violation_flags = []

        ethically_aligned = (
            constraint_alignment_status == "aligned"
            and legal_conflict_status == "resolved"
            and boundary_status not in ["violation", "breach", "blocked"]
            and procedural_truth in ["true", "conclusive", "general_pass"]
            and ethical_constraint_score >= 0.7
            and len(ethical_violation_flags) == 0
        )

        state["ethical_constraint_status"] = (
            "aligned" if ethically_aligned else "misaligned"
        )
        state["ethical_constraint_score"] = ethical_constraint_score
        state["ethical_violation_flags"] = ethical_violation_flags

        if ethically_aligned:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(EthicalConstraintEngine())
