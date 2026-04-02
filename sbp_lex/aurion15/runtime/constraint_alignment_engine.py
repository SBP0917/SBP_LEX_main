from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class ConstraintAlignmentEngine(AurionEngine):
    name = "constraint_alignment_engine"
    stage = 3
    depends_on = [
        "autonomy_boundary_engine",
        "procedural_validation_engine",
        "legal_conflict_resolution_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        boundary_status = state.get("boundary_status")
        procedural_truth = state.get("procedural_truth_status")
        legal_conflict_status = state.get("legal_conflict_resolution_status")

        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        constraint_score = payload.get(
            "constraint_alignment_score",
            current_candidate.get("constraint_alignment_score", 0.0),
        )

        try:
            constraint_score = float(constraint_score)
        except (TypeError, ValueError):
            constraint_score = 0.0

        aligned = (
            boundary_status not in ["violation", "breach"]
            and legal_conflict_status == "resolved"
            and procedural_truth in ["true", "conclusive", "general_pass"]
            and constraint_score >= 0.7
        )

        state["constraint_alignment_status"] = "aligned" if aligned else "misaligned"
        state["constraint_alignment_score"] = constraint_score

        if aligned:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(ConstraintAlignmentEngine())
