"""Ecological constraint engine imported from SBP0917/SBP."""

from typing import Any, Dict

from .base_engine import AurionEngine
from .registry import aurion_registry


class EcologicalConstraintEngine(AurionEngine):
    name = "ecological_constraint_engine"
    stage = 5
    depends_on = [
        "risk_detection_engine",
        "demographic_monitoring_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}
        risk_level = state.get("risk_level")
        demographic_status = state.get("demographic_monitoring_status")

        ecological_constraint_score = payload.get(
            "ecological_constraint_score",
            current_candidate.get("ecological_constraint_score", 0.0),
        )
        ecological_violation_flags = payload.get(
            "ecological_violation_flags",
            current_candidate.get("ecological_violation_flags", []),
        )

        try:
            ecological_constraint_score = float(ecological_constraint_score)
        except (TypeError, ValueError):
            ecological_constraint_score = 0.0

        if not isinstance(ecological_violation_flags, list):
            ecological_violation_flags = []

        ecological_valid = (
            risk_level not in ["critical"]
            and demographic_status == "stable"
            and ecological_constraint_score >= 0.7
            and len(ecological_violation_flags) == 0
        )

        state["ecological_constraint_status"] = (
            "within_limits" if ecological_valid else "constraint_violation"
        )
        state["ecological_constraint_score"] = ecological_constraint_score
        state["ecological_violation_flags"] = ecological_violation_flags
        state["candidate_action"] = "pass" if ecological_valid else "refine_candidate"
        return state


aurion_registry.register(EcologicalConstraintEngine())
