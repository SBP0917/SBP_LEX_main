from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class TechnologyImpactEngine(AurionEngine):
    name = "technology_impact_engine"
    stage = 5
    depends_on = [
        "risk_detection_engine",
        "ecological_constraint_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        risk_level = state.get("risk_level")
        ecological_constraint_status = state.get("ecological_constraint_status")

        technology_impact_score = payload.get(
            "technology_impact_score",
            current_candidate.get("technology_impact_score", 0.0),
        )

        technology_impact_flags = payload.get(
            "technology_impact_flags",
            current_candidate.get("technology_impact_flags", []),
        )

        try:
            technology_impact_score = float(technology_impact_score)
        except (TypeError, ValueError):
            technology_impact_score = 0.0

        if not isinstance(technology_impact_flags, list):
            technology_impact_flags = []

        acceptable_impact = (
            risk_level not in ["critical"]
            and ecological_constraint_status == "within_limits"
            and technology_impact_score >= 0.7
            and len(technology_impact_flags) == 0
        )

        state["technology_impact_status"] = (
            "acceptable" if acceptable_impact else "disruptive"
        )

        state["technology_impact_score"] = technology_impact_score
        state["technology_impact_flags"] = technology_impact_flags

        if acceptable_impact:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(TechnologyImpactEngine())
