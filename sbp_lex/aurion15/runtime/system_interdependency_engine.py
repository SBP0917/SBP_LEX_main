from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class SystemInterdependencyEngine(AurionEngine):
    name = "system_interdependency_engine"
    stage = 4
    depends_on = [
        "cascading_failure_detection_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        cascading_failure_status = state.get("cascading_failure_status")

        interdependency_score = payload.get(
            "interdependency_score",
            current_candidate.get("interdependency_score", 0.0),
        )

        interdependency_links = payload.get(
            "interdependency_links",
            current_candidate.get("interdependency_links", []),
        )

        try:
            interdependency_score = float(interdependency_score)
        except (TypeError, ValueError):
            interdependency_score = 0.0

        if not isinstance(interdependency_links, list):
            interdependency_links = []

        interdependency_risk = (
            cascading_failure_status == "cascade_detected"
            or interdependency_score >= 0.7
            or len(interdependency_links) >= 3
        )

        state["system_interdependency_status"] = (
            "interdependent_risk" if interdependency_risk else "contained"
        )
        state["interdependency_score"] = interdependency_score
        state["interdependency_links"] = interdependency_links

        if interdependency_risk:
            state["candidate_action"] = "refine_candidate"
        else:
            state["candidate_action"] = "pass"

        return state


aurion_registry.register(SystemInterdependencyEngine())
