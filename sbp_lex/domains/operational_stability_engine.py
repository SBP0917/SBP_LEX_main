from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class OperationalStabilityEngine(AurionEngine):
    name = "operational_stability_engine"
    stage = 4
    depends_on = [
        "risk_detection_engine",
        "system_interdependency_engine",
        "cascading_failure_detection_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        risk_level = state.get("risk_level")
        system_interdependency_status = state.get("system_interdependency_status")
        cascading_failure_status = state.get("cascading_failure_status")

        operational_stability_score = payload.get(
            "operational_stability_score",
            current_candidate.get("operational_stability_score", 0.0),
        )

        operational_disruptions = payload.get(
            "operational_disruptions",
            current_candidate.get("operational_disruptions", []),
        )

        try:
            operational_stability_score = float(operational_stability_score)
        except (TypeError, ValueError):
            operational_stability_score = 0.0

        if not isinstance(operational_disruptions, list):
            operational_disruptions = []

        stable = (
            risk_level not in ["critical"]
            and system_interdependency_status != "interdependent_risk"
            and cascading_failure_status != "cascade_detected"
            and operational_stability_score >= 0.7
            and len(operational_disruptions) == 0
        )

        state["operational_stability_status"] = "stable" if stable else "unstable"
        state["operational_stability_score"] = operational_stability_score
        state["operational_disruptions"] = operational_disruptions

        if stable:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(OperationalStabilityEngine())
