from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class InfrastructureStateEngine(AurionEngine):
    name = "infrastructure_state_engine"
    stage = 5
    depends_on = [
        "risk_detection_engine",
        "operational_stability_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:

        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        risk_level = state.get("risk_level")
        operational_status = state.get("operational_stability_status")

        infrastructure_health = payload.get(
            "infrastructure_health_score",
            current_candidate.get("infrastructure_health_score", 0.0),
        )

        infrastructure_events = payload.get(
            "infrastructure_events",
            current_candidate.get("infrastructure_events", []),
        )

        try:
            infrastructure_health = float(infrastructure_health)
        except (TypeError, ValueError):
            infrastructure_health = 0.0

        if not isinstance(infrastructure_events, list):
            infrastructure_events = []

        stable_infrastructure = (
            risk_level not in ["critical"]
            and operational_status == "stable"
            and infrastructure_health >= 0.7
            and len(infrastructure_events) == 0
        )

        state["infrastructure_state_status"] = (
            "stable" if stable_infrastructure else "degraded"
        )

        state["infrastructure_health_score"] = infrastructure_health
        state["infrastructure_events"] = infrastructure_events

        if stable_infrastructure:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(InfrastructureStateEngine())
